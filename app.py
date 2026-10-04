from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime
import sqlite3, hashlib, os, re, secrets, json

BASE_DIR = Path(__file__).resolve().parent
# Render's filesystem is ephemeral but writable; /tmp avoids repository write surprises.
DATA_ROOT = Path(os.environ.get('PYDEFEND_DATA_DIR', str(BASE_DIR / 'data')))
DATA_ROOT.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_ROOT / 'pydefend.db'
UPLOAD_DIR = DATA_ROOT / 'uploads'; REPORT_DIR = DATA_ROOT / 'reports'; QUARANTINE_DIR = DATA_ROOT / 'quarantine'
for folder in (UPLOAD_DIR, REPORT_DIR, QUARANTINE_DIR): folder.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(BASE_DIR / 'templates'), static_folder=str(BASE_DIR / 'static'))
app.secret_key = os.environ.get('PYDEFEND_SECRET') or 'pydefend-demo-secret-change-me'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

ALLOWED_UPLOADS = {'.txt','.pdf','.doc','.docx','.docm','.xls','.xlsx','.ppt','.pptx','.pptm','.csv','.jpg','.jpeg','.png','.gif','.webp','.zip','.py','.html','.css','.js','.json','.xml'}
DANGEROUS_EXTENSIONS = {'.exe','.dll','.bat','.cmd','.scr','.vbs','.ps1','.msi','.jar','.com'}
DEMO_MARKERS = {
    'PYDEFEND_TEST_THREAT': ('CRITICAL', 70, 'PyDefend simulated threat signature detected.'),
    'PYDEFEND_TEST_HIGH_RISK': ('HIGH', 45, 'PyDefend simulated HIGH-RISK classroom marker detected.'),
    'PYDEFEND_TEST_WARNING': ('MEDIUM', 20, 'PyDefend simulated WARNING classroom marker detected.'),
}
SUSPICIOUS_PATTERNS = [
    r'powershell\s+-enc', r'cmd\.exe\s*/c', r'certutil\s+-decode',
    r'javascript:\s*eval\s*\(', r'<script[^>]+src=["\']https?://'
]


def db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn


def init_db():
    conn = db()
    conn.executescript('''
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student', active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL, last_login TEXT
    );
    CREATE TABLE IF NOT EXISTS scans(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, scan_type TEXT NOT NULL, target TEXT NOT NULL,
      status TEXT NOT NULL, score INTEGER NOT NULL, threats INTEGER NOT NULL DEFAULT 0, warnings INTEGER NOT NULL DEFAULT 0,
      checked INTEGER NOT NULL DEFAULT 0, findings TEXT DEFAULT '[]', created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS activity(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS quarantine(
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, filename TEXT NOT NULL, risk TEXT NOT NULL,
      reason TEXT NOT NULL, stored_name TEXT NOT NULL, created_at TEXT NOT NULL, restored INTEGER DEFAULT 0,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    ''')
    users = [
      ('Administrator','admin@pydefend.local','PyDefend123!','admin'),
      ('Student User','student@pydefend.local','Student123!','student')
    ]
    for username,email,password,role in users:
        exists = conn.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
        if not exists:
            conn.execute('INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                         (username,email,hashlib.sha256(password.encode()).hexdigest(),role,datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    # Keep databases created by older PyDefend versions compatible.
    # SQLite does not add new columns when a table already exists, so add
    # any missing fields needed by the current release.
    migrations = {
        'users': [
            ('username', 'TEXT'), ('email', 'TEXT'), ('password_hash', 'TEXT'),
            ('role', "TEXT NOT NULL DEFAULT 'student'"),
            ('active', 'INTEGER NOT NULL DEFAULT 1'), ('created_at', "TEXT NOT NULL DEFAULT ''"),
            ('last_login', 'TEXT')
        ],
        'scans': [
            ('user_id', 'INTEGER'), ('scan_type', "TEXT NOT NULL DEFAULT 'file'"),
            ('target', "TEXT NOT NULL DEFAULT ''"), ('status', "TEXT NOT NULL DEFAULT 'COMPLETED'"),
            ('score', 'INTEGER NOT NULL DEFAULT 0'), ('threats', 'INTEGER NOT NULL DEFAULT 0'),
            ('warnings', 'INTEGER NOT NULL DEFAULT 0'), ('checked', 'INTEGER NOT NULL DEFAULT 0'),
            ('findings', "TEXT DEFAULT '[]'"), ('created_at', "TEXT NOT NULL DEFAULT ''")
        ],
        'activity': [
            ('user_id', 'INTEGER'), ('title', "TEXT NOT NULL DEFAULT ''"),
            ('detail', "TEXT NOT NULL DEFAULT ''"), ('created_at', "TEXT NOT NULL DEFAULT ''")
        ]
    }
    for table, needed in migrations.items():
        existing = {row['name'] for row in conn.execute(f'PRAGMA table_info({table})').fetchall()}
        for column, definition in needed:
            if column not in existing:
                try:
                    conn.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
                except sqlite3.OperationalError:
                    pass

    # Make sure the two built-in demo accounts remain usable after an upgrade.
    for username,email,password,role in users:
        conn.execute('UPDATE users SET role=?, active=1 WHERE email=?', (role,email))

    conn.commit(); conn.close()


def current_user():
    uid = session.get('user_id')
    if not uid: return None
    conn=db(); row=conn.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); conn.close(); return row


def require_login(): return current_user() is not None

def is_admin():
    u=current_user(); return bool(u and u['role']=='admin')


def add_activity(title, detail, user_id=None):
    user_id = user_id or session.get('user_id')
    conn=db(); conn.execute('INSERT INTO activity(user_id,title,detail,created_at) VALUES(?,?,?,?)',
                            (user_id,title,detail,datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); conn.commit(); conn.close()


def save_scan(scan_type,target,status,score,threats,warnings,checked,findings):
    conn=db(); cur=conn.execute('''INSERT INTO scans(user_id,scan_type,target,status,score,threats,warnings,checked,findings,created_at)
      VALUES(?,?,?,?,?,?,?,?,?,?)''',(session.get('user_id'),scan_type,target,status,score,threats,warnings,checked,json.dumps(findings),datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    sid=cur.lastrowid; conn.commit(); conn.close(); return sid


def password_score(password):
    score=0; tips=[]
    if len(password)>=8: score+=20
    else: tips.append('Use at least 8 characters.')
    if len(password)>=12: score+=15
    if re.search(r'[A-Z]',password): score+=15
    else: tips.append('Add an uppercase letter.')
    if re.search(r'[a-z]',password): score+=15
    else: tips.append('Add a lowercase letter.')
    if re.search(r'\d',password): score+=15
    else: tips.append('Add a number.')
    if re.search(r'[^A-Za-z0-9]',password): score+=20
    else: tips.append('Add a special character.')
    if re.search(r'(1234|password|qwerty|admin|letmein)',password.lower()): score=min(score,35); tips.append('Avoid common password words or sequences.')
    score=min(100,score); label='Strong' if score>=80 else ('Moderate' if score>=55 else 'Weak')
    return score,label,tips


def scan_content(filename,data,extra_text=''):
    ext=Path(filename).suffix.lower(); sha256=hashlib.sha256(data).hexdigest(); findings=[]; risk=0
    text=data.decode('utf-8',errors='ignore') + '\n' + (extra_text or '')
    if ext in DANGEROUS_EXTENSIONS:
        findings.append({'level':'HIGH','title':'Potentially dangerous file type','detail':f'{ext.upper()} files may execute code. Treat them with caution.'}); risk+=35
    for marker,(level,points,detail) in DEMO_MARKERS.items():
        if marker in text:
            findings.append({'level':level,'title':detail,'detail':f'Safe classroom marker {marker} was intentionally detected. It is not malware.'}); risk+=points
    for pattern in SUSPICIOUS_PATTERNS:
        try: matched=re.search(pattern,text,flags=re.I) is not None
        except re.error: matched=False
        if matched:
            findings.append({'level':'MEDIUM','title':'Suspicious pattern detected','detail':'A suspicious command or script pattern was found in the analyzed content.'}); risk+=20
    if not data:
        findings.append({'level':'LOW','title':'Empty file','detail':'The uploaded item contains no data.'}); risk+=5
    score=max(0,100-min(100,risk)); threats=sum(x['level'] in {'CRITICAL','HIGH'} for x in findings); warnings=sum(x['level'] in {'MEDIUM','LOW'} for x in findings)
    status='CRITICAL' if any(x['level']=='CRITICAL' for x in findings) else ('HIGH RISK' if threats else ('WARNING' if warnings else 'SECURE'))
    return {'filename':filename,'size':len(data),'sha256':sha256,'score':score,'status':status,'threats':threats,'warnings':warnings,'findings':findings}


def system_assessment(scan_type):
    checks=[
      ('Account protection',18,'PASS','Login protection is enabled.'),('Password policy',16,'PASS','Password strength rules are available.'),
      ('File integrity',18,'PASS','SHA-256 hashing is used for uploaded files.'),('Dangerous file detection',18,'PASS','Risky executable extensions are flagged.'),
      ('Suspicious pattern detection',15,'PASS','Basic suspicious text patterns are checked.'),('Audit activity',15,'PASS','Scan activity is recorded locally.'),
      ('Mobile access readiness',10,'PASS','The interface is responsive for phone browsers.')]
    if scan_type=='quick': checks=checks[:4]
    return checks, sum(x[1] for x in checks)


def user_scan_rows(admin=False, limit=100):
    conn=db()
    if admin: rows=conn.execute('SELECT scans.*,users.username FROM scans LEFT JOIN users ON users.id=scans.user_id ORDER BY scans.id DESC LIMIT ?', (limit,)).fetchall()
    else: rows=conn.execute('SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT ?', (session['user_id'],limit)).fetchall()
    conn.close(); return rows


@app.context_processor
def inject_globals():
    try:
        u = current_user()
        return {'me': u, 'admin': bool(u and u['role'] == 'admin')}
    except Exception:
        return {'me': None, 'admin': False}

@app.route('/')
def index():
    try:
        if session.get('user_id') and current_user() is not None:
            return redirect(url_for('dashboard'))
    except Exception:
        session.clear()
    return render_template('login.html')

@app.route('/login',methods=['POST'])
def login():
    email=request.form.get('email','').strip().lower(); password=request.form.get('password','')
    conn=db(); row=conn.execute('SELECT * FROM users WHERE email=? AND active=1',(email,)).fetchone()
    ok=row and row['password_hash']==hashlib.sha256(password.encode()).hexdigest()
    if ok:
        session['user_id']=row['id']; conn.execute('UPDATE users SET last_login=? WHERE id=?',(datetime.now().strftime('%Y-%m-%d %H:%M:%S'),row['id'])); conn.commit(); conn.close()
        add_activity('Successful login',f'{row["username"]} signed in as {row["role"]}.',row['id']); return redirect(url_for('dashboard'))
    conn.close(); flash('Invalid credentials. Try the demo accounts shown below.','error'); return redirect(url_for('index'))

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if not require_login(): return redirect(url_for('index'))
    conn=db(); uid=session['user_id']
    if is_admin():
        total=conn.execute('SELECT COUNT(*) c FROM scans').fetchone()['c']; threats=conn.execute('SELECT COALESCE(SUM(threats),0)c FROM scans').fetchone()['c']; checked=conn.execute('SELECT COALESCE(SUM(checked),0)c FROM scans').fetchone()['c']; users=conn.execute('SELECT COUNT(*) c FROM users WHERE role="student"').fetchone()['c']; activity=conn.execute('SELECT * FROM activity ORDER BY id DESC LIMIT 7').fetchall(); last=conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 1').fetchone()
    else:
        total=conn.execute('SELECT COUNT(*) c FROM scans WHERE user_id=?',(uid,)).fetchone()['c']; threats=conn.execute('SELECT COALESCE(SUM(threats),0)c FROM scans WHERE user_id=?',(uid,)).fetchone()['c']; checked=conn.execute('SELECT COALESCE(SUM(checked),0)c FROM scans WHERE user_id=?',(uid,)).fetchone()['c']; users=0; activity=conn.execute('SELECT * FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 7',(uid,)).fetchall(); last=conn.execute('SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 1',(uid,)).fetchone()
    conn.close(); score=last['score'] if last else 92
    return render_template('dashboard.html',total=total,threats=threats,checked=checked,users=users,activity=activity,score=score,last=last)

@app.route('/scanner')
def scanner():
    if not require_login(): return redirect(url_for('index'))
    return render_template('scanner.html')

@app.route('/system-scan',methods=['POST'])
def system_scan():
    if not require_login(): return jsonify({'error':'Unauthorized'}),401
    scan_type=request.form.get('scan_type','full'); checks,score=system_assessment(scan_type); findings=[{'level':c[2],'title':c[0],'detail':c[3]} for c in checks]; sid=save_scan(scan_type,'Local security assessment','COMPLETED',score,0,0,len(checks),findings); add_activity('Security assessment completed',f'{scan_type.title()} scan finished with score {score}/100.')
    return render_template('results.html',result={'scan_id':sid,'title':f'{scan_type.title()} Security Assessment','score':score,'status':'SECURE' if score>=80 else 'WARNING','threats':0,'warnings':0,'checked':len(checks),'findings':findings,'sha256':None,'filename':'Local system','recommendations':['Keep accounts protected.','Use strong unique passwords.','Review any future findings.']})

@app.route('/file-scan',methods=['POST'])
def file_scan():
    if not require_login(): return redirect(url_for('index'))
    uploaded=request.files.get('file')
    if not uploaded or not uploaded.filename: flash('Please choose a file first.','error'); return redirect(url_for('scanner'))
    filename=secure_filename(uploaded.filename); ext=Path(filename).suffix.lower()
    if ext not in ALLOWED_UPLOADS and ext not in DANGEROUS_EXTENSIONS: flash('File type is not supported.','error'); return redirect(url_for('scanner'))
    data=uploaded.read(); result=scan_content(filename,data); stored=f'{secrets.token_hex(8)}_{filename}'; (UPLOAD_DIR/stored).write_bytes(data)
    sid=save_scan('file',filename,result['status'],result['score'],result['threats'],result['warnings'],1,result['findings']); add_activity('File scan completed',f'{filename} → {result["status"]}.'); result['scan_id']=sid; result['recommendations']=recommendations(result['findings'])
    return render_template('results.html',result=result)

@app.route('/picture-scan',methods=['POST'])
def picture_scan():
    if not require_login(): return redirect(url_for('index'))
    uploaded=request.files.get('picture'); ocr=request.form.get('ocr_text','')
    if not uploaded or not uploaded.filename: flash('Please capture or choose a picture first.','error'); return redirect(url_for('scanner'))
    filename=secure_filename(uploaded.filename); data=uploaded.read(); result=scan_content(filename,data,ocr); stored=f'{secrets.token_hex(8)}_{filename}'; (UPLOAD_DIR/stored).write_bytes(data)
    if ocr: result['findings'].append({'level':'INFO','title':'OCR text analyzed','detail':f'{len(ocr)} characters were extracted from the picture and included in the security check.'})
    sid=save_scan('picture',filename,result['status'],result['score'],result['threats'],result['warnings'],1,result['findings']); add_activity('Picture scan completed',f'{filename} → {result["status"]}.'); result['scan_id']=sid; result['recommendations']=recommendations(result['findings'])
    return render_template('results.html',result=result)


def recommendations(findings):
    rec=[]
    levels={x['level'] for x in findings}
    if 'CRITICAL' in levels or 'HIGH' in levels: rec.append('Review the flagged item before opening or sharing it. Use quarantine simulation when appropriate.')
    if 'MEDIUM' in levels: rec.append('Review suspicious text or commands and verify the source.')
    if not rec: rec.append('No high-risk indicator was detected by the checks used in this student prototype.')
    rec += ['Keep software updated.','Use strong, unique passwords and enable MFA where available.']
    return rec

@app.route('/password')
def password_page():
    if not require_login(): return redirect(url_for('index'))
    return render_template('password.html')

@app.route('/check-password',methods=['POST'])
def check_password():
    if not require_login(): return jsonify({'error':'Unauthorized'}),401
    score,label,tips=password_score(request.form.get('password','')); return jsonify({'score':score,'label':label,'tips':tips})

@app.route('/url-checker',methods=['GET','POST'])
def url_checker():
    if not require_login(): return redirect(url_for('index'))
    result=None
    if request.method=='POST':
        raw=request.form.get('url','').strip(); low=raw.lower(); findings=[]; score=100
        if not raw.startswith(('http://','https://')): findings.append(('WARNING','URL does not specify HTTP/HTTPS.')); score-=20
        if raw.startswith('http://'): findings.append(('MEDIUM','Connection is not encrypted with HTTPS.')); score-=25
        if '@' in raw: findings.append(('HIGH','URL contains an @ character, which can be confusing in phishing-style links.')); score-=35
        if any(x in low for x in ['bit.ly/','tinyurl.com/','free-login','verify-account','password-reset']): findings.append(('MEDIUM','The URL contains a pattern commonly associated with risky links.')); score-=20
        result={'url':raw,'score':max(0,score),'status':'HIGH RISK' if score<50 else ('WARNING' if score<80 else 'LOW RISK'),'findings':findings}
        add_activity('URL security check',f'{raw} → {result["status"]}.')
    return render_template('url_checker.html',result=result)

@app.route('/history')
def history():
    if not require_login(): return redirect(url_for('index'))
    return render_template('history.html',scans=user_scan_rows(is_admin()))

@app.route('/analytics')
def analytics():
    if not require_login(): return redirect(url_for('index'))
    conn=db(); where='' if is_admin() else ' WHERE user_id=?'; args=() if is_admin() else (session['user_id'],)
    stats=conn.execute('SELECT COUNT(*) scans, COALESCE(SUM(threats),0) threats, COALESCE(SUM(warnings),0) warnings, COALESCE(AVG(score),0) avg_score FROM scans'+where,args).fetchone()
    types=conn.execute('SELECT scan_type,COUNT(*) c FROM scans'+where+' GROUP BY scan_type',args).fetchall(); conn.close(); return render_template('analytics.html',stats=stats,types=types)

@app.route('/quarantine')
def quarantine():
    if not require_login(): return redirect(url_for('index'))
    conn=db(); rows=conn.execute('SELECT * FROM quarantine WHERE user_id=? ORDER BY id DESC',(session['user_id'],)).fetchall(); conn.close(); return render_template('quarantine.html',rows=rows)

@app.route('/quarantine/add/<int:scan_id>',methods=['POST'])
def quarantine_add(scan_id):
    if not require_login(): return redirect(url_for('index'))
    conn=db(); scan=conn.execute('SELECT * FROM scans WHERE id=?',(scan_id,)).fetchone(); conn.close()
    if not scan or scan['user_id']!=session['user_id']: flash('Scan not available.','error'); return redirect(url_for('dashboard'))
    stored=f'quarantine_{scan_id}_{secrets.token_hex(4)}.txt'; (QUARANTINE_DIR/stored).write_text(f'PyDefend quarantine simulation\nOriginal: {scan["target"]}\nStatus: {scan["status"]}\n',encoding='utf-8')
    conn=db(); conn.execute('INSERT INTO quarantine(user_id,filename,risk,reason,stored_name,created_at) VALUES(?,?,?,?,?,?)',(session['user_id'],scan['target'],scan['status'],'Simulated isolation for classroom demo.',stored,datetime.now().strftime('%Y-%m-%d %H:%M:%S'))); conn.commit(); conn.close(); add_activity('Item quarantined',f'{scan["target"]} was placed in simulated quarantine.'); flash('Item moved to PyDefend quarantine simulation.','success'); return redirect(url_for('quarantine'))

@app.route('/test-center')
def test_center():
    if not require_login(): return redirect(url_for('index'))
    return render_template('test_center.html')

@app.route('/profile',methods=['GET','POST'])
def profile():
    if not require_login(): return redirect(url_for('index'))
    u=current_user()
    if request.method=='POST':
        username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower()
        if not username or not email: flash('Username and email are required.','error'); return redirect(url_for('profile'))
        conn=db()
        try: conn.execute('UPDATE users SET username=?,email=? WHERE id=?',(username,email,u['id'])); conn.commit(); flash('Profile updated.','success')
        except sqlite3.IntegrityError: flash('Username or email is already in use.','error')
        finally: conn.close()
        return redirect(url_for('profile'))
    return render_template('profile.html',user=u)

@app.route('/change-password',methods=['POST'])
def change_password():
    if not require_login(): return redirect(url_for('index'))
    u=current_user(); old=request.form.get('current',''); new=request.form.get('new',''); confirm=request.form.get('confirm','')
    if hashlib.sha256(old.encode()).hexdigest()!=u['password_hash']: flash('Current password is incorrect.','error'); return redirect(url_for('profile'))
    if new!=confirm or len(new)<8: flash('New passwords must match and be at least 8 characters.','error'); return redirect(url_for('profile'))
    conn=db(); conn.execute('UPDATE users SET password_hash=? WHERE id=?',(hashlib.sha256(new.encode()).hexdigest(),u['id'])); conn.commit(); conn.close(); add_activity('Password changed','Account password was updated.'); flash('Password changed successfully.','success'); return redirect(url_for('profile'))

@app.route('/admin/users')
def admin_users():
    if not is_admin(): return redirect(url_for('dashboard'))
    conn=db(); users=conn.execute('SELECT * FROM users ORDER BY role DESC, id').fetchall(); conn.close(); return render_template('admin_users.html',users=users)

@app.route('/admin/users/<int:user_id>/toggle',methods=['POST'])
def toggle_user(user_id):
    if not is_admin(): return redirect(url_for('dashboard'))
    conn=db(); row=conn.execute('SELECT active,role FROM users WHERE id=?',(user_id,)).fetchone()
    if row and row['role']!='admin': conn.execute('UPDATE users SET active=? WHERE id=?',(0 if row['active'] else 1,user_id)); conn.commit()
    conn.close(); return redirect(url_for('admin_users'))

@app.route('/admin/activity')
def admin_activity():
    if not is_admin(): return redirect(url_for('dashboard'))
    conn=db(); rows=conn.execute('SELECT activity.*,users.username FROM activity LEFT JOIN users ON users.id=activity.user_id ORDER BY activity.id DESC LIMIT 100').fetchall(); conn.close(); return render_template('admin_activity.html',rows=rows)

@app.route('/report/<int:scan_id>')
def report(scan_id):
    if not require_login(): return redirect(url_for('index'))
    conn=db(); row=conn.execute('SELECT scans.*,users.username FROM scans LEFT JOIN users ON users.id=scans.user_id WHERE scans.id=?',(scan_id,)).fetchone(); conn.close()
    if not row or (not is_admin() and row['user_id']!=session['user_id']): flash('Report not found.','error'); return redirect(url_for('dashboard'))
    findings=json.loads(row['findings'] or '[]'); return render_template('report.html',scan=row,findings=findings,recommendations=recommendations(findings))

@app.route('/api/health')
def health():
    try:
        conn = db()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        return jsonify({'app': 'PyDefend', 'status': 'online', 'time': datetime.now().isoformat(timespec='seconds')}), 200
    except Exception as exc:
        app.logger.exception('Health check database error: %s', exc)
        return jsonify({'app': 'PyDefend', 'status': 'degraded', 'time': datetime.now().isoformat(timespec='seconds')}), 200

@app.errorhandler(413)
def too_large(_): flash('File is too large. Maximum upload size is 10 MB.','error'); return redirect(url_for('scanner'))

@app.errorhandler(500)
def internal_error(error):
    app.logger.exception('PyDefend internal error: %s', error)
    return render_template('login.html', server_error='PyDefend encountered a temporary server error. Please refresh and try again.'), 500

# Initialize once when the module is loaded by Render or Flask.
try:
    init_db()
except Exception as exc:
    app.logger.exception('PyDefend database initialization failed: %s', exc)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '5000'))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True, use_reloader=False)
