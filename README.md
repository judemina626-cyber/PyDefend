# PyDefend

A school-project cybersecurity assessment web app built with Python Flask, HTML, CSS, JavaScript and SQLite.

## Features
- Admin + Student roles
- Responsive laptop/mobile dashboard
- Full and Quick security assessments
- File Scan with SHA-256, risky-extension checks, demo signatures and safe suspicious-pattern rules
- Picture/Camera Scan with optional browser OCR using Tesseract.js
- URL security checker
- Password strength analyzer
- Smart risk analysis and recommendations
- Scan history and analytics
- Safe quarantine simulation
- Automatic printable security reports
- Admin user management and audit activity
- Demo Test Center for SAFE/WARNING/HIGH/CRITICAL simulated markers

## Demo accounts
Admin: admin@pydefend.local / PyDefend123!
Student: student@pydefend.local / Student123!

## Run
PowerShell:

    .\\venv\\Scripts\\python.exe -m pip install -r requirements.txt
    .\\venv\\Scripts\\python.exe app.py

Open on laptop: http://127.0.0.1:5000
For a phone on the same Wi-Fi, open http://LAPTOP-IP:5000

## Safe demo files
Use the included marker files from the PyDefend demo ZIP. They are not malware.

## Important
This is an educational prototype. It is not a replacement for commercial antivirus, EDR, malware sandboxing, or professional security analysis.
