@echo off
setlocal
cd /d "%~dp0"
if exist "venv\Scripts\python.exe" (
  set "PY=venv\Scripts\python.exe"
) else if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
) else (
  set "PY=python"
)
"%PY%" -c "import flask" >nul 2>&1
if errorlevel 1 (
  echo Flask is not installed. Installing project requirements...
  "%PY%" -m pip install -r requirements.txt
  if errorlevel 1 (
    echo.
    echo Could not install requirements. Check your internet connection or Python/pip setup.
    pause
    exit /b 1
  )
)
echo.
echo ========================================
echo          PYDEFEND IS STARTING
echo ========================================
echo Laptop: http://127.0.0.1:5000
echo Phone:  use the LAPTOP IPv4 address shown below.
echo Press CTRL+C in this window to stop.
echo.
"%PY%" app.py
pause
