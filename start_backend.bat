@echo off
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  echo Python virtual environment topilmadi. Avval setup_project.bat ni ishlating.
  exit /b 1
)
if exist ".venv\Scripts\uvicorn.exe" (
  start "CyberGuard Backend" powershell -NoExit -Command ".\.venv\Scripts\python.exe manage.py migrate; .\.venv\Scripts\uvicorn.exe cyberguard.asgi:application --host 0.0.0.0 --port 8000"
) else (
  start "CyberGuard Backend" powershell -NoExit -Command ".\.venv\Scripts\python.exe manage.py migrate; .\.venv\Scripts\python.exe manage.py runserver 0.0.0.0:8000 --noreload"
)
