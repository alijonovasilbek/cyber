@echo off
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  echo Python virtual environment topilmadi. Avval setup_project.bat ni ishlating.
  exit /b 1
)
start "CyberGuard Local Agent" powershell -NoExit -Command ".\.venv\Scripts\python.exe local_agent.py"
