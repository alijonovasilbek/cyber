@echo off
cd /d "%~dp0frontend"
if not exist "node_modules" (
  echo Frontend dependency topilmadi. Avval setup_project.bat ni ishlating.
  exit /b 1
)
start "CyberGuard Frontend" cmd /k "npm.cmd run dev -- --host 0.0.0.0 --port 5173"
