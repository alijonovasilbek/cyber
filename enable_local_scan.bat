@echo off
cd /d "%~dp0"

echo [1/2] Local scan protocol o'rnatilmoqda...
call install_local_scan_protocol.bat

echo [2/2] Local agent ishga tushirilmoqda...
call start_local_agent.bat
