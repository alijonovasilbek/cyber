@echo off
cd /d "%~dp0"

echo [1/2] Backend ishga tushirilmoqda...
call start_backend.bat

echo [2/2] Frontend ishga tushirilmoqda...
call start_frontend.bat

echo CyberGuard backend va frontend ishga tushirildi.
