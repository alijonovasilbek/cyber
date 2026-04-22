@echo off
setlocal
cd /d "%~dp0"

echo [1/3] Backend virtual environment tayyorlanmoqda...
cd /d "%~dp0backend"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv 2>nul
  if errorlevel 1 (
    python -m venv .venv
  )
)
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip
pip install -r requirements.txt
python manage.py migrate

echo [2/3] Frontend dependency o'rnatilmoqda...
cd /d "%~dp0frontend"
cmd /c npm.cmd install

echo [3/3] Tayyor. Endi start_backend.bat va start_frontend.bat ni ishga tushiring.
endlocal
