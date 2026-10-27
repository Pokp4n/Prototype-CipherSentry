@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run setup_windows.bat first. Python 3.12 is required for that installer.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m ciphersentry %*
if errorlevel 1 pause
