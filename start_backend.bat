@echo off
title SecureShield AI - Backend Server
echo ========================================================
echo  Starting SecureShield AI Backend Server (FastAPI / Uvicorn)
echo ========================================================
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found in .venv!
    echo Please ensure the Python virtual environment exists.
    pause
    exit /b 1
)

echo Activating virtual environment and starting server on http://0.0.0.0:8000...
echo (Press CTRL+C to stop the server)
echo.

".venv\Scripts\python.exe" -m uvicorn main:app --app-dir backend --host 0.0.0.0 --port 8000 --reload
pause
