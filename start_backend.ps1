# SecureShield AI Backend Server Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " Starting SecureShield AI Backend Server (FastAPI / Uvicorn)" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

$pythonPath = Join-Path $scriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $pythonPath)) {
    Write-Host "[ERROR] Virtual environment not found at $pythonPath" -ForegroundColor Red
    exit 1
}

Write-Host "Starting server on http://0.0.0.0:8000..." -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate.`n" -ForegroundColor Yellow

& $pythonPath -m uvicorn main:app --app-dir "$scriptDir\backend" --host 0.0.0.0 --port 8000 --reload
