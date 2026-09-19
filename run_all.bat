@echo off
echo ============================================================
echo Starting OSINT Platform Services (Backend + Frontend)
echo ============================================================
cd /d "%~dp0"
start "OSINT Backend API" cmd.exe /k "%~dp0run_backend.bat"
start "OSINT Web Frontend" cmd.exe /k "%~dp0run_frontend.bat"
echo.
echo Both servers have been launched in dedicated terminal windows!
echo - API Server:   http://127.0.0.1:8000
echo - Swagger Docs: http://127.0.0.1:8000/docs
echo - Web UI:       http://localhost:3000
echo ============================================================
