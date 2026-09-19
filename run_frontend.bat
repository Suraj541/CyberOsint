@echo off
echo ============================================================
echo Starting Cybersecurity OSINT Web UI (Next.js)
echo ============================================================
cd /d "%~dp0apps\web"
echo UI URL: http://localhost:3000
cmd.exe /c "npm run dev"
