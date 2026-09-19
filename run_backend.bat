@echo off
echo ============================================================
echo Starting Cybersecurity OSINT Intelligence Platform API
echo ============================================================
cd /d "%~dp0"
set PYTHONPATH=.;apps/api
echo Host: http://127.0.0.1:8000
echo Docs: http://127.0.0.1:8000/docs
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
