@echo off
echo ============================================================
echo Running Full Test Suite (Stage Suites + Subsystem Tests)
echo ============================================================
cd /d "%~dp0"
set PYTHONPATH=.;apps/api
python -m unittest discover -s tests -t . -p "test_*.py"
