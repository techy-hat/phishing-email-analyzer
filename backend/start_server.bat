@echo off
REM PhishGuard analyzer server launcher
REM Starts the FastAPI backend on http://127.0.0.1:8000
cd /d "%~dp0"
echo Starting PhishGuard analyzer server on http://127.0.0.1:8000 ...
echo Press Ctrl+C to stop.
python -m uvicorn main:app --host 127.0.0.1 --port 8000
