@echo off
REM ══════════════════════════════════════════════════
REM  HQG Web Security Platform — Local Dev Launcher
REM ══════════════════════════════════════════════════
REM
REM Prerequisites:
REM   1. Redis running on localhost:6379  (e.g. docker run -d -p 6379:6379 redis:7-alpine)
REM   2. Python venv activated with deps installed  (pip install -e .)
REM   3. .env file present in project root
REM
REM Usage:  Run from hqg-backend directory:
REM         scripts\dev_start.bat
REM

echo.
echo ========================================
echo   HQG Backend — Local Development Mode
echo ========================================
echo.

REM Ensure we're in the project root (where backend/ lives)
if not exist backend\main.py (
    echo [ERROR] Run this script from the hqg-backend directory.
    exit /b 1
)

REM Check Redis is reachable
where redis-cli >nul 2>&1
if %ERRORLEVEL% equ 0 (
    redis-cli ping >nul 2>&1
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Redis is not running on localhost:6379
        echo         Start it with: docker run -d -p 6379:6379 redis:7-alpine
        exit /b 1
    )
    echo [OK] Redis is reachable
) else (
    echo [WARN] redis-cli not found — skipping Redis check
)

REM Windows requires --pool=solo (prefork not supported)
echo.
echo Starting Celery worker in background (pool=solo)...
start "HQG-Celery" cmd /c "python -m celery -A backend.celery_app.celery_app worker --loglevel=info --pool=solo -Q queue_default,queue_scan_manager,queue_discovery,queue_crawler,queue_payload,queue_detection,queue_cve_intelligence,queue_template,queue_ai,queue_reporting,queue_scheduler"

REM Give worker a moment to connect
timeout /t 3 /nobreak >nul

echo Starting FastAPI server...
echo.
echo   API:    http://localhost:8000
echo   Docs:   http://localhost:8000/docs
echo   Health: http://localhost:8000/health
echo.
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
