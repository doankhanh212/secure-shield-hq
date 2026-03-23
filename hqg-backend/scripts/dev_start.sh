#!/usr/bin/env bash
set -e

# ══════════════════════════════════════════════════
#  HQG Web Security Platform — Local Dev Launcher
# ══════════════════════════════════════════════════
#
# Prerequisites:
#   1. Redis running on localhost:6379  (e.g. docker run -d -p 6379:6379 redis:7-alpine)
#   2. Python venv activated with deps installed  (pip install -e .)
#   3. .env file present in project root
#

echo ""
echo "========================================"
echo "  HQG Backend — Local Development Mode"
echo "========================================"
echo ""

# Check Redis
if command -v redis-cli &>/dev/null; then
    if redis-cli ping &>/dev/null; then
        echo "[OK] Redis is reachable"
    else
        echo "[ERROR] Redis is not running on localhost:6379"
        echo "        Start it with: docker run -d -p 6379:6379 redis:7-alpine"
        exit 1
    fi
else
    echo "[WARN] redis-cli not found — skipping Redis check"
fi

cleanup() {
    echo ""
    echo "Shutting down..."
    kill "$CELERY_PID" 2>/dev/null || true
    wait "$CELERY_PID" 2>/dev/null || true
    echo "Done."
}
trap cleanup EXIT INT TERM

echo ""
echo "Starting Celery worker in background..."
celery -A backend.celery_app.celery_app worker \
    --loglevel=info \
    --concurrency=4 \
    -Q queue_default,queue_scan_manager,queue_discovery,queue_crawler,queue_payload,queue_detection,queue_cve_intelligence,queue_template,queue_ai,queue_reporting,queue_scheduler &
CELERY_PID=$!

sleep 3

echo "Starting FastAPI server..."
echo ""
echo "  API:    http://localhost:8000"
echo "  Docs:   http://localhost:8000/docs"
echo "  Health: http://localhost:8000/health"
echo ""
uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
