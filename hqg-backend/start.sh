#!/usr/bin/env bash
set -e

echo "╔══════════════════════════════════════════════╗"
echo "║   HQG Web Security Platform — Starting...   ║"
echo "╚══════════════════════════════════════════════╝"

# Run migrations if alembic is configured
if [ -f alembic.ini ]; then
    echo "→ Running database migrations..."
    alembic upgrade head || echo "⚠  Migrations skipped (database may not be available)"
fi

echo "→ Starting Uvicorn API server on :8000"
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 "$@"
