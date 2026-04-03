# ── HQG Backend — production image ─────────────────────────────────
# Single image used for both the API server and the Celery worker.
# The CMD is overridden per-service in docker-compose.yml.
FROM python:3.11-slim AS base

# ── System deps ──────────────────────────────────────────────────────
# WeasyPrint needs pango/cairo; curl is used by the healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpango-1.0-0 \
        libpangocairo-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libcairo2 \
        libffi-dev \
        libglib2.0-0 \
        shared-mime-info \
        fonts-liberation \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ── Python deps (cached layer) ───────────────────────────────────────
COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

# ── Application source ───────────────────────────────────────────────
COPY . .

EXPOSE 8000

# Default: API server.  Worker overrides this in docker-compose.yml.
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
