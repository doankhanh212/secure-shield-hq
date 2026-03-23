# HQG Backend Skeleton

Backend-only scaffold for HQG Web Security Platform.

## Stack
- Python
- FastAPI
- Celery + Redis
- PostgreSQL (async SQLAlchemy)
- Elasticsearch

## Run API

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## Run worker (distributed-ready)

```bash
celery -A backend.celery_app:celery_app worker -l info -Q queue_scan_manager,queue_discovery,queue_crawler,queue_payload,queue_detection,queue_template,queue_ai,queue_reporting,queue_scheduler
```

## Environment
Copy `.env.example` to `.env` and update connection strings.
