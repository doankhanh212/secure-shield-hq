from backend.celery_app import celery_app


@celery_app.task(name="scheduler.bootstrap")
def bootstrap() -> dict[str, str]:
    return {"stage": "scheduler"}
