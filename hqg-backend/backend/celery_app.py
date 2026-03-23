from celery import Celery

from backend.config import get_settings


settings = get_settings()

celery_app = Celery(
    "hqg",
    broker=settings.redis_url,
    backend=settings.redis_result_backend,
    include=[
        "scanner.scan_manager.tasks",
        "scanner.asset_discovery.tasks",
        "scanner.crawler.tasks",
        "scanner.payload_engine.tasks",
        "scanner.detection_engine.tasks",
        "scanner.cve_intelligence.tasks",
        "scanner.template_engine.tasks",
        "ai.analyzer.tasks",
        "reporting.engine.tasks",
        "scheduler.tasks",
    ],
)

celery_app.conf.update(
    task_default_queue=settings.celery_task_default_queue,
    task_track_started=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_routes={
        "scanner.scan_manager.*": {"queue": "queue_scan_manager"},
        "scanner.asset_discovery.*": {"queue": "queue_discovery"},
        "scanner.crawler.*": {"queue": "queue_crawler"},
        "scanner.payload_engine.*": {"queue": "queue_payload"},
        "scanner.detection_engine.*": {"queue": "queue_detection"},
        "scanner.cve_intelligence.*": {"queue": "queue_cve_intelligence"},
        "scanner.template_engine.*": {"queue": "queue_template"},
        "ai.analyzer.*": {"queue": "queue_ai"},
        "reporting.engine.*": {"queue": "queue_reporting"},
        "scheduler.*": {"queue": "queue_scheduler"},
    },
)


@celery_app.task(name="scanner.scan_manager.healthcheck")
def worker_healthcheck() -> str:
    return "ok"
