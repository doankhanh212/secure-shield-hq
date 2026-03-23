"""Template-engine Celery task and async entry-point."""
from __future__ import annotations

import asyncio
import logging

from backend.celery_app import celery_app
from scanner.template_engine.executor import run_templates_async
from scanner.template_engine.loader import load_templates

logger = logging.getLogger(__name__)


@celery_app.task(name="scanner.template_engine.bootstrap")
def bootstrap(scan_id: str) -> dict[str, str]:
    return {"scan_id": scan_id, "stage": "template_engine"}


async def _run_template_scan_async(
    endpoints: list[str],
    concurrency: int = 30,
    endpoint_info: list[dict] | None = None,
) -> list[dict[str, object]]:
    """Load templates and execute them against *endpoints*.

    Returns a list of finding dicts ready to merge with detection findings.
    """
    templates = load_templates()
    if not templates:
        logger.warning("No templates loaded — skipping template scan")
        return []

    logger.info(
        "Template scan starting: %d templates × %d endpoints (concurrency=%d)",
        len(templates),
        len(endpoints),
        concurrency,
    )

    matches = await run_templates_async(
        endpoints=endpoints,
        templates=templates,
        concurrency=concurrency,
        endpoint_info=endpoint_info,
    )

    findings = [m.to_dict() for m in matches]
    logger.info("Template scan finished: %d findings", len(findings))
    return findings
