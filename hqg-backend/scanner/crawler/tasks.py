from __future__ import annotations

import asyncio

from backend.celery_app import celery_app
from scanner.crawler.crawler import crawl_target_async


@celery_app.task(name="scanner.crawler.crawl_target")
def crawl_target(scan_id: str, target: str, max_depth: int = 2) -> dict[str, object]:
    result = asyncio.run(crawl_target_async(target=target, max_depth=max_depth))
    payload = result.to_dict()
    payload["scan_id"] = scan_id
    payload["target"] = target
    payload["max_depth"] = max_depth
    return payload
