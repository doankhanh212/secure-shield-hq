from __future__ import annotations

import logging

from backend.config import get_settings

logger = logging.getLogger(__name__)

settings = get_settings()

try:
    from elasticsearch import AsyncElasticsearch

    if settings.elasticsearch_username and settings.elasticsearch_password:
        es_client = AsyncElasticsearch(
            hosts=[settings.elasticsearch_url],
            basic_auth=(settings.elasticsearch_username, settings.elasticsearch_password),
        )
    else:
        es_client = AsyncElasticsearch(hosts=[settings.elasticsearch_url])
except Exception as exc:
    logger.warning("Elasticsearch client unavailable: %s", exc)

    class _StubES:
        """No-op stub so the app starts without Elasticsearch."""
        async def ping(self) -> bool:
            return False
        async def close(self) -> None:
            pass
        async def search(self, **kw: object) -> dict[str, object]:
            return {"hits": {"hits": []}}
        async def index(self, **kw: object) -> dict[str, object]:
            return {}

    es_client = _StubES()  # type: ignore[assignment]
