"""Per-asset technology fingerprinting.

Reuses existing detection modules:
  • wappalyzer_engine  — full Wappalyzer.latest() detection + CPE resolution
  • tech_fingerprint   — lightweight header/body heuristics

Fetches a limited number of sample URLs per host to avoid unnecessary
traffic, then merges the signals.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

from scanner.asset_intelligence.models import Technology

logger = logging.getLogger(__name__)

# Maximum pages to fetch per host for fingerprinting
_MAX_SAMPLE_URLS = 5

# Timeout for each probe
_PROBE_TIMEOUT = 8.0

# Concurrency limiter shared across all probes in one call
_SEMAPHORE = asyncio.Semaphore(10)

# In-memory fingerprint cache: host -> (technologies, expiry_monotonic)
# TTL is 600 seconds (10 minutes). No external dependency required.
_FINGERPRINT_CACHE: dict[str, tuple[list[Technology], float]] = {}
_CACHE_TTL = 600.0

# Lock that serialises cache reads and writes under async concurrency.
# Prevents duplicate fingerprinting when two coroutines race on the same host.
_CACHE_LOCK = asyncio.Lock()


async def _fetch_page(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[tuple[str, dict[str, str], str]]:
    """Fetch a single URL and return (body, headers_dict, url) or None."""
    async with _SEMAPHORE:
        try:
            resp = await client.get(url)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.text[:8000], headers, url
        except Exception:
            return None


async def fingerprint_asset(
    host: str,
    urls: list[str],
) -> list[Technology]:
    """Fingerprint a single asset by probing a sample of its URLs.

    Results are cached in-process for ``_CACHE_TTL`` seconds so that the
    same host is never fingerprinted more than once per cache window.

    Detection strategy (ordered by priority):
      1. Wappalyzer.latest() via ``wappalyzer_engine.fingerprint_response``
         → returns name, version, CPE, categories.
      2. Lightweight ``tech_fingerprint._from_headers`` / ``_from_body``
         → adds names the bundled Wappalyzer DB might miss.

    Technologies from both sources are merged and deduplicated.
    Wappalyzer detections (with version+CPE) take priority when the
    same technology is reported by both.

    Args:
        host:  The hostname of the asset.
        urls:  All crawled URLs that belong to this host.

    Returns:
        Deduplicated list of ``Technology`` objects.
    """
    # ── Cache read ───────────────────────────────────────────────────────
    async with _CACHE_LOCK:
        now = time.monotonic()
        cached = _FINGERPRINT_CACHE.get(host)
        if cached is not None:
            techs, expires_at = cached
            if now < expires_at:
                logger.debug("fingerprint_service [%s]: cache hit", host)
                return techs

    sample = urls[:_MAX_SAMPLE_URLS]

    # ── Fetch pages ──────────────────────────────────────────────────────
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(_PROBE_TIMEOUT),
        follow_redirects=True,
        verify=False,
    ) as client:
        tasks = [_fetch_page(client, u) for u in sample]
        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    pages: list[tuple[str, dict[str, str], str]] = [
        r for r in raw_results if isinstance(r, tuple)
    ]
    if not pages:
        logger.debug("fingerprint_service: no reachable pages for %s", host)
        return []

    # ── Wappalyzer detection ─────────────────────────────────────────────
    wap_techs: dict[str, Technology] = {}
    try:
        from scanner.asset_discovery.wappalyzer_engine import fingerprint_response

        for body, headers, page_url in pages:
            for det in fingerprint_response(page_url, body, headers):
                existing = wap_techs.get(det.name)
                # Keep the detection that carries a version
                if existing is None or (det.version and not existing.version):
                    wap_techs[det.name] = Technology(
                        name=det.name,
                        version=det.version,
                        confidence=1.0,
                        sources=["wappalyzer"],
                        cpe=det.cpe,
                    )
    except Exception as exc:
        logger.debug("Wappalyzer unavailable (%s) — falling back to heuristics", exc)

    # ── Lightweight heuristic detection ──────────────────────────────────
    try:
        from scanner.asset_discovery.tech_fingerprint import (
            _from_body,
            _from_headers,
        )

        heuristic_names: set[str] = set()
        for body, headers, _ in pages:
            heuristic_names |= _from_headers(headers)
            if body:
                heuristic_names |= _from_body(body)

        for name in heuristic_names:
            if name not in wap_techs:
                wap_techs[name] = Technology(
                    name=name,
                    confidence=0.6,
                    sources=["heuristic"],
                )
    except Exception as exc:
        logger.debug("Heuristic fingerprint unavailable: %s", exc)

    result = sorted(wap_techs.values(), key=lambda t: t.name.lower())
    logger.info(
        "fingerprint_service [%s]: %d technologies (%d versioned, %d CPE)",
        host,
        len(result),
        sum(1 for t in result if t.version),
        sum(1 for t in result if t.cpe),
    )

    # ── Cache write ──────────────────────────────────────────────────────
    async with _CACHE_LOCK:
        _FINGERPRINT_CACHE[host] = (result, time.monotonic() + _CACHE_TTL)

    return result
