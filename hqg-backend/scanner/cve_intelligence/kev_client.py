"""
CISA Known Exploited Vulnerabilities (KEV) catalog client.

Public API
----------
fetch_kev_catalog(redis_client=None) → set[str]
    Returns the full set of CVE IDs in the KEV catalog.
    Caches in Redis for 24 h when a client is provided.

is_actively_exploited(cve_id, kev_set) → bool
    Lightweight O(1) check.

match_kev(technology, version, kev_data=None) → list[CVERecord]
    Legacy function kept for backward compatibility with cve_lookup.py.
    Filters KEV entries by technology keyword.
"""
from __future__ import annotations

import json
import logging

import httpx

from scanner.cve_intelligence.models import CVERecord

logger = logging.getLogger(__name__)

KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
_KEV_REDIS_KEY = "kev:catalog"
_KEV_REDIS_TTL = 86_400  # 24 hours


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _fetch_kev_raw() -> list[dict]:
    """
    Download the raw KEV catalog from CISA.
    Returns the list of vulnerability dicts.  Empty list on any error.
    """
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0)) as client:
            resp = await client.get(KEV_JSON_URL)
            resp.raise_for_status()
            return resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def fetch_kev_catalog(redis_client=None) -> set[str]:
    """
    Return the set of CVE IDs present in the CISA KEV catalog.

    Uses Redis (key ``kev:catalog``, TTL 24 h) when *redis_client* is provided.
    Falls back to a direct HTTPS fetch on cache miss or Redis error.
    Any network/parse failure returns an empty set — never raises.
    """
    # 1. Try Redis cache
    if redis_client is not None:
        try:
            cached = await redis_client.get(_KEV_REDIS_KEY)
            if cached:
                cve_ids: set[str] = set(json.loads(cached))
                logger.debug("KEV: loaded %d CVE IDs from Redis cache", len(cve_ids))
                return cve_ids
        except Exception as _re:
            logger.debug("KEV: Redis read failed (%s), falling back to HTTP", _re)

    # 2. Fetch from CISA
    raw = await _fetch_kev_raw()
    if not raw:
        return set()

    try:
        cve_ids = {str(entry.get("cveID", "")) for entry in raw if entry.get("cveID")}
    except Exception as exc:
        logger.warning("KEV: JSON parse failed: %s", exc)
        return set()

    # 3. Store in Redis
    if redis_client is not None and cve_ids:
        try:
            await redis_client.setex(_KEV_REDIS_KEY, _KEV_REDIS_TTL, json.dumps(list(cve_ids)))
            logger.debug("KEV: cached %d CVE IDs in Redis (TTL %ds)", len(cve_ids), _KEV_REDIS_TTL)
        except Exception as _we:
            logger.debug("KEV: Redis write failed (%s), continuing without cache", _we)

    logger.info("KEV catalog: %d actively exploited CVEs loaded", len(cve_ids))
    return cve_ids


def is_actively_exploited(cve_id: str, kev_set: set[str]) -> bool:
    """Return True if *cve_id* is in the CISA KEV catalog set."""
    return bool(cve_id) and cve_id in kev_set


# ---------------------------------------------------------------------------
# Backward-compatible legacy function (used by cve_lookup.py)
# ---------------------------------------------------------------------------


async def match_kev(
    technology: str,
    version: str = "",
    kev_data: list[dict] | set[str] | None = None,
) -> list[CVERecord]:
    """
    Filter the KEV catalog for entries matching *technology*.

    *kev_data* can be:
    - ``None``        → fetch raw catalog internally
    - ``list[dict]``  → legacy format from old fetch_kev_catalog()
    - ``set[str]``    → new format (CVE ID set); raw catalog is re-fetched
                        for technology matching (one extra HTTP call)

    Returns a list of CVERecord objects.
    """
    # Resolve raw catalog
    if kev_data is None or isinstance(kev_data, set):
        # Either no data provided, or new-format set (can't filter by tech from set alone)
        raw: list[dict] = await _fetch_kev_raw()
    else:
        raw = kev_data  # legacy list[dict] path

    tech_lower = technology.lower()
    records: list[CVERecord] = []

    for entry in raw:
        vendor = str(entry.get("vendorProject", "")).lower()
        product = str(entry.get("product", "")).lower()

        if tech_lower not in vendor and tech_lower not in product:
            continue

        records.append(
            CVERecord(
                cve_id=str(entry.get("cveID", "")),
                technology=technology,
                version=version,
                cvss=0.0,          # KEV catalog doesn't carry CVSS scores
                severity="High",   # All KEV entries are actively exploited
                summary=str(entry.get("shortDescription", ""))[:500],
                exploit_available=True,
                published_date=str(entry.get("dateAdded", "")),
                source="CISA-KEV",
            )
        )

    return records
