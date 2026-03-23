from __future__ import annotations

import logging

import httpx

from scanner.cve_intelligence.models import CVERecord

logger = logging.getLogger(__name__)

KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev_catalog() -> list[dict[str, object]]:
    """
    Download the CISA Known Exploited Vulnerabilities (KEV) catalog.

    Returns the raw vulnerability list.  On failure returns an empty list.
    """
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            resp = await client.get(KEV_JSON_URL)
            resp.raise_for_status()
            return resp.json().get("vulnerabilities", [])
    except Exception as exc:
        logger.warning("CISA KEV fetch failed: %s", exc)
        return []


async def match_kev(
    technology: str,
    version: str = "",
    kev_data: list[dict[str, object]] | None = None,
) -> list[CVERecord]:
    """
    Filter the KEV catalog for entries matching *technology*.

    If *kev_data* is not provided the catalog is fetched on-demand.
    """
    if kev_data is None:
        kev_data = await fetch_kev_catalog()

    tech_lower = technology.lower()
    records: list[CVERecord] = []

    for entry in kev_data:
        vendor = str(entry.get("vendorProject", "")).lower()
        product = str(entry.get("product", "")).lower()

        if tech_lower not in vendor and tech_lower not in product:
            continue

        records.append(
            CVERecord(
                cve_id=str(entry.get("cveID", "")),
                technology=technology,
                version=version,
                cvss=0.0,  # KEV catalog doesn't carry CVSS scores
                severity="High",  # All KEV entries are exploited ⇒ treat as High+
                summary=str(entry.get("shortDescription", ""))[:500],
                exploit_available=True,
                published_date=str(entry.get("dateAdded", "")),
                source="CISA-KEV",
            )
        )

    return records
