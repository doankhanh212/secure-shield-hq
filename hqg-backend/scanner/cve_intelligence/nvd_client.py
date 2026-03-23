from __future__ import annotations

import logging
import re

import httpx

from scanner.cve_intelligence.models import CVERecord

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cvss_score(vuln_item: dict) -> float:
    """Extract the best available CVSS score from NVD metrics."""
    metrics = vuln_item.get("metrics", {})
    for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(version_key, [])
        if entries:
            return float(entries[0].get("cvssData", {}).get("baseScore", 0.0))
    return 0.0


def _severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


async def search_nvd(
    technology: str,
    version: str = "",
    *,
    max_results: int = 10,
    api_key: str | None = None,
) -> list[CVERecord]:
    """
    Query the NVD 2.0 REST API for CVEs matching *technology* (and optional *version*).

    Returns a list of ``CVERecord`` objects.  Network errors are logged and
    result in an empty list so the pipeline is never blocked.
    """
    keyword = f"{technology} {version}".strip()
    params: dict[str, str | int] = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }

    headers: dict[str, str] = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(20.0)) as client:
            resp = await client.get(NVD_API_BASE, params=params, headers=headers)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("NVD lookup failed for %r: %s", keyword, exc)
        return []

    records: list[CVERecord] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        summary = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            "",
        )
        cvss = _cvss_score(cve)
        published = cve.get("published", "")[:10]

        records.append(
            CVERecord(
                cve_id=cve_id,
                technology=technology,
                version=version,
                cvss=cvss,
                severity=_severity_from_cvss(cvss),
                summary=summary[:500],
                published_date=published,
                source="NVD",
            )
        )

    return records
