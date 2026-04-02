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


async def search_cves_by_cpe(
    cpe: str,
    client: httpx.AsyncClient,
    api_key: str | None = None,
) -> list[dict]:
    """
    Precise CVE lookup using NVD 2.0 cpeName parameter.

    Complements the existing keyword search with version-exact results.
    Only called when a Wappalyzer detection yielded a versioned CPE.

    Returns plain dicts (not CVERecord) so callers control dedup + typing.
    """
    params = {"cpeName": cpe, "resultsPerPage": 20}
    req_headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = await client.get(
            NVD_API_BASE,
            params=params,
            headers=req_headers,
            timeout=15.0,
        )
        if resp.status_code != 200:
            logger.warning("NVD CPE lookup HTTP %d for: %s", resp.status_code, cpe)
            return []

        results: list[dict] = []
        for item in resp.json().get("vulnerabilities", []):
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id", "")
            if not cve_id:
                continue

            cvss_score: float | None = None
            severity: str | None = None
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                m_list = cve_obj.get("metrics", {}).get(key, [])
                if m_list:
                    d = m_list[0].get("cvssData", {})
                    cvss_score = d.get("baseScore")
                    severity = d.get("baseSeverity")
                    break

            desc = next(
                (d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
                "",
            )
            results.append(
                {
                    "cve_id": cve_id,
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "description": desc[:200],
                    "source": "cpe_match",
                    "matched_cpe": cpe,
                }
            )

        logger.info("NVD CPE %s → %d CVEs", cpe, len(results))
        return results

    except Exception as exc:
        logger.warning("NVD CPE failed %s: %s", cpe, exc)
        return []
