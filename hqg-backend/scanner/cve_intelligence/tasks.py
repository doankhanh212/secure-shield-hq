from __future__ import annotations

import asyncio
import logging

import httpx

from backend.celery_app import celery_app
from scanner.cve_intelligence.cve_lookup import (
    detect_software_versions,
    enrich_findings,
    lookup_cves,
)
from scanner.cve_intelligence.models import CVEIntelligenceOutput, CVERecord
from scanner.cve_intelligence.nvd_client import search_cves_by_cpe

logger = logging.getLogger(__name__)


async def _enrich_async(
    technologies: list[str],
    service_details: list[dict[str, object]],
    findings: list[dict[str, object]],
    *,
    nvd_api_key: str | None = None,
    discovery_data: dict[str, object] | None = None,
) -> dict[str, object]:
    software_versions = detect_software_versions(technologies, service_details)

    cve_records = await lookup_cves(software_versions, nvd_api_key=nvd_api_key)

    # ── CPE-based CVE lookup (additive — does NOT replace keyword search) ──
    wap_techs: list[dict] = []
    if isinstance(discovery_data, dict):
        wap_techs = discovery_data.get("wappalyzer_technologies", []) or []
    elif discovery_data is not None:
        wap_techs = getattr(discovery_data, "wappalyzer_technologies", []) or []

    versioned = [
        t for t in wap_techs
        if t.get("cpe") and t.get("version") and "*" not in str(t["version"])
    ]

    if versioned:
        logger.info("CPE CVE lookup: %d versioned techs to query NVD", len(versioned))
        existing_ids = {r.cve_id for r in cve_records}
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as session:
            for tech in versioned:
                hits = await search_cves_by_cpe(
                    cpe=tech["cpe"],
                    client=session,
                    api_key=nvd_api_key,
                )
                for h in hits:
                    cid = h.get("cve_id", "")
                    if not cid or cid in existing_ids:
                        continue
                    existing_ids.add(cid)
                    try:
                        cve_records.append(
                            CVERecord(
                                cve_id=cid,
                                technology=tech.get("name", ""),
                                version=tech.get("version", ""),
                                cvss=float(h.get("cvss_score") or 0.0),
                                severity=str(h.get("severity") or "Medium"),
                                summary=(h.get("description") or "")[:500],
                                source="NVD-cpe",
                            )
                        )
                    except Exception:
                        continue
                # NVD rate limit: 5 req/30 s without key, 50 req/30 s with key
                await asyncio.sleep(0.7)

        logger.info(
            "CVE Intelligence: %d total CVEs after CPE enrichment",
            len(cve_records),
        )

    enriched_findings = enrich_findings(findings, cve_records)

    output = CVEIntelligenceOutput(
        software_versions=software_versions,
        cve_records=cve_records,
    )

    return {
        "cve_intelligence": output.to_dict(),
        "enriched_findings": enriched_findings,
    }


@celery_app.task(name="scanner.cve_intelligence.enrich_with_cve")
def enrich_with_cve(
    scan_id: str,
    technologies: list[str],
    service_details: list[dict[str, object]],
    findings: list[dict[str, object]],
    nvd_api_key: str | None = None,
    discovery_data: dict[str, object] | None = None,
) -> dict[str, object]:
    """Celery entry-point for CVE intelligence enrichment."""
    result = asyncio.run(
        _enrich_async(
            technologies=technologies,
            service_details=service_details,
            findings=findings,
            nvd_api_key=nvd_api_key,
            discovery_data=discovery_data,
        )
    )
    return {"scan_id": scan_id, **result}
