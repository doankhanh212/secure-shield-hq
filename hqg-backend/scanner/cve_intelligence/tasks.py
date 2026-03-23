from __future__ import annotations

import asyncio
import logging

from backend.celery_app import celery_app
from scanner.cve_intelligence.cve_lookup import (
    detect_software_versions,
    enrich_findings,
    lookup_cves,
)
from scanner.cve_intelligence.models import CVEIntelligenceOutput

logger = logging.getLogger(__name__)


async def _enrich_async(
    technologies: list[str],
    service_details: list[dict[str, object]],
    findings: list[dict[str, object]],
    *,
    nvd_api_key: str | None = None,
) -> dict[str, object]:
    software_versions = detect_software_versions(technologies, service_details)

    cve_records = await lookup_cves(software_versions, nvd_api_key=nvd_api_key)

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
) -> dict[str, object]:
    """Celery entry-point for CVE intelligence enrichment."""
    result = asyncio.run(
        _enrich_async(
            technologies=technologies,
            service_details=service_details,
            findings=findings,
            nvd_api_key=nvd_api_key,
        )
    )
    return {"scan_id": scan_id, **result}
