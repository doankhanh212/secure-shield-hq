"""Main entry point for the Asset Intelligence Layer.

Orchestrates:
  1. Host grouping
  2. Asset creation
  3. Technology fingerprinting (async, per-asset)
  4. Vulnerability + CVE enrichment
  5. Priority sorting (KEV > CVSS > confirmed vulns)

Call ``build_assets`` from the pipeline after crawling and detection
are complete.  The function is intentionally **synchronous** (runs its
own ``asyncio.run``) so it plugs into the existing Celery task flow
without requiring callers to be async-aware.

The async variant ``build_assets_async`` is also exported for callers
that already live in an async context (like ``run_pipeline``).
"""
from __future__ import annotations

import asyncio
import logging

from scanner.asset_intelligence.asset_enricher import enrich_asset
from scanner.asset_intelligence.fingerprint_service import fingerprint_asset
from scanner.asset_intelligence.host_grouper import group_by_host
from scanner.asset_intelligence.models import Asset
from scanner.asset_intelligence.risk_aggregator import sort_assets

logger = logging.getLogger(__name__)


async def build_assets_async(
    urls: list[str],
    findings: list[dict[str, object]] | None = None,
    cve_records: list[dict[str, object]] | None = None,
) -> list[Asset]:
    """Build the full asset inventory (async version).

    Args:
        urls:         Crawled endpoint URLs (flat list).
        findings:     Detection-engine / AI-analyzer findings dicts.
        cve_records:  CVE intelligence record dicts.

    Returns:
        Sorted list of ``Asset`` objects, highest risk first.
    """
    findings = findings or []
    cve_records = cve_records or []

    # 1 — Group URLs by host
    host_map = group_by_host(urls)

    # 2 — Create base Asset objects
    assets: list[Asset] = [
        Asset(host=host, endpoints=sorted(ep_urls))
        for host, ep_urls in host_map.items()
    ]

    # 3 — Fingerprint each asset (concurrently)
    fp_tasks = [
        fingerprint_asset(a.host, a.endpoints) for a in assets
    ]
    fp_results = await asyncio.gather(*fp_tasks, return_exceptions=True)
    for asset, result in zip(assets, fp_results):
        if isinstance(result, list):
            asset.technologies = result
        else:
            logger.warning(
                "fingerprint failed for %s: %s", asset.host, result,
            )

    # 4 — Enrich with vulnerabilities + CVEs
    for asset in assets:
        enrich_asset(asset, findings, cve_records)

    # 5 — Sort by priority (KEV > CVSS > confirmed vulns)
    assets = sort_assets(assets)

    logger.info(
        "asset_intelligence: %d assets built "
        "(%d total vulns, %d total CVEs, top_kev=%s, top_cvss=%s)",
        len(assets),
        sum(len(a.vulnerabilities) for a in assets),
        sum(len(a.cves) for a in assets),
        assets[0].has_kev if assets else False,
        assets[0].max_cvss if assets else None,
    )
    return assets


def build_assets(
    urls: list[str],
    findings: list[dict[str, object]] | None = None,
    cve_records: list[dict[str, object]] | None = None,
) -> list[Asset]:
    """Synchronous wrapper — safe to call from Celery tasks."""
    return asyncio.run(
        build_assets_async(urls, findings=findings, cve_records=cve_records)
    )
