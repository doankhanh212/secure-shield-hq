"""Asset prioritization based on real security signals.

Sorting priority:
  1. KEV presence   — assets with actively exploited CVEs come first
  2. Max CVSS score — highest CVE severity
  3. Confirmed vulnerabilities — count of high-confidence findings

No synthetic "risk score" is produced. The sort key is a tuple used
directly by the caller to order assets for display/reporting.
"""
from __future__ import annotations

import logging

from scanner.asset_intelligence.models import Asset

logger = logging.getLogger(__name__)


def asset_sort_key(asset: Asset) -> tuple[int, float, int]:
    """Return a sort key for prioritizing assets.

    Higher values = higher priority. Designed for descending sort:
        sorted(assets, key=asset_sort_key, reverse=True)

    Components (all maximized):
      1. KEV flag     — 1 if any CVE is actively exploited, else 0
      2. Max CVSS     — highest CVSS score across asset CVEs (0.0 if none)
      3. Confirmed    — count of high-confidence vulnerabilities
    """
    kev = 1 if asset.has_kev else 0
    max_cvss = asset.max_cvss or 0.0
    confirmed = asset.confirmed_vuln_count

    logger.debug(
        "priority [%s]: kev=%d max_cvss=%.1f confirmed=%d",
        asset.host, kev, max_cvss, confirmed,
    )
    return (kev, max_cvss, confirmed)


def sort_assets(assets: list[Asset]) -> list[Asset]:
    """Sort assets by security priority (most critical first)."""
    return sorted(assets, key=asset_sort_key, reverse=True)
