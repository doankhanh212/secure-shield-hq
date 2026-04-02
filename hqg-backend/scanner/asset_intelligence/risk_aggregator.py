"""Calculate a composite risk score for an asset.

The score rolls up vulnerability severity and CVSS base scores into
a single 0–100 float that can drive dashboards and prioritisation.
"""
from __future__ import annotations

import logging

from scanner.asset_intelligence.models import Asset

logger = logging.getLogger(__name__)

# Points contributed by each vulnerability severity level
_VULN_SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 15.0,
    "high": 10.0,
    "medium": 5.0,
    "low": 2.0,
}

# Multiplier applied to severity score based on detection confidence
_CONFIDENCE_WEIGHT: dict[str, float] = {
    "confirmed": 1.0,
    "high": 0.9,
    "medium": 0.6,
    "low": 0.3,
}

# Maximum score that the vulnerability component can contribute
_MAX_VULN_COMPONENT = 50.0

# Maximum score that the CVE component can contribute
_MAX_CVE_COMPONENT = 50.0

# Number of highest-CVSS CVEs considered (prevents score inflation)
_TOP_CVE_COUNT = 3


def calculate_risk(asset: Asset) -> float:
    """Calculate a 0–100 risk score for *asset*.

    Components (each capped individually):
      • Vulnerability component (0–50):
          sum of per-severity weights * confidence multiplier,
          capped at ``_MAX_VULN_COMPONENT``.
      • CVE component (0–50):
          sum of CVSS scores for the top ``_TOP_CVE_COUNT`` CVEs,
          capped at ``_MAX_CVE_COMPONENT``.

    Returns:
        A float in [0.0, 100.0].
    """
    # ── Vulnerability component ──────────────────────────────────────────
    vuln_score = 0.0
    for v in asset.vulnerabilities:
        severity_pts = _VULN_SEVERITY_WEIGHT.get(v.severity.lower(), 2.0)
        confidence_mult = _CONFIDENCE_WEIGHT.get(v.confidence.lower(), 0.6)
        vuln_score += severity_pts * confidence_mult
    vuln_score = min(vuln_score, _MAX_VULN_COMPONENT)

    # ── CVE component ────────────────────────────────────────────────────
    # Top N CVEs by CVSS with diminishing-return weights: 1st→1.0, 2nd→0.7, 3rd→0.5
    # This prevents a pile of mid-severity CVEs from inflating the score as
    # much as a single critical one.
    _CVE_WEIGHTS = (1.0, 0.7, 0.5)
    top_cves = sorted(asset.cves, key=lambda c: c.cvss, reverse=True)[:_TOP_CVE_COUNT]
    cve_score = min(
        sum(c.cvss * _CVE_WEIGHTS[i] for i, c in enumerate(top_cves)),
        _MAX_CVE_COMPONENT,
    )

    total = round(vuln_score + cve_score, 2)

    logger.debug(
        "risk [%s]: vuln=%.1f cve=%.1f → total=%.2f",
        asset.host,
        vuln_score,
        cve_score,
        total,
    )
    return total
