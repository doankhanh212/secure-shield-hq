"""Post-filter for template-engine findings.

Applies the same false-positive reduction logic that the detection engine
uses, so template findings don't bypass quality filters.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# CSRF / security-token keywords — these are NOT info disclosure
_INFO_DISCLOSURE_SKIP_KEYWORDS = [
    "csrf", "token", "_token", "authenticity_token",
    "__requestverificationtoken", "x-csrf-token", "user_token",
]


def filter_template_findings(
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Remove near-certain false positives from template findings.

    Mirrors the rules in detection_engine.tasks._filter_low_quality_findings
    but operates on raw finding dicts (template output format).
    """
    filtered: list[dict[str, object]] = []

    for f in findings:
        vuln_type = str(f.get("vulnerability_type", "")).lower()
        evidence = str(f.get("evidence", "")).lower()

        # Rule 1: CmdI on error pages — already handled in executor.py,
        # but double-check here as a safety net
        if vuln_type in ("cmdi", "time_based_cmdi"):
            if "not found" in evidence and "404" in evidence:
                logger.debug("Template filter: dropped CmdI on 404 page: %s", f.get("endpoint"))
                continue

        # Rule 2: Info disclosure that is just a CSRF/security token
        if vuln_type == "info_disclosure":
            if any(kw in evidence for kw in _INFO_DISCLOSURE_SKIP_KEYWORDS):
                logger.debug("Template filter: dropped info_disclosure (CSRF token): %s", f.get("endpoint"))
                continue

        # Rule 3: XSS on non-HTML response — downgrade confidence
        if vuln_type == "xss":
            detection = str(f.get("detection_method", ""))
            if detection == "template" and evidence:
                if not any(tag in evidence for tag in ["<html", "<body", "<!doctype", "<div", "<p ", "<form"]):
                    conf = str(f.get("confidence", ""))
                    if conf == "High":
                        f["confidence"] = "Medium"
                    elif conf == "Medium":
                        f["confidence"] = "Low"

        filtered.append(f)

    dropped = len(findings) - len(filtered)
    if dropped:
        logger.info("Template filter: dropped %d/%d false positive findings", dropped, len(findings))

    return filtered
