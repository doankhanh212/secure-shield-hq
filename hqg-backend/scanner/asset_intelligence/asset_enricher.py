"""Attach vulnerability findings and CVE records to an asset.

This module does NOT re-run the detection engine or NVD queries.
It consumes data that the pipeline has already produced and maps each
record to the correct asset by matching endpoints/technology names.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

from scanner.asset_intelligence.models import Asset, CVE, Vulnerability

logger = logging.getLogger(__name__)


def _parse_version(version: str) -> tuple[int, ...]:
    """Convert a dotted version string to a tuple of ints for comparison."""
    parts = re.findall(r'\d+', version)
    return tuple(int(p) for p in parts) if parts else ()


def version_in_range(version: str, range_str: str) -> bool:
    """Return True when *version* satisfies all constraints in *range_str*.

    Supported range_str formats::

        '>=7.0'
        '<=8.1'
        '>=5.6,<8.0'

    Fallback rules:
      * Either argument missing/empty  → True  (no info, don't suppress CVE)
      * Both present but version fails to parse → False (fail-safe: malformed
        version string must not produce incorrect CVE matches)
    """
    if not version or not range_str:
        return True

    ver = _parse_version(version)
    if not ver:
        # version string present but unparseable — fail-safe
        return False

    for constraint in range_str.split(','):
        m = re.match(r'^\s*(>=|<=|>|<|==)\s*([\d.]+)', constraint.strip())
        if not m:
            continue  # unrecognised token — skip, don't reject
        op, v_str = m.group(1), m.group(2)
        cmp_ver = _parse_version(v_str)
        if not cmp_ver:
            continue
        if op == '>=' and not (ver >= cmp_ver):
            return False
        elif op == '<=' and not (ver <= cmp_ver):
            return False
        elif op == '>' and not (ver > cmp_ver):
            return False
        elif op == '<' and not (ver < cmp_ver):
            return False
        elif op == '==' and not (ver == cmp_ver):
            return False

    return True


def _host_owns_endpoint(host: str, endpoint: str) -> bool:
    """Return True when *endpoint* belongs to *host*."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(endpoint)
        return (parsed.hostname or parsed.netloc or "").lower() == host.lower()
    except Exception:
        return False


def attach_vulnerabilities(
    asset: Asset,
    findings: list[dict[str, object]],
) -> None:
    """Map pipeline findings to the asset based on endpoint ownership.

    Only findings whose ``endpoint`` belongs to ``asset.host`` are attached.
    Duplicates (same type + endpoint + parameter) are suppressed.
    """
    seen: set[tuple[str, str, str]] = set()
    for f in findings:
        ep = str(f.get("endpoint", ""))
        if not _host_owns_endpoint(asset.host, ep):
            continue

        vtype = str(f.get("vulnerability_type", ""))
        param = str(f.get("parameter", ""))
        key = (vtype, ep, param)
        if key in seen:
            continue
        seen.add(key)

        # verification_steps may be a list or a newline-separated string
        raw_steps = f.get("verification_steps")
        if isinstance(raw_steps, list):
            vsteps: list[str] = [str(s) for s in raw_steps if s]
        elif isinstance(raw_steps, str) and raw_steps.strip():
            vsteps = [s.strip() for s in raw_steps.splitlines() if s.strip()]
        else:
            vsteps = []

        asset.vulnerabilities.append(
            Vulnerability(
                type=vtype,
                endpoint=ep,
                severity=str(f.get("severity", "Medium")),
                confidence=str(f.get("confidence", "Medium")),
                parameter=param,
                detection_method=str(f.get("detection_method", "")),
                payload=str(f.get("payload", "") or f.get("poc", "") or ""),
                evidence=str(f.get("evidence", "") or ""),
                explanation=str(f.get("explanation", "") or ""),
                impact=str(f.get("impact", "") or ""),
                remediation=str(f.get("remediation", "") or f.get("fix_recommendation", "") or ""),
                cwe_id=str(f.get("cwe_id", "") or ""),
                cvss_score=float(f.get("cvss_score", 0.0) or 0.0),
                owasp_category=str(f.get("owasp_category", "") or ""),
                verification_steps=vsteps,
            )
        )


def attach_cves(
    asset: Asset,
    cve_records: list[dict[str, object]],
) -> None:
    """Attach CVE records whose technology matches the asset's tech stack.

    Matching is case-insensitive on technology name. Version compatibility
    is verified via ``version_in_range`` when the CVE record carries a
    version range string, preventing e.g. PHP 7 being mapped to PHP 8 CVEs.
    """
    tech_names = {t.name.lower() for t in asset.technologies}
    if not tech_names:
        return

    # Build a map of tech name → detected version for range checking
    tech_versions: dict[str, str] = {
        t.name.lower(): (t.version or "") for t in asset.technologies
    }

    seen_ids: set[str] = set()
    for rec in cve_records:
        cve_id = str(rec.get("cve_id", ""))
        if not cve_id or cve_id in seen_ids:
            continue

        rec_tech = str(rec.get("technology", "")).lower()
        if rec_tech not in tech_names:
            continue

        # Version range check — only filter when CVE carries explicit range
        rec_version_range = str(rec.get("version", ""))
        detected_version = tech_versions.get(rec_tech, "")
        if rec_version_range and not version_in_range(detected_version, rec_version_range):
            logger.debug(
                "Skipping CVE %s for %s: version %r not in range %r",
                cve_id,
                rec_tech,
                detected_version,
                rec_version_range,
            )
            continue

        seen_ids.add(cve_id)
        asset.cves.append(
            CVE(
                id=cve_id,
                cvss=float(rec.get("cvss", 0.0)),
                severity=str(rec.get("severity", "Medium")),
                technology=rec_tech,
                summary=str(rec.get("summary", ""))[:200],
                is_actively_exploited=bool(rec.get("is_actively_exploited", False)),
            )
        )


def enrich_asset(
    asset: Asset,
    findings: list[dict[str, object]],
    cve_records: list[dict[str, object]],
) -> Asset:
    """One-call convenience: attach both vulns and CVEs, then return asset."""
    attach_vulnerabilities(asset, findings)
    attach_cves(asset, cve_records)
    logger.info(
        "enrich_asset [%s]: %d vulns, %d CVEs attached",
        asset.host,
        len(asset.vulnerabilities),
        len(asset.cves),
    )
    return asset
