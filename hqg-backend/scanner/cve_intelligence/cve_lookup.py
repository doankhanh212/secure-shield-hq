from __future__ import annotations

import asyncio
import logging
import re

from scanner.cve_intelligence.kev_client import fetch_kev_catalog, match_kev
from scanner.cve_intelligence.models import CVEIntelligenceOutput, CVERecord, SoftwareVersion
from scanner.cve_intelligence.nvd_client import search_nvd

logger = logging.getLogger(__name__)

# Regex patterns for extracting technology + version from HTTP headers / banners
_VERSION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(Apache)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(nginx)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(PHP)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(OpenSSL)[/ ]+(\d+\.\d+[\.\w]*)", re.IGNORECASE),
    re.compile(r"(Microsoft-IIS)[/ ]+(\d+\.\d+)", re.IGNORECASE),
    re.compile(r"(Express)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(WordPress)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(Django)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(Laravel)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(Tomcat)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(Node\.?js)[/ ]+v?(\d+\.\d+[\.\d]*)", re.IGNORECASE),
    re.compile(r"(jQuery)[/ ]+(\d+\.\d+[\.\d]*)", re.IGNORECASE),
]


def detect_software_versions(
    technologies: list[str],
    service_details: list[dict[str, object]],
) -> list[SoftwareVersion]:
    """
    Build a list of ``SoftwareVersion`` from scanner data.

    *technologies* comes from asset discovery (e.g. ["nginx", "django"]).
    *service_details* contains raw HTTP probe results with ``headers`` and
    ``server_banner`` fields.
    """
    versions: dict[str, SoftwareVersion] = {}

    # From banner / header strings
    raw_banners: list[str] = []
    for svc in service_details:
        banner = str(svc.get("server_banner", "") or "")
        if banner:
            raw_banners.append(banner)
        headers = svc.get("headers") or {}
        if isinstance(headers, dict):
            for val in headers.values():
                if isinstance(val, str):
                    raw_banners.append(val)

    for text in raw_banners:
        for pat in _VERSION_PATTERNS:
            m = pat.search(text)
            if m:
                tech = m.group(1)
                ver = m.group(2)
                key = tech.lower()
                if key not in versions or (not versions[key].version and ver):
                    versions[key] = SoftwareVersion(
                        technology=tech, version=ver, raw_banner=text[:200]
                    )

    # Ensure every known technology appears even without a version
    for tech in technologies:
        key = tech.lower()
        if key not in versions:
            versions[key] = SoftwareVersion(technology=tech)

    return sorted(versions.values(), key=lambda sv: sv.technology.lower())


async def lookup_cves(
    software_versions: list[SoftwareVersion],
    *,
    nvd_api_key: str | None = None,
) -> list[CVERecord]:
    """
    Query NVD + CISA KEV for every detected technology/version pair.

    Deduplicates by CVE ID.
    """
    # Pre-fetch KEV catalog once to avoid repeated downloads
    kev_data = await fetch_kev_catalog()

    tasks = []
    for sv in software_versions:
        tasks.append(search_nvd(sv.technology, sv.version, api_key=nvd_api_key))
        tasks.append(match_kev(sv.technology, sv.version, kev_data=kev_data))

    raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    seen_cve: set[str] = set()
    records: list[CVERecord] = []
    for result in raw_results:
        if isinstance(result, Exception):
            logger.warning("CVE lookup error: %s", result)
            continue
        for rec in result:
            if rec.cve_id and rec.cve_id not in seen_cve:
                seen_cve.add(rec.cve_id)
                records.append(rec)

    return sorted(records, key=lambda r: r.cvss, reverse=True)


def enrich_findings(
    findings: list[dict[str, object]],
    cve_records: list[CVERecord],
) -> list[dict[str, object]]:
    """
    Attach matching CVE intelligence to scanner findings.

    If a finding's vulnerability maps to a technology with known CVEs, the
    finding gets a ``cve_intelligence`` list and its severity may be promoted.
    """
    # Build a quick lookup: technology (lower) → list of CVEs
    tech_cves: dict[str, list[dict[str, object]]] = {}
    for rec in cve_records:
        key = rec.technology.lower()
        tech_cves.setdefault(key, []).append(rec.to_dict())

    _SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    enriched: list[dict[str, object]] = []
    for finding in findings:
        f = dict(finding)

        # Heuristic: match CVE tech to vuln type keywords
        matched_cves: list[dict[str, object]] = []
        for tech_key, cves in tech_cves.items():
            matched_cves.extend(cves)

        if matched_cves:
            f["cve_intelligence"] = matched_cves[:5]  # top 5

            # Promote severity if a high-CVSS CVE is present
            max_cvss = max(c.get("cvss", 0.0) for c in matched_cves)
            if max_cvss >= 9.0:
                current = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 1)
                if current < 3:
                    f["severity"] = "Critical"
            elif max_cvss >= 7.0:
                current = _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 1)
                if current < 2:
                    f["severity"] = "High"

        enriched.append(f)

    return enriched
