from __future__ import annotations

from datetime import datetime, timezone

from reporting.engine.models import (
    AssetSummary,
    CVEDetail,
    ExecutiveSummary,
    RiskOverview,
    ScanReport,
    VulnerabilityDetail,
    get_remediation,
)


def build_report(
    scan_id: str,
    analyzed_vulnerabilities: list[dict[str, object]],
    *,
    target: str = "",
    scan_mode: str = "standard",
    scan_duration_seconds: float = 0.0,
    discovery: dict[str, object] | None = None,
    cve_intelligence: dict[str, object] | None = None,
) -> ScanReport:
    """
    Assemble a ScanReport from the AI analyzer's finding list.

    Args:
        scan_id: Unique scan identifier.
        analyzed_vulnerabilities: List of finding dicts from ai.analyzer.
        target: Primary scan target hostname/URL.
        scan_mode: Scan mode label (quick / standard / deep / full).
        scan_duration_seconds: Wall-clock seconds the scan took.
        discovery: Raw discovery dict from scanner.asset_discovery (optional).
    """
    details: list[VulnerabilityDetail] = []
    risk = RiskOverview()
    confirmed = 0

    for vuln in analyzed_vulnerabilities:
        is_fp = bool(vuln.get("is_false_positive", False))
        severity = str(vuln.get("severity", "Medium"))
        vuln_type = str(vuln.get("vulnerability_type", ""))

        detail = VulnerabilityDetail(
            endpoint=str(vuln.get("endpoint", "")),
            vulnerability_type=vuln_type,
            vulnerability=str(vuln.get("vulnerability", vuln_type)),
            owasp=str(vuln.get("owasp", "Unknown")),
            cwe=str(vuln.get("cwe", "CWE-0")),
            severity=severity,
            confidence=str(vuln.get("confidence", "Low")),
            explanation=str(vuln.get("explanation", "")),
            remediation=get_remediation(vuln_type),
            is_false_positive=is_fp,
        )
        details.append(detail)

        if not is_fp:
            confirmed += 1
            sev_lower = severity.lower()
            if sev_lower == "critical":
                risk.critical += 1
            elif sev_lower == "high":
                risk.high += 1
            elif sev_lower == "medium":
                risk.medium += 1
            else:
                risk.low += 1

    disc = discovery or {}
    asset_summary = AssetSummary(
        domains=_as_str_list(disc.get("domains") or ([target] if target else [])),
        subdomains=_as_str_list(disc.get("subdomains")),
        services=_extract_services(disc),
        technologies=_extract_technologies(disc),
    )

    exec_summary = ExecutiveSummary(
        target=target,
        scan_mode=scan_mode,
        scan_duration_seconds=round(scan_duration_seconds, 2),
        total_vulnerabilities=len(details),
        confirmed_vulnerabilities=confirmed,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    # --- CVE details ---
    cve_details: list[CVEDetail] = []
    cve_data = cve_intelligence or {}
    for rec in cve_data.get("cve_records") or []:
        if isinstance(rec, dict):
            cve_details.append(
                CVEDetail(
                    cve_id=str(rec.get("cve_id", "")),
                    technology=str(rec.get("technology", "")),
                    version=str(rec.get("version", "")),
                    cvss=float(rec.get("cvss", 0.0)),
                    severity=str(rec.get("severity", "Medium")),
                    summary=str(rec.get("summary", "")),
                    exploit_available=bool(rec.get("exploit_available", False)),
                    source=str(rec.get("source", "NVD")),
                )
            )

    return ScanReport(
        scan_id=scan_id,
        executive_summary=exec_summary,
        risk_overview=risk,
        vulnerability_details=details,
        asset_summary=asset_summary,
        cve_details=cve_details,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _as_str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if v]
    return []


def _extract_services(discovery: dict[str, object]) -> list[str]:
    services: list[str] = []
    for item in discovery.get("services") or []:
        if isinstance(item, dict):
            host = item.get("host", "")
            port = item.get("port", "")
            scheme = item.get("scheme", "")
            if host:
                label = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
                services.append(label)
        elif isinstance(item, str):
            services.append(item)
    return sorted(set(services))


def _extract_technologies(discovery: dict[str, object]) -> list[str]:
    techs: set[str] = set()
    for item in discovery.get("technologies") or []:
        if isinstance(item, dict):
            name = item.get("name") or item.get("technology", "")
            if name:
                techs.add(str(name))
        elif isinstance(item, str):
            techs.add(item)
    return sorted(techs)
