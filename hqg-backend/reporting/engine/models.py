from __future__ import annotations

from dataclasses import dataclass, field


REMEDIATION_MAP: dict[str, str] = {
    "sqli": (
        "Use parameterized queries or prepared statements. "
        "Never concatenate user input directly into SQL strings. "
        "Apply input validation and run with least-privilege database accounts."
    ),
    "xss": (
        "Encode all user-supplied output using context-aware escaping (HTML, JS, CSS, URL). "
        "Implement a strict Content-Security-Policy header. "
        "Avoid inserting untrusted data into dangerous sinks (innerHTML, document.write)."
    ),
    "ssrf": (
        "Validate and whitelist allowed destination hosts, ports, and protocols. "
        "Use a network-level egress firewall. "
        "Deny requests to private IP ranges (RFC 1918) and link-local addresses."
    ),
    "cmdi": (
        "Avoid passing user input to shell commands. "
        "Use language-native APIs instead of system shells. "
        "If a shell call is unavoidable, strictly whitelist allowed characters and arguments."
    ),
    "lfi": (
        "Resolve all file paths to a canonical form and verify they remain within the allowed "
        "directory. Never expose raw user input to filesystem APIs."
    ),
    "path_traversal": (
        "Normalize file paths and enforce a strict root directory. "
        "Reject any input containing traversal sequences such as ../ or ../."
    ),
    "info_disclosure": (
        "Remove server version headers and disable debug error pages in production. "
        "Disable directory listing. Apply the principle of least information exposure."
    ),
    "time_based_sqli": (
        "Use parameterized queries or prepared statements. "
        "Never concatenate user input directly into SQL strings. "
        "Apply query timeouts and least-privilege database accounts."
    ),
    "time_based_cmdi": (
        "Avoid passing user input to shell commands. "
        "Use language-native APIs and apply strict input whitelisting."
    ),
}

_DEFAULT_REMEDIATION = "Review the vulnerability and apply relevant security best practices per the OWASP Testing Guide."


def get_remediation(vuln_type: str) -> str:
    return REMEDIATION_MAP.get(vuln_type, _DEFAULT_REMEDIATION)


@dataclass(slots=True)
class ExecutiveSummary:
    target: str
    scan_mode: str
    scan_duration_seconds: float
    total_vulnerabilities: int
    confirmed_vulnerabilities: int
    generated_at: str


@dataclass(slots=True)
class RiskOverview:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
        }


@dataclass(slots=True)
class VulnerabilityDetail:
    endpoint: str
    vulnerability_type: str
    vulnerability: str
    owasp: str
    cwe: str
    severity: str
    confidence: str
    explanation: str
    remediation: str
    is_false_positive: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "vulnerability_type": self.vulnerability_type,
            "vulnerability": self.vulnerability,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "is_false_positive": self.is_false_positive,
        }


@dataclass(slots=True)
class AssetSummary:
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "domains": self.domains,
            "subdomains": self.subdomains,
            "services": self.services,
            "technologies": self.technologies,
        }


@dataclass(slots=True)
class CVEDetail:
    cve_id: str
    technology: str
    version: str
    cvss: float
    severity: str
    summary: str
    exploit_available: bool = False
    source: str = "NVD"

    def to_dict(self) -> dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "technology": self.technology,
            "version": self.version,
            "cvss": self.cvss,
            "severity": self.severity,
            "summary": self.summary,
            "exploit_available": self.exploit_available,
            "source": self.source,
        }


@dataclass(slots=True)
class ScanReport:
    scan_id: str
    executive_summary: ExecutiveSummary
    risk_overview: RiskOverview
    vulnerability_details: list[VulnerabilityDetail]
    asset_summary: AssetSummary
    cve_details: list[CVEDetail] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        es = self.executive_summary
        return {
            "scan_id": self.scan_id,
            "executive_summary": {
                "target": es.target,
                "scan_mode": es.scan_mode,
                "scan_duration_seconds": es.scan_duration_seconds,
                "total_vulnerabilities": es.total_vulnerabilities,
                "confirmed_vulnerabilities": es.confirmed_vulnerabilities,
                "generated_at": es.generated_at,
            },
            "risk_overview": self.risk_overview.to_dict(),
            "vulnerability_details": [v.to_dict() for v in self.vulnerability_details],
            "asset_summary": self.asset_summary.to_dict(),
            "cve_details": [c.to_dict() for c in self.cve_details],
        }
