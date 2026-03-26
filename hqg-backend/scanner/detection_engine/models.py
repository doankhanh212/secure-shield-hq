from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


OWASP_MAP: dict[str, str] = {
    "sqli": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "ssrf": "A10:2021 SSRF",
    "cmdi": "A03:2021 Injection",
    "lfi": "A05:2021 Security Misconfiguration",
    "path_traversal": "A05:2021 Security Misconfiguration",
    "info_disclosure": "A02:2021 Cryptographic Failures",
    "time_based_sqli": "A03:2021 Injection",
    "time_based_cmdi": "A03:2021 Injection",
}

CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "ssrf": "CWE-918",
    "cmdi": "CWE-78",
    "lfi": "CWE-22",
    "path_traversal": "CWE-22",
    "info_disclosure": "CWE-200",
    "time_based_sqli": "CWE-89",
    "time_based_cmdi": "CWE-78",
}

CVSS_MAP: dict[str, float] = {
    "sqli": 9.8,
    "xss": 6.1,
    "ssrf": 8.6,
    "cmdi": 9.8,
    "lfi": 7.5,
    "path_traversal": 7.5,
    "info_disclosure": 5.3,
    "time_based_sqli": 7.5,
    "time_based_cmdi": 7.5,
}


def _cvss_to_severity(score: float) -> str:
    """Map CVSS v3.1 score to severity string."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "None"

VULN_NAME_MAP: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "ssrf": "Server-Side Request Forgery",
    "cmdi": "Command Injection",
    "lfi": "File Inclusion",
    "path_traversal": "Path Traversal",
    "info_disclosure": "Information Disclosure",
    "time_based_sqli": "Time-Based SQL Injection",
    "time_based_cmdi": "Time-Based Command Injection",
}


@dataclass(slots=True)
class VulnerabilityFinding:
    endpoint: str
    payload: str
    vulnerability_type: str
    confidence: str        # High | Medium | Low
    detection_method: str  # error_pattern | reflection | diff | time_based | lfi_pattern | template
    evidence: str = field(default="")   # response snippet proving the finding
    parameter: str = field(default="")  # injected parameter name, e.g. "q", "id"
    http_method: str = field(default="GET")
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def vulnerability(self) -> str:
        return VULN_NAME_MAP.get(self.vulnerability_type, self.vulnerability_type)

    @property
    def owasp(self) -> str:
        return OWASP_MAP.get(self.vulnerability_type, "Unknown")

    @property
    def cwe(self) -> str:
        return CWE_MAP.get(self.vulnerability_type, "CWE-0")

    @property
    def cvss_score(self) -> float:
        return CVSS_MAP.get(self.vulnerability_type, 0.0)

    @property
    def severity(self) -> str:
        return _cvss_to_severity(self.cvss_score)

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "http_method": self.http_method,
            "payload": self.payload,
            "vulnerability": self.vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "discovered_at": self.discovered_at,
        }
