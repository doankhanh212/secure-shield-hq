from __future__ import annotations

from dataclasses import dataclass, field


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

SEVERITY_MAP: dict[str, str] = {
    "sqli": "Critical",
    "xss": "High",
    "ssrf": "High",
    "cmdi": "Critical",
    "lfi": "High",
    "path_traversal": "High",
    "info_disclosure": "Medium",
    "time_based_sqli": "Critical",
    "time_based_cmdi": "Critical",
}

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
    confidence: str       # High | Medium | Low
    detection_method: str # error_pattern | reflection | diff | time_based | lfi_pattern
    evidence: str = field(default="")  # response snippet proving the finding

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
    def severity(self) -> str:
        return SEVERITY_MAP.get(self.vulnerability_type, "Medium")

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "payload": self.payload,
            "vulnerability": self.vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
        }
