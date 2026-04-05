from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# CWE mapping: vulnerability_type → CWE root cause identifier.
# This is the one valid static mapping — CWE identifies the weakness class
# of each detection type. OWASP classification is handled dynamically by
# scanner.owasp_mapping.engine.
CWE_MAP: dict[str, str] = {
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "xss_reflected": "CWE-79",
    "xss_stored": "CWE-79",
    "ssrf": "CWE-918",
    "cmdi": "CWE-78",
    "lfi": "CWE-22",
    "path_traversal": "CWE-22",
    "info_disclosure": "CWE-200",
    "time_based_sqli": "CWE-89",
    "time_based_cmdi": "CWE-78",
    "open_redirect": "CWE-601",
}


def cvss_to_severity(score: Optional[float]) -> str:
    """Map CVSS v3.1 score to severity string.

    Returns 'Unscored' when no CVSS score is available (None or 0).
    """
    if score is None:
        return "Unscored"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Unscored"


VULN_NAME_MAP: dict[str, str] = {
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "xss_reflected": "Reflected XSS",
    "xss_stored": "Stored XSS",
    "ssrf": "Server-Side Request Forgery",
    "cmdi": "Command Injection",
    "lfi": "File Inclusion",
    "path_traversal": "Path Traversal",
    "info_disclosure": "Information Disclosure",
    "time_based_sqli": "Time-Based SQL Injection",
    "time_based_cmdi": "Time-Based Command Injection",
    "open_redirect": "Open Redirect",
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
    is_false_positive: bool = field(default=False)
    false_positive_reason: str = field(default="")
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    @property
    def vulnerability(self) -> str:
        return VULN_NAME_MAP.get(self.vulnerability_type, self.vulnerability_type)

    @property
    def cwe(self) -> str:
        return CWE_MAP.get(self.vulnerability_type, "")

    def to_dict(self) -> dict[str, object]:
        """Serialize finding to dict.

        OWASP category and CVSS score are NOT set here — they are assigned
        downstream by the OWASP mapping engine and CVE intelligence layer
        respectively. This ensures no fake/static scoring pollutes findings.
        """
        return {
            "finding_id": self.finding_id,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "http_method": self.http_method,
            "payload": self.payload,
            "vulnerability": self.vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "evidence": self.evidence,
            "discovered_at": self.discovered_at,
        }
