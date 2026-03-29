from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class AnalyzedVulnerability:
    endpoint: str
    vulnerability: str
    vulnerability_type: str
    owasp: str
    cwe: str
    severity: str
    confidence: str
    explanation: str
    payload: str = ""
    detection_method: str = ""
    is_false_positive: bool = False
    false_positive_reason: str = ""
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "vulnerability": self.vulnerability,
            "vulnerability_type": self.vulnerability_type,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "payload": self.payload,
            "detection_method": self.detection_method,
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "tags": self.tags,
        }
