"""Data models for the template-based scanning engine."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class TemplateMatcher:
    """A single matcher rule inside a template."""
    type: str          # word | regex | status | time
    value: str         # pattern, word, status code, or threshold
    part: str = "body"  # body | header | status | time
    negative: bool = False


@dataclass(frozen=True, slots=True)
class TemplateRequest:
    """HTTP request specification inside a template."""
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    inject_in: str = "query"  # query | body | header | path


@dataclass(frozen=True, slots=True)
class ScanTemplate:
    """Parsed representation of a YAML scan template."""
    id: str
    name: str
    severity: str                  # critical | high | medium | low | info
    vulnerability_type: str        # sqli, xss, ssrf, ...
    owasp: str
    cwe: str
    description: str
    payloads: list[str]
    request: TemplateRequest
    matchers: list[TemplateMatcher]
    tags: list[str] = field(default_factory=list)
    match_condition: str = "or"    # or | and


@dataclass(slots=True)
class TemplateMatch:
    """A single finding produced by the template engine."""
    endpoint: str
    payload: str
    template_id: str
    vulnerability_name: str
    vulnerability_type: str
    severity: str
    confidence: str
    owasp: str
    cwe: str
    evidence: str = ""
    detection_method: str = "template"

    def to_dict(self) -> dict[str, object]:
        return {
            "endpoint": self.endpoint,
            "payload": self.payload,
            "template_id": self.template_id,
            "vulnerability": self.vulnerability_name,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "owasp": self.owasp,
            "cwe": self.cwe,
            "evidence": self.evidence,
            "detection_method": self.detection_method,
        }
