"""Data models for the Asset Intelligence Layer.

Uses plain dataclasses (matching the rest of the HQG scanner codebase)
instead of Pydantic so there is zero extra dependency and zero conflict
with existing modules.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Technology:
    """A technology (CMS, framework, server, library) detected on an asset."""

    name: str
    version: Optional[str] = None
    confidence: float = 1.0
    sources: list[str] = field(default_factory=list)
    cpe: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "confidence": round(self.confidence, 2),
            "sources": self.sources,
            "cpe": self.cpe,
        }


@dataclass
class Vulnerability:
    """A vulnerability finding attached to an asset."""

    type: str
    endpoint: str
    severity: str
    confidence: str
    parameter: str = ""
    detection_method: str = ""
    payload: str = ""
    evidence: str = ""
    explanation: str = ""
    impact: str = ""
    remediation: str = ""
    cwe_id: str = ""
    cvss_score: float = 0.0
    owasp_category: str = ""
    verification_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "type": self.type,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "confidence": self.confidence,
            "parameter": self.parameter,
            "detection_method": self.detection_method,
            "payload": self.payload,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "impact": self.impact,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "owasp_category": self.owasp_category,
            "verification_steps": self.verification_steps,
        }


@dataclass
class CVE:
    """A CVE record associated with an asset's technology stack."""

    id: str
    cvss: float
    severity: str
    technology: str = ""
    summary: str = ""
    is_actively_exploited: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "cvss": self.cvss,
            "severity": self.severity,
            "technology": self.technology,
            "summary": self.summary,
            "is_actively_exploited": self.is_actively_exploited,
        }


@dataclass
class Asset:
    """A single network asset (host) with all associated intelligence."""

    host: str
    endpoints: list[str] = field(default_factory=list)
    technologies: list[Technology] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    cves: list[CVE] = field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "endpoints": self.endpoints,
            "technologies": [t.to_dict() for t in self.technologies],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "cves": [c.to_dict() for c in self.cves],
            "risk_score": round(self.risk_score, 2),
        }
