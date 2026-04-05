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
    cvss_score: Optional[float] = None
    owasp_category: str = ""
    owasp_source: str = ""
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
            "owasp_source": self.owasp_source,
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

    @property
    def has_kev(self) -> bool:
        """True if any CVE on this asset is in the CISA KEV catalog."""
        return any(c.is_actively_exploited for c in self.cves)

    @property
    def max_cvss(self) -> Optional[float]:
        """Highest CVSS score across all CVEs, or None if no CVEs."""
        if not self.cves:
            return None
        return max(c.cvss for c in self.cves)

    @property
    def confirmed_vuln_count(self) -> int:
        """Count of confirmed vulnerabilities (High confidence)."""
        return sum(1 for v in self.vulnerabilities if v.confidence.lower() in ("high", "confirmed"))

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "endpoints": self.endpoints,
            "technologies": [t.to_dict() for t in self.technologies],
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "cves": [c.to_dict() for c in self.cves],
            "has_kev": self.has_kev,
            "max_cvss": self.max_cvss,
            "confirmed_vuln_count": self.confirmed_vuln_count,
        }
