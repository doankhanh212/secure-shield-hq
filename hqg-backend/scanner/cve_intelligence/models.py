from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class SoftwareVersion:
    technology: str
    version: str = ""
    raw_banner: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "technology": self.technology,
            "version": self.version,
            "raw_banner": self.raw_banner,
        }


@dataclass(slots=True)
class CVERecord:
    cve_id: str
    technology: str
    version: str = ""
    cvss: float = 0.0
    severity: str = "Medium"
    summary: str = ""
    exploit_available: bool = False
    published_date: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "cve_id": self.cve_id,
            "technology": self.technology,
            "version": self.version,
            "cvss": self.cvss,
            "severity": self.severity,
            "summary": self.summary,
            "exploit_available": self.exploit_available,
            "published_date": self.published_date,
            "source": self.source,
        }


@dataclass(slots=True)
class CVEIntelligenceOutput:
    software_versions: list[SoftwareVersion] = field(default_factory=list)
    cve_records: list[CVERecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "software_versions": [sv.to_dict() for sv in self.software_versions],
            "cve_records": [cr.to_dict() for cr in self.cve_records],
        }
