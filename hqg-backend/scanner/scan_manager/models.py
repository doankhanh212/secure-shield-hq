from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanStage(str, Enum):
    PENDING = "pending"
    ASSET_DISCOVERY = "asset_discovery"
    CRAWLING = "crawling"
    TEMPLATE_SCAN = "template_scan"
    PAYLOAD_INJECTION = "payload_injection"
    DETECTION = "detection"
    AI_ANALYSIS = "ai_analysis"
    CVE_INTELLIGENCE = "cve_intelligence"
    DONE = "done"


@dataclass
class ScanJob:
    scan_id: str
    target: str
    mode: str
    status: ScanStatus = ScanStatus.QUEUED
    stage: ScanStage = ScanStage.PENDING
    progress: float = 0.0          # 0.0 – 1.0
    error: str | None = None
    created_at: str = ""
    result: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "mode": self.mode,
            "status": self.status.value,
            "stage": self.stage.value,
            "progress": round(self.progress, 4),
            "error": self.error,
            "created_at": self.created_at,
        }
