from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScanModeConfig:
    name: str
    stages: tuple[str, ...]
    max_depth: int
    max_concurrency: int
    inject_headers: bool
    payload_mutation: bool = False
    cve_intelligence: bool = False

    def has_stage(self, stage: str) -> bool:
        return stage in self.stages


QUICK_SCAN = ScanModeConfig(
    name="quick",
    stages=("asset_discovery", "crawling", "template_scan", "payload_injection", "detection"),
    max_depth=2,
    max_concurrency=20,
    inject_headers=False,
    payload_mutation=False,
    cve_intelligence=False,
)

STANDARD_SCAN = ScanModeConfig(
    name="standard",
    stages=("asset_discovery", "crawling", "template_scan", "payload_injection", "detection", "ai_analysis", "cve_intelligence"),
    max_depth=3,
    max_concurrency=40,
    inject_headers=False,
    payload_mutation=False,
    cve_intelligence=True,
)

DEEP_SCAN = ScanModeConfig(
    name="deep",
    stages=("asset_discovery", "crawling", "template_scan", "payload_injection", "detection", "ai_analysis", "cve_intelligence"),
    max_depth=4,
    max_concurrency=40,
    inject_headers=True,
    payload_mutation=True,
    cve_intelligence=True,
)

FULL_ATTACK_SURFACE_SCAN = ScanModeConfig(
    name="full",
    stages=("asset_discovery", "crawling", "template_scan", "payload_injection", "detection", "ai_analysis", "cve_intelligence"),
    max_depth=6,
    max_concurrency=60,
    inject_headers=True,
    payload_mutation=True,
    cve_intelligence=True,
)

SCAN_MODES: dict[str, ScanModeConfig] = {
    "quick": QUICK_SCAN,
    "standard": STANDARD_SCAN,
    "deep": DEEP_SCAN,
    "full": FULL_ATTACK_SURFACE_SCAN,
}


def get_mode(name: str) -> ScanModeConfig:
    key = name.lower().strip()
    if key not in SCAN_MODES:
        raise ValueError(f"Unknown scan mode {name!r}. Valid modes: {list(SCAN_MODES)}")
    return SCAN_MODES[key]
