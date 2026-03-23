from __future__ import annotations

import json
from pathlib import Path

from reporting.engine.models import ScanReport


def write_json(report: ScanReport, output_dir: Path) -> Path:
    """Serialize *report* to a pretty-printed JSON file under *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{report.scan_id}.json"
    path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return path
