from __future__ import annotations

import csv
from pathlib import Path

from reporting.engine.models import ScanReport

_HEADERS = [
    "scan_id",
    "target",
    "endpoint",
    "vulnerability",
    "vulnerability_type",
    "owasp",
    "cwe",
    "severity",
    "confidence",
    "is_false_positive",
    "explanation",
    "remediation",
]


def write_csv(report: ScanReport, output_dir: Path) -> Path:
    """Write one row per vulnerability to a UTF-8 CSV file under *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{report.scan_id}.csv"

    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_HEADERS, extrasaction="ignore")
        writer.writeheader()
        for vuln in report.vulnerability_details:
            writer.writerow(
                {
                    "scan_id": report.scan_id,
                    "target": report.executive_summary.target,
                    "endpoint": vuln.endpoint,
                    "vulnerability": vuln.vulnerability,
                    "vulnerability_type": vuln.vulnerability_type,
                    "owasp": vuln.owasp,
                    "cwe": vuln.cwe,
                    "severity": vuln.severity,
                    "confidence": vuln.confidence,
                    "is_false_positive": vuln.is_false_positive,
                    "explanation": vuln.explanation,
                    "remediation": vuln.remediation,
                }
            )
    return path
