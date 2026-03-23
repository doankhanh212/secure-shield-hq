from __future__ import annotations

import logging
import time
from pathlib import Path

from backend.celery_app import celery_app
from reporting.engine.csv_report import write_csv
from reporting.engine.html_report import write_html
from reporting.engine.json_report import write_json
from reporting.engine.pdf_report import write_pdf
from reporting.engine.report_builder import build_report

logger = logging.getLogger(__name__)

_FORMAT_WRITERS = {
    "json": write_json,
    "csv": write_csv,
    "html": write_html,
    "pdf": write_pdf,
}


@celery_app.task(name="reporting.engine.generate_report")
def generate_report(
    scan_id: str,
    analyzed_vulnerabilities: list[dict[str, object]],
    formats: list[str] | None = None,
    output_dir: str = "/tmp/hqg-reports",
    scan_meta: dict[str, object] | None = None,
) -> dict[str, object]:
    """
    Build a ScanReport from analyzed vulnerabilities and write to *output_dir*.

    Args:
        scan_id: Unique scan identifier.
        analyzed_vulnerabilities: List of finding dicts from ai.analyzer.
        formats: Desired output formats. Defaults to ["json", "html"].
                 Supported values: "json", "csv", "html", "pdf".
        output_dir: Root directory for report output. A sub-directory named
                    *scan_id* is created inside it.
        scan_meta: Optional dict with keys:
                     target              (str)
                     scan_mode           (str)
                     scan_duration_seconds (float)
                     discovery           (dict) — raw asset discovery output
    """
    requested_formats = [f.lower() for f in (formats or ["json", "html"])]
    invalid = set(requested_formats) - set(_FORMAT_WRITERS)
    if invalid:
        raise ValueError(
            f"Unsupported format(s): {invalid}. "
            f"Choose from: {sorted(_FORMAT_WRITERS)}"
        )

    meta = scan_meta or {}
    started = time.monotonic()

    report = build_report(
        scan_id=scan_id,
        analyzed_vulnerabilities=analyzed_vulnerabilities,
        target=str(meta.get("target", "")),
        scan_mode=str(meta.get("scan_mode", "standard")),
        scan_duration_seconds=float(meta.get("scan_duration_seconds", 0.0)),
        discovery=meta.get("discovery"),  # type: ignore[arg-type]
    )

    out_path = Path(output_dir) / scan_id
    outputs: dict[str, str] = {}

    for fmt in requested_formats:
        file_path = _FORMAT_WRITERS[fmt](report, out_path)
        outputs[fmt] = str(file_path)
        logger.info("scan=%s format=%s written → %s", scan_id, fmt, file_path)

    elapsed = round(time.monotonic() - started, 3)
    logger.info(
        "scan=%s report generation done in %.3fs (%d findings)",
        scan_id, elapsed, report.executive_summary.total_vulnerabilities,
    )

    return {
        "scan_id": scan_id,
        "total_vulnerabilities": report.executive_summary.total_vulnerabilities,
        "confirmed_vulnerabilities": report.executive_summary.confirmed_vulnerabilities,
        "risk_overview": report.risk_overview.to_dict(),
        "outputs": outputs,
        "elapsed_seconds": elapsed,
    }
