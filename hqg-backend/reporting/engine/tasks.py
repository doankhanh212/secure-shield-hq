from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
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
    "pdf": write_pdf,
}

_ALL_FORMATS = set(_FORMAT_WRITERS) | {"html"}


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
                     target                (str)
                     scan_mode             (str)
                     scan_duration_seconds (float)
                     discovery             (dict) — raw asset discovery output
                     cve_intelligence      (dict) — raw CVE intelligence output
                     started_at            (str)  — ISO timestamp
                     scanner_version       (str)
    """
    requested_formats = [f.lower() for f in (formats or ["json", "html"])]
    invalid = set(requested_formats) - _ALL_FORMATS
    if invalid:
        raise ValueError(
            f"Unsupported format(s): {invalid}. "
            f"Choose from: {sorted(_ALL_FORMATS)}"
        )

    meta = scan_meta or {}
    started = time.monotonic()

    report = build_report(
        scan_id=scan_id,
        analyzed_vulnerabilities=analyzed_vulnerabilities,
        target=str(meta.get("target", "")),
        scan_mode=str(meta.get("scan_mode", "standard")),
        scan_duration_seconds=float(meta.get("scan_duration_seconds", 0.0)),
        discovery=meta.get("discovery"),          # type: ignore[arg-type]
        cve_intelligence=meta.get("cve_intelligence"),  # type: ignore[arg-type]
    )

    out_path = Path(output_dir) / scan_id
    out_path.mkdir(parents=True, exist_ok=True)
    outputs: dict[str, str] = {}

    # --- Non-HTML formats (ScanReport-based) ---
    for fmt in requested_formats:
        if fmt == "html":
            continue
        file_path = _FORMAT_WRITERS[fmt](report, out_path)
        outputs[fmt] = str(file_path)
        logger.info("scan=%s format=%s written → %s", scan_id, fmt, file_path)

    # --- HTML format (scan_result dict-based) ---
    if "html" in requested_formats:
        html_path = out_path / f"{scan_id}.html"
        scan_result = _build_scan_result_dict(
            scan_id=scan_id,
            report=report,
            analyzed_vulnerabilities=analyzed_vulnerabilities,
            meta=meta,
        )
        write_html(scan_result, html_path)
        outputs["html"] = str(html_path)
        logger.info("scan=%s format=html written → %s", scan_id, html_path)

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


# ---------------------------------------------------------------------------
# Private helper — assemble the flat dict expected by write_html()
# ---------------------------------------------------------------------------

def _build_scan_result_dict(
    scan_id: str,
    report,  # ScanReport
    analyzed_vulnerabilities: list[dict[str, object]],
    meta: dict[str, object],
) -> dict[str, object]:
    """Convert ScanReport + raw pipeline data into the dict write_html() expects."""
    cve_intel = meta.get("cve_intelligence") or {}
    discovery = meta.get("discovery") or {}

    # CVE records list: prefer raw list from cve_intelligence, fall back to report
    cve_records: list[dict] = []
    raw_cve_records = cve_intel.get("cve_records")
    if isinstance(raw_cve_records, list):
        cve_records = [r for r in raw_cve_records if isinstance(r, dict)]
    else:
        cve_records = [
            {
                "cve_id": c.cve_id,
                "technology": c.technology,
                "version": c.version,
                "cvss": c.cvss,
                "severity": c.severity,
                "summary": c.summary,
                "exploit_available": c.exploit_available,
                "source": c.source,
            }
            for c in report.cve_details
        ]

    # Build versioned tech list: prefer Wappalyzer data (has name+version+cpe)
    # over the plain string list from basic fingerprinting.
    wap_techs: list[dict] = []
    if isinstance(discovery.get("wappalyzer_technologies"), list):
        wap_techs = [
            t for t in discovery["wappalyzer_technologies"]
            if isinstance(t, dict) and t.get("name")
        ]

    if wap_techs:
        # Build display strings: "Name 1.2.3" or "Name" when no version
        tech_display = [
            f"{t['name']} {t['version']}" if t.get("version") else t["name"]
            for t in wap_techs
        ]
        # Also include the raw wappalyzer dicts for richer rendering
    else:
        tech_display = report.asset_summary.technologies

    asset_summary = {
        "domains":      report.asset_summary.domains,
        "subdomains":   report.asset_summary.subdomains,
        "services":     report.asset_summary.services,
        "technologies": tech_display,
        "wappalyzer_technologies": wap_techs,  # full structured data for rich rendering
        "open_ports":   _as_list(discovery.get("open_ports")),
    }

    risk = report.risk_overview.to_dict()
    # Compute overall_score: 100 minus severity-weighted penalty (floor 0)
    _penalty = (
        risk["critical"] * 25
        + risk["high"]     * 15
        + risk["medium"]   *  8
        + risk["low"]      *  3
    )
    risk["overall_score"] = max(0.0, float(100 - _penalty))

    # Count unique endpoints with findings for the asset summary
    _unique_eps = len({
        str(v.get("endpoint", ""))
        for v in analyzed_vulnerabilities
        if v.get("endpoint")
    })
    asset_summary["total_endpoints"] = _unique_eps

    # Asset intelligence: list of per-host dicts from the pipeline
    asset_intelligence_raw = meta.get("asset_intelligence")
    if isinstance(asset_intelligence_raw, list):
        asset_intelligence = [a for a in asset_intelligence_raw if isinstance(a, dict)]
    else:
        asset_intelligence = []

    return {
        "scan_id":        scan_id,
        "target":         report.executive_summary.target,
        "scan_mode":      report.executive_summary.scan_mode,
        "started_at":     str(meta.get("started_at", report.executive_summary.generated_at)),
        "completed_at":   datetime.now(timezone.utc).isoformat(),
        "scanner_version": str(meta.get("scanner_version", "1.0.0")),
        "risk_overview":  risk,
        "asset_summary":  asset_summary,
        "analyzed_vulnerabilities": analyzed_vulnerabilities,
        "cve_intelligence": cve_records,
        "attack_surface": meta.get("attack_surface") or {},
        "attack_paths": meta.get("attack_paths") or [],
        "false_positive_removed": int(meta.get("false_positive_removed", 0)),
        "asset_intelligence": asset_intelligence,
    }


def _as_list(value: object) -> list:
    return list(value) if isinstance(value, (list, tuple, set)) else []
