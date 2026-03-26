from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

from scanner.scan_manager.scan_service import get_discovery, get_findings, get_scan

router = APIRouter(prefix="/reports", tags=["reports"])

_REPORTS_DIR = os.environ.get("HQG_REPORTS_DIR", "/tmp/hqg-reports")
_SUPPORTED_FORMATS = ("json", "csv", "html", "pdf")
_MEDIA_TYPES: dict[str, str] = {
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "pdf": "application/pdf",
}


def _report_dir(scan_id: str) -> Path:
    return Path(_REPORTS_DIR) / scan_id


def _existing_files(scan_id: str) -> dict[str, dict[str, object]]:
    """Scan the report directory and return metadata for each present format."""
    out: dict[str, dict[str, object]] = {}
    base = _report_dir(scan_id)
    if not base.exists():
        return out
    for fmt in _SUPPORTED_FORMATS:
        candidate = base / f"{scan_id}.{fmt}"
        if candidate.exists():
            stat = candidate.stat()
            out[fmt] = {
                "format": fmt,
                "size_bytes": stat.st_size,
                "generated_at": datetime.fromtimestamp(
                    stat.st_mtime, tz=timezone.utc
                ).isoformat(),
            }
    return out


def _generate_format(scan_id: str, fmt: str, scan_meta: dict[str, object]) -> Path:
    """Build + write a single report format on-demand. Returns the output path."""
    from reporting.engine.report_builder import build_report

    findings = get_findings(scan_id)
    out_dir = _report_dir(scan_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "html":
        # HTML report takes a flat scan_result dict, not a ScanReport object
        from reporting.engine.html_report import write_html
        from reporting.engine.tasks import _build_scan_result_dict

        report = build_report(
            scan_id=scan_id,
            analyzed_vulnerabilities=findings,
            target=str(scan_meta.get("target", "")),
            scan_mode=str(scan_meta.get("mode", "standard")),
        )
        scan_result = _build_scan_result_dict(
            scan_id=scan_id,
            report=report,
            analyzed_vulnerabilities=findings,
            meta=scan_meta,
        )
        html_path = out_dir / f"{scan_id}.html"
        write_html(scan_result, html_path)
        return html_path

    report = build_report(
        scan_id=scan_id,
        analyzed_vulnerabilities=findings,
        target=str(scan_meta.get("target", "")),
        scan_mode=str(scan_meta.get("mode", "standard")),
    )

    if fmt == "json":
        from reporting.engine.json_report import write_json
        return write_json(report, out_dir)
    if fmt == "csv":
        from reporting.engine.csv_report import write_csv
        return write_csv(report, out_dir)
    if fmt == "pdf":
        from reporting.engine.pdf_report import write_pdf
        return write_pdf(report, out_dir)
    raise ValueError(f"Unsupported format: {fmt!r}")


# ── GET /reports/{scan_id} ────────────────────────────────────────────────────

@router.get("/{scan_id}", summary="Get report metadata for a scan")
async def get_report_metadata(scan_id: str) -> dict[str, object]:
    """
    Return metadata for all generated report files associated with *scan_id*.

    If no reports have been generated yet the ``available_formats`` list is empty.
    Use ``GET /reports/{scan_id}/download?format=<fmt>`` to generate and download
    a specific format on demand.
    """
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    files = await run_in_threadpool(_existing_files, scan_id)
    return {
        "scan_id": scan_id,
        "target": job.target,
        "scan_status": job.status.value,
        "available_formats": sorted(files.keys()),
        "files": files,
    }


# ── GET /reports/{scan_id}/download ──────────────────────────────────────────

@router.get("/{scan_id}/download", summary="Download a report file")
async def download_report(
    scan_id: str,
    format: Annotated[  # noqa: A002
        str,
        Query(description="Report format: json | csv | html | pdf"),
    ] = "json",
) -> FileResponse:
    """
    Download a report for *scan_id* in the requested format.

    If the report file does not yet exist it is generated synchronously before
    being served. Use ``format=pdf`` only when WeasyPrint is installed.
    """
    fmt = format.lower().strip()
    if fmt not in _SUPPORTED_FORMATS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported format {fmt!r}. Choose from: {_SUPPORTED_FORMATS}",
        )

    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    candidate = _report_dir(scan_id) / f"{scan_id}.{fmt}"

    if not candidate.exists():
        discovery = await run_in_threadpool(get_discovery, scan_id)
        scan_meta: dict[str, object] = {
            "target":     job.target,
            "mode":       job.mode,
            "started_at": job.created_at,   # Fix #6: use scan creation time for duration
            "discovery":  discovery,         # Fix #5: supply asset discovery data
        }
        try:
            candidate = await run_in_threadpool(
                _generate_format, scan_id, fmt, scan_meta
            )
        except RuntimeError as exc:
            # WeasyPrint not installed etc.
            raise HTTPException(status_code=503, detail=str(exc)) from exc

    return FileResponse(
        path=str(candidate),
        media_type=_MEDIA_TYPES[fmt],
        filename=f"scan-{scan_id}.{fmt}",
    )
