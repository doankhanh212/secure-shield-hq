from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

from backend.api.deps import get_current_user

from scanner.scan_manager.scan_service import (
    get_asset_intelligence,
    get_attack_paths,
    get_attack_surface,
    get_discovery,
    get_findings,
    get_scan,
)


# ── Retroactive Wappalyzer fingerprinting ────────────────────────────────────

def _retroactive_fingerprint(discovery: dict) -> list[dict]:
    """
    Run Wappalyzer on saved service_details from an old scan that has no
    wappalyzer_technologies.  Returns a list of DetectedTechnology dicts.
    Safe to call in a threadpool — no async I/O.
    """
    try:
        from scanner.asset_discovery.wappalyzer_engine import fingerprint_response
    except Exception:
        return []

    service_details = discovery.get("service_details") or []
    wap_raw = []
    for svc in service_details:
        if not isinstance(svc, dict):
            continue
        body = (
            svc.get("body") or svc.get("html") or
            svc.get("response_body") or svc.get("body_snippet") or ""
        )
        hdrs = svc.get("headers") or {}
        svc_url = svc.get("url") or svc.get("base_url") or ""
        if body or hdrs:
            try:
                wap_raw.extend(fingerprint_response(svc_url, body, hdrs))
            except Exception:
                continue

    # Dedup: keep entry with version over one without
    seen: dict[str, object] = {}
    for t in wap_raw:
        existing = seen.get(t.name)
        if existing is None or (t.version and not existing.version):
            seen[t.name] = t
    return [t.to_dict() for t in seen.values()]


# ── Retroactive CVE lookup via Wappalyzer CPE ────────────────────────────────

async def _build_cve_from_wappalyzer(
    wap_techs: list[dict],
    job: object,
) -> dict:
    """
    Query NVD via CPE for each versioned Wappalyzer tech.
    Returns a cve_intelligence dict compatible with the report renderer.
    """
    import asyncio as _asyncio
    import httpx as _httpx

    try:
        from scanner.cve_intelligence.nvd_client import search_cves_by_cpe
        from backend.config import get_settings as _get_settings
    except Exception:
        return {}

    versioned = [
        t for t in wap_techs
        if t.get("cpe") and t.get("version") and "*" not in str(t.get("version", ""))
    ]
    if not versioned:
        return {}

    try:
        api_key = _get_settings().nvd_api_key or None
    except Exception:
        api_key = None

    cve_records: list[dict] = []
    seen_ids: set[str] = set()

    async with _httpx.AsyncClient(timeout=_httpx.Timeout(15.0)) as session:
        for tech in versioned:
            try:
                hits = await search_cves_by_cpe(
                    cpe=tech["cpe"], client=session, api_key=api_key
                )
                for h in hits:
                    cid = h.get("cve_id", "")
                    if not cid or cid in seen_ids:
                        continue
                    seen_ids.add(cid)
                    cve_records.append({
                        "cve_id":    cid,
                        "technology": tech.get("name", ""),
                        "version":   tech.get("version", ""),
                        "cvss":      float(h.get("cvss_score") or 0.0),
                        "severity":  str(h.get("severity") or "Medium"),
                        "summary":   (h.get("description") or "")[:500],
                        "source":    "NVD-cpe",
                        "is_actively_exploited": False,
                    })
            except Exception:
                continue
            await _asyncio.sleep(0.7)  # NVD rate limit

    if not cve_records:
        return {}

    cve_records.sort(key=lambda r: float(r.get("cvss", 0)), reverse=True)
    return {"cve_records": cve_records, "total_cves": len(cve_records)}


# ── Existing CVE intelligence getter (best-effort from Redis) ─────────────────

def get_cve_intelligence(scan_id: str) -> dict | None:
    """Load cached CVE intelligence from Redis for a scan, if present."""
    try:
        import redis as _redis, json as _json
        from backend.config import get_settings
        r = _redis.from_url(get_settings().redis_url, decode_responses=True)
        raw = r.get(f"scan:{scan_id}:cve_intelligence")
        return _json.loads(raw) if raw else None
    except Exception:
        return None

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
async def get_report_metadata(
    scan_id: str,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
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
    _: dict = Depends(get_current_user),
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
        attack_surface = await run_in_threadpool(get_attack_surface, scan_id)
        attack_paths = await run_in_threadpool(get_attack_paths, scan_id)

        # ── Retroactive Wappalyzer fingerprinting ────────────────────────
        # If the scan ran before Wappalyzer was integrated (or returned no
        # wappalyzer_technologies), re-fingerprint now from saved service_details.
        discovery = dict(discovery or {})
        if not discovery.get("wappalyzer_technologies"):
            discovery["wappalyzer_technologies"] = await run_in_threadpool(
                _retroactive_fingerprint, discovery
            )

        # ── Retroactive CVE enrichment via CPE ───────────────────────────
        # Build cve_intelligence from Wappalyzer CPE data when it's absent.
        cve_intelligence = await run_in_threadpool(
            get_cve_intelligence, scan_id
        )
        if not cve_intelligence:
            cve_intelligence = await _build_cve_from_wappalyzer(
                discovery.get("wappalyzer_technologies") or [],
                job,
            )

        asset_intelligence = await run_in_threadpool(get_asset_intelligence, scan_id)

        scan_meta: dict[str, object] = {
            "target":              job.target,
            "mode":                job.mode,
            "started_at":          job.created_at,
            "discovery":           discovery,
            "cve_intelligence":    cve_intelligence,
            "attack_surface":      attack_surface,
            "attack_paths":        attack_paths,
            "asset_intelligence":  asset_intelligence,
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
