from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from backend.config import get_settings
from scanner.scan_manager.scan_service import get_discovery, get_scan

import redis as _redis

router = APIRouter(prefix="/assets", tags=["assets"])


def _r() -> _redis.Redis:
    return _redis.from_url(get_settings().redis_url, decode_responses=True)


# ── Pydantic models ─────────────────────────────────────────────────────────

class DomainCreate(BaseModel):
    url: str


# ── Domain helpers (Redis-backed) ───────────────────────────────────────────

def _domain_key(domain_name: str) -> str:
    return f"domain:{domain_name}"


def _get_domain(r: _redis.Redis, domain_name: str) -> dict | None:
    raw = r.get(_domain_key(domain_name))
    return json.loads(raw) if raw else None


def _save_domain(r: _redis.Redis, data: dict) -> None:
    domain_name = data["domain"]
    r.set(_domain_key(domain_name), json.dumps(data))
    r.sadd("domains:index", domain_name)


def _extract_domain(target: str) -> str:
    """Extract domain name from URL or plain hostname."""
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
    else:
        host = target
    # Remove port if present
    return host.split(":")[0].strip().lower()


_SEVERITY_KEYS = ("critical", "high", "medium", "low")


def _summarize_findings(findings: list[dict] | None) -> dict[str, object]:
    all_findings = findings or []
    sev_counts = {key: 0 for key in _SEVERITY_KEYS}
    false_positive_count = 0
    active_vuln_count = 0

    for finding in all_findings:
        if bool(finding.get("is_false_positive", False)):
            false_positive_count += 1
            continue

        active_vuln_count += 1
        sev = str(finding.get("severity", "")).strip().lower()
        if sev in sev_counts:
            sev_counts[sev] += 1

    penalty = (
        sev_counts["critical"] * 25
        + sev_counts["high"] * 15
        + sev_counts["medium"] * 8
        + sev_counts["low"] * 3
    )
    risk_score = max(0.0, float(100 - penalty))

    return {
        "total_vulnerabilities": len(all_findings),
        "severity_counts": sev_counts,
        "false_positive_count": false_positive_count,
        "active_vuln_count": active_vuln_count,
        "vuln_counts": {
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
            "total": active_vuln_count,
        },
        "risk_score": risk_score,
    }


def register_domain_from_scan(
    target: str,
    scan_id: str,
    scan_mode: str,
    discovery: dict | None = None,
    findings: list[dict] | None = None,
) -> None:
    """Called by pipeline to auto-register/update a domain after scan."""
    r = _r()
    domain_name = _extract_domain(target)
    if not domain_name:
        return

    existing = _get_domain(r, domain_name)
    now = datetime.now(timezone.utc).isoformat()

    disc = discovery or {}

    # Extract subdomains
    subdomains = disc.get("subdomains") or []
    if isinstance(subdomains, list):
        subdomains = [str(s) for s in subdomains if s]

    # Extract technologies
    technologies: list[str] = []
    for item in disc.get("technologies") or []:
        if isinstance(item, dict):
            name = item.get("name") or item.get("technology", "")
            if name:
                technologies.append(str(name))
        elif isinstance(item, str):
            technologies.append(item)

    summary = _summarize_findings(findings)

    if existing:
        prev_scan_id = str(existing.get("last_scan_id") or "")
        existing["last_scan_id"] = scan_id
        existing["last_scan_date"] = now
        existing["last_scan_mode"] = scan_mode
        existing["total_scans"] = existing.get("total_scans", 0) + (
            0 if prev_scan_id == scan_id else 1
        )
        existing["total_vulnerabilities"] = summary["total_vulnerabilities"]
        existing["severity_counts"] = summary["severity_counts"]
        existing["false_positive_count"] = summary["false_positive_count"]
        existing["active_vuln_count"] = summary["active_vuln_count"]
        existing["risk_score"] = summary["risk_score"]
        if subdomains:
            merged = list(set(existing.get("subdomains", []) + subdomains))
            existing["subdomains"] = merged
        if technologies:
            existing["technologies"] = technologies
        existing["updated_at"] = now
        _save_domain(r, existing)
    else:
        data = {
            "id": str(uuid.uuid4()),
            "domain": domain_name,
            "url": target,
            "subdomains": subdomains,
            "technologies": technologies,
            "last_scan_id": scan_id,
            "last_scan_date": now,
            "last_scan_mode": scan_mode,
            "total_scans": 1,
            "total_vulnerabilities": summary["total_vulnerabilities"],
            "severity_counts": summary["severity_counts"],
            "false_positive_count": summary["false_positive_count"],
            "active_vuln_count": summary["active_vuln_count"],
            "risk_score": summary["risk_score"],
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
        _save_domain(r, data)


# ── API endpoints ────────────────────────────────────────────────────────────

@router.get("", summary="List all domains")
async def list_assets() -> list[dict[str, object]]:
    def _load() -> list[dict[str, object]]:
        from scanner.scan_manager.scan_service import get_findings

        r = _r()
        names = r.smembers("domains:index")
        out: list[dict[str, object]] = []
        for name in names:
            data = _get_domain(r, name)
            if not data:
                continue

            # Recompute domain vulnerability summary from the latest findings.
            last_scan_id = data.get("last_scan_id")
            if last_scan_id:
                findings = get_findings(str(last_scan_id))
                summary = _summarize_findings(findings)
                data["total_vulnerabilities"] = summary["total_vulnerabilities"]
                data["severity_counts"] = summary["severity_counts"]
                data["false_positive_count"] = summary["false_positive_count"]
                data["active_vuln_count"] = summary["active_vuln_count"]
                data["risk_score"] = summary["risk_score"]
                data["vuln_counts"] = summary["vuln_counts"]
            else:
                data.setdefault("total_vulnerabilities", 0)
                data.setdefault("severity_counts", {k: 0 for k in _SEVERITY_KEYS})
                data.setdefault("false_positive_count", 0)
                data.setdefault("active_vuln_count", 0)
                data["risk_score"] = None  # never scanned → no risk score
                data["vuln_counts"] = None  # never scanned → no vuln data
            out.append(data)
        return sorted(out, key=lambda a: a.get("last_scan_date") or a.get("created_at", ""), reverse=True)
    return await run_in_threadpool(_load)


@router.post("", status_code=201, summary="Add a domain manually")
async def create_asset(body: DomainCreate) -> dict[str, object]:
    def _create() -> dict[str, object]:
        r = _r()
        domain_name = _extract_domain(body.url)
        if not domain_name:
            raise HTTPException(status_code=400, detail="Invalid URL or domain")

        existing = _get_domain(r, domain_name)
        if existing:
            return existing

        now = datetime.now(timezone.utc).isoformat()
        data = {
            "id": str(uuid.uuid4()),
            "domain": domain_name,
            "url": body.url.strip(),
            "subdomains": [],
            "technologies": [],
            "last_scan_id": None,
            "last_scan_date": None,
            "last_scan_mode": None,
            "total_scans": 0,
            "total_vulnerabilities": 0,
            "severity_counts": {},
            "false_positive_count": 0,
            "active_vuln_count": 0,
            "risk_score": None,
            "status": "active",
            "created_at": now,
            "updated_at": now,
        }
        _save_domain(r, data)
        return data
    return await run_in_threadpool(_create)


@router.delete("/{domain_id}", summary="Delete a domain")
async def delete_asset(domain_id: str) -> dict[str, str]:
    def _delete() -> None:
        r = _r()
        # domain_id could be either a UUID or a domain name
        # First try to find by iterating domains
        names = r.smembers("domains:index")
        for name in names:
            data = _get_domain(r, name)
            if data and (data.get("id") == domain_id or data.get("domain") == domain_id):
                r.delete(_domain_key(name))
                r.srem("domains:index", name)
                return
        raise HTTPException(status_code=404, detail="Domain not found")
    await run_in_threadpool(_delete)
    return {"message": "Domain deleted"}


# ── Scan-based discovery (existing) ─────────────────────────────────────────

@router.get("/{scan_id}/discovery", summary="Get asset discovery results for a scan")
async def get_assets_discovery(scan_id: str) -> dict[str, object]:
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    discovery = await run_in_threadpool(get_discovery, scan_id)

    return {
        "scan_id": scan_id,
        "target": job.target,
        "domains": discovery.get("domains", [job.target]),
        "subdomains": discovery.get("subdomains", []),
        "services": discovery.get("services", []),
        "technologies": discovery.get("technologies", []),
    }


# ── Domain report (per-domain, active findings only) ────────────────────────

@router.get("/{domain_id}/report", summary="Download a domain-scoped report excluding false positives")
async def domain_report(domain_id: str, format: str = "html") -> object:  # noqa: A002
    """
    Generate and download a report for the most-recent scan of *domain_id*.
    False-positive findings are excluded automatically.
    Returns a FileResponse.
    """
    from fastapi.responses import FileResponse
    from pathlib import Path
    import os

    fmt = format.lower().strip()
    if fmt not in ("json", "csv", "html", "pdf"):
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt!r}")

    def _build() -> tuple[Path, int]:
        from scanner.scan_manager.scan_service import get_findings, get_discovery, get_attack_paths, get_attack_surface

        r = _r()
        # Resolve domain from ID or name
        names = r.smembers("domains:index")
        domain_data: dict | None = None
        for name in names:
            d = _get_domain(r, name)
            if d and (d.get("id") == domain_id or d.get("domain") == domain_id):
                domain_data = d
                break

        if not domain_data:
            raise HTTPException(status_code=404, detail="Domain not found")

        scan_id = domain_data.get("last_scan_id")
        if not scan_id:
            raise HTTPException(status_code=404, detail="No scans found for this domain")

        # Load and filter findings — exclude false positives
        all_findings = get_findings(str(scan_id))
        active_findings = [f for f in all_findings if not f.get("is_false_positive")]
        fp_count = len(all_findings) - len(active_findings)

        scan_job = get_scan(str(scan_id))
        target = domain_data.get("url") or domain_data.get("domain", "")
        scan_mode = str(scan_job.mode if scan_job else "standard")

        # Build report from active findings only
        from reporting.engine.report_builder import build_report

        report = build_report(
            scan_id=str(scan_id),
            analyzed_vulnerabilities=active_findings,
            target=str(target),
            scan_mode=scan_mode,
        )

        reports_dir = os.environ.get("HQG_REPORTS_DIR", "/tmp/hqg-reports")
        out_dir = Path(reports_dir) / f"domain_{domain_id}"
        out_dir.mkdir(parents=True, exist_ok=True)

        if fmt == "html":
            from reporting.engine.html_report import write_html
            from reporting.engine.tasks import _build_scan_result_dict

            discovery = get_discovery(str(scan_id))
            attack_surface = get_attack_surface(str(scan_id))
            attack_paths = get_attack_paths(str(scan_id))
            meta: dict = {
                "target": target,
                "mode": scan_mode,
                "started_at": scan_job.created_at if scan_job else "",
                "discovery": discovery,
                "attack_surface": attack_surface,
                "attack_paths": attack_paths,
                "false_positive_removed": fp_count,
            }
            scan_result = _build_scan_result_dict(
                scan_id=str(scan_id),
                report=report,
                analyzed_vulnerabilities=active_findings,
                meta=meta,
            )
            scan_result["false_positive_removed"] = fp_count
            out_path = out_dir / f"domain_{domain_id}.html"
            write_html(scan_result, out_path)
            return out_path, fp_count

        if fmt == "json":
            out_path = out_dir / f"domain_{domain_id}.json"
            payload = report.to_dict()
            payload["metadata"] = {"false_positive_removed": fp_count}
            out_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
            return out_path, fp_count
        if fmt == "csv":
            from reporting.engine.csv_report import write_csv
            return write_csv(report, out_dir), fp_count
        if fmt == "pdf":
            from reporting.engine.pdf_report import write_pdf
            return write_pdf(report, out_dir), fp_count
        raise ValueError(f"Unsupported format: {fmt!r}")

    _media: dict[str, str] = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
        "pdf": "application/pdf",
    }

    path, false_positive_removed = await run_in_threadpool(_build)
    return FileResponse(
        path=str(path),
        media_type=_media[fmt],
        filename=f"domain-{domain_id}.{fmt}",
        headers={"X-False-Positive-Removed": str(false_positive_removed)},
    )
