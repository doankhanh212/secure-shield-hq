from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from scanner.scan_manager.scan_service import get_findings, get_scan, list_scans, store_findings

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])


def _vuln_id(scan_id: str, idx: int) -> str:
    """Encode a stable vulnerability ID from its scan and positional index."""
    return f"{scan_id}_{idx}"


def _decode_vuln_id(vuln_id: str) -> tuple[str, int]:
    """Parse a vulnerability ID back into (scan_id, idx). Raises ValueError on bad format."""
    parts = vuln_id.rsplit("_", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid vulnerability id: {vuln_id!r}")
    scan_id, idx_str = parts
    return scan_id, int(idx_str)


# ── GET /vulnerabilities ─────────────────────────────────────────────────────

@router.get("", summary="List vulnerabilities")
async def list_vulnerabilities(
    scan_id: Annotated[str | None, Query(description="Filter by scan ID")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity (Critical/High/Medium/Low)")] = None,
    endpoint: Annotated[str | None, Query(description="Filter by endpoint substring")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
) -> dict[str, object]:
    """
    Return a paginated vulnerability list.

    Supports optional filters: ``scan_id``, ``severity``, ``endpoint``.
    If ``scan_id`` is omitted the 200 most-recent findings across all scans
    are returned (newest scans first).
    """
    def _load() -> list[dict[str, object]]:
        if scan_id:
            scan_ids = [scan_id]
        else:
            all_scans = list_scans()  # already sorted newest-first
            scan_ids = [s["scan_id"] for s in all_scans]

        items: list[dict[str, object]] = []
        for sid in scan_ids:
            for idx, finding in enumerate(get_findings(sid)):
                vuln = dict(finding)
                vuln["id"] = _vuln_id(sid, idx)
                vuln["scan_id"] = sid
                items.append(vuln)

        if severity:
            sev_lower = severity.lower()
            items = [v for v in items if str(v.get("severity", "")).lower() == sev_lower]
        if endpoint:
            items = [v for v in items if endpoint in str(v.get("endpoint", ""))]

        return items[:limit]

    items = await run_in_threadpool(_load)
    return {"total": len(items), "items": items}


# ── GET /vulnerabilities/{id} ────────────────────────────────────────────────

@router.get("/{vuln_id}", summary="Get full vulnerability detail")
async def get_vulnerability(vuln_id: str) -> dict[str, object]:
    """
    Return a single vulnerability by its ID, including explanation and remediation.
    """
    try:
        scan_id, idx = _decode_vuln_id(vuln_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Malformed vulnerability id: {vuln_id!r}")

    def _load() -> dict[str, object] | None:
        if not get_scan(scan_id):
            return None
        findings = get_findings(scan_id)
        if idx < 0 or idx >= len(findings):
            return None
        vuln = dict(findings[idx])
        vuln["id"] = vuln_id
        vuln["scan_id"] = scan_id

        # Attach remediation if not already present (older findings may lack it)
        if "remediation" not in vuln:
            from reporting.engine.models import get_remediation
            vuln["remediation"] = get_remediation(str(vuln.get("vulnerability_type", "")))
        return vuln

    result = await run_in_threadpool(_load)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id!r} not found")
    return result


# ── PATCH /vulnerabilities/{id} ──────────────────────────────────────────────

class VulnPatch(BaseModel):
    status: str | None = None
    is_false_positive: bool | None = None
    remediation_note: str | None = None


@router.patch("/{vuln_id}", summary="Update vulnerability fields")
async def patch_vulnerability(vuln_id: str, body: VulnPatch) -> dict[str, object]:
    """
    Update mutable fields on a vulnerability: status, is_false_positive, remediation_note.
    """
    try:
        scan_id, idx = _decode_vuln_id(vuln_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Malformed vulnerability id: {vuln_id!r}")

    def _patch() -> dict[str, object]:
        if not get_scan(scan_id):
            raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
        findings = get_findings(scan_id)
        if idx < 0 or idx >= len(findings):
            raise HTTPException(status_code=404, detail=f"Vulnerability {vuln_id!r} not found")

        vuln = findings[idx]
        updates = body.model_dump(exclude_none=True)
        vuln.update(updates)
        findings[idx] = vuln
        store_findings(scan_id, findings)

        # If false positive status changed, refresh domain vuln counts
        if "is_false_positive" in updates:
            try:
                from backend.api.routes.assets import register_domain_from_scan
                from scanner.scan_manager.scan_service import get_discovery

                job = get_scan(scan_id)
                if job:
                    discovery = get_discovery(scan_id)
                    register_domain_from_scan(
                        target=job.target,
                        scan_id=scan_id,
                        scan_mode=job.mode,
                        discovery=discovery,
                        findings=findings,
                    )
            except Exception:
                pass  # Domain sync failure is non-fatal

        vuln["id"] = vuln_id
        vuln["scan_id"] = scan_id
        return vuln

    return await run_in_threadpool(_patch)
