from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, field_validator

from backend.api.deps import get_current_user
from scanner.scan_manager.scan_service import get_findings, get_scan, list_scans, store_findings

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
logger = logging.getLogger(__name__)


def _vuln_id(scan_id: str, idx: int) -> str:
    return f"{scan_id}_{idx}"


def _decode_vuln_id(vuln_id: str) -> tuple[str, int]:
    parts = vuln_id.rsplit("_", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid vulnerability id: {vuln_id!r}")
    scan_id, idx_str = parts
    return scan_id, int(idx_str)


# ── GET /vulnerabilities ─────────────────────────────────────────────────────

@router.get("", summary="List vulnerabilities")
async def list_vulnerabilities(
    scan_id: Annotated[str | None, Query(description="Filter by scan ID")] = None,
    severity: Annotated[str | None, Query(description="Filter by severity")] = None,
    domain: Annotated[str | None, Query(description="Filter by domain substring")] = None,
    endpoint: Annotated[str | None, Query(description="Filter by endpoint substring")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    def _load() -> list[dict[str, object]]:
        if scan_id:
            scan_ids = [scan_id]
        else:
            all_scans = list_scans()
            # Only load findings from completed scans, cap at 20 most recent
            scan_ids = [
                s["scan_id"] for s in all_scans
                if str(s.get("status", "")) == "completed"
            ][:20]

        items: list[dict[str, object]] = []
        for sid in scan_ids:
            for idx, finding in enumerate(get_findings(sid)):
                if bool(finding.get("is_false_positive", False)):
                    continue
                vuln = dict(finding)
                vuln["id"] = _vuln_id(sid, idx)
                vuln["scan_id"] = sid
                items.append(vuln)
            if len(items) >= limit:
                break

        if severity:
            sev_lower = severity.lower()
            items = [v for v in items if str(v.get("severity", "")).lower() == sev_lower]
        if domain:
            domain_lower = domain.lower()
            items = [v for v in items if domain_lower in str(v.get("endpoint", "")).lower()]
        if endpoint:
            items = [v for v in items if endpoint in str(v.get("endpoint", ""))]

        return items[:limit]

    items = await run_in_threadpool(_load)
    return {"total": len(items), "items": items}


# ── GET /vulnerabilities/{id} ────────────────────────────────────────────────

@router.get("/{vuln_id}", summary="Get full vulnerability detail")
async def get_vulnerability(
    vuln_id: str,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
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
    false_positive_reason: str | None = None
    remediation_note: str | None = None

    @field_validator("false_positive_reason", "remediation_note", mode="before")
    @classmethod
    def limit_string_length(cls, v: object) -> object:
        if isinstance(v, str) and len(v) > 2000:
            raise ValueError("Field must not exceed 2000 characters")
        return v


@router.patch("/{vuln_id}", summary="Update vulnerability fields")
async def patch_vulnerability(
    vuln_id: str,
    body: VulnPatch,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
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
        if updates.get("is_false_positive") is False and "false_positive_reason" not in updates:
            updates["false_positive_reason"] = ""
        vuln.update(updates)
        findings[idx] = vuln
        store_findings(scan_id, findings)

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
                logger.debug("Domain sync after false-positive update failed", exc_info=True)

        vuln["id"] = vuln_id
        vuln["scan_id"] = scan_id
        return vuln

    return await run_in_threadpool(_patch)
