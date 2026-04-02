from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, field_validator

from backend.api.deps import get_current_user
from backend.celery_app import celery_app
from scanner.scan_manager.models import ScanStatus
from scanner.scan_manager.scan_modes import SCAN_MODES
from scanner.scan_manager.scan_service import (
    cancel_scan,
    create_scan,
    get_asset_intelligence,
    get_scan,
    list_scans,
)
from scanner.scan_manager.tasks import start_scan

router = APIRouter(prefix="/scans", tags=["scans"])

_TARGET_RE = re.compile(
    r"^https?://[^\s/$.?#][^\s]*$"
    r"|^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$"
)


class StartScanRequest(BaseModel):
    target: str
    mode: str = "standard"

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not _TARGET_RE.match(v):
            raise ValueError(
                "target must be a valid URL (https://example.com) or hostname (example.com)"
            )
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        key = v.lower().strip()
        if key not in SCAN_MODES:
            raise ValueError(f"mode must be one of: {sorted(SCAN_MODES)}")
        return key


# ── POST /scans ──────────────────────────────────────────────────────────────

@router.post("", status_code=202, summary="Start a new scan")
async def create_scan_endpoint(
    body: StartScanRequest,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    job = await run_in_threadpool(create_scan, body.target, body.mode)
    start_scan.apply_async(
        args=[job.scan_id, job.target, job.mode],
        task_id=job.scan_id,
    )
    return {
        "scan_id": job.scan_id,
        "target": job.target,
        "mode": job.mode,
        "status": ScanStatus.QUEUED.value,
    }


# ── GET /scans ───────────────────────────────────────────────────────────────

@router.get("", summary="List all scans")
async def list_scans_endpoint(
    _: dict = Depends(get_current_user),
) -> list[dict[str, object]]:
    return await run_in_threadpool(list_scans)


# ── GET /scans/{scan_id} ─────────────────────────────────────────────────────

@router.get("/{scan_id}", summary="Get scan status")
async def get_scan_endpoint(
    scan_id: str,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return job.to_dict()


# ── GET /scans/{scan_id}/asset-intelligence ──────────────────────────────────

@router.get("/{scan_id}/asset-intelligence", summary="Get asset intelligence for a scan")
async def get_asset_intelligence_endpoint(
    scan_id: str,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    assets = await run_in_threadpool(get_asset_intelligence, scan_id)
    if not assets:
        raise HTTPException(
            status_code=404,
            detail=(
                "Asset intelligence not available for this scan. "
                "Run a Standard or Deep scan to generate it."
            ),
        )

    critical_assets = sum(1 for a in assets if a.get("risk_score", 0) >= 80)
    high_risk_assets = sum(1 for a in assets if 60 <= a.get("risk_score", 0) < 80)
    total_cves = sum(len(a.get("cves", [])) for a in assets)

    return {
        "scan_id": scan_id,
        "target": job.target,
        "assets": assets,
        "total_assets": len(assets),
        "critical_assets": critical_assets,
        "high_risk_assets": high_risk_assets,
        "total_cves": total_cves,
    }


# ── DELETE /scans/{scan_id} ──────────────────────────────────────────────────

@router.delete("/{scan_id}", summary="Cancel a running scan")
async def cancel_scan_endpoint(
    scan_id: str,
    _: dict = Depends(get_current_user),
) -> dict[str, str]:
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    cancelled = await run_in_threadpool(cancel_scan, scan_id)
    if not cancelled:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Scan {scan_id!r} cannot be cancelled "
                f"(current status: {job.status.value})"
            ),
        )

    celery_app.control.revoke(scan_id, terminate=True, signal="SIGTERM")
    return {"message": "Scan cancelled", "scan_id": scan_id}
