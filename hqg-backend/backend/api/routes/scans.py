from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, field_validator

from backend.celery_app import celery_app
from scanner.scan_manager.models import ScanStatus
from scanner.scan_manager.scan_modes import SCAN_MODES
from scanner.scan_manager.scan_service import (
    cancel_scan,
    create_scan,
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
async def create_scan_endpoint(body: StartScanRequest) -> dict[str, object]:
    """
    Create a scan job and dispatch it to the Celery worker queue.
    Returns immediately with status ``queued``.
    """
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
async def list_scans_endpoint() -> list[dict[str, object]]:
    """
    Return all tracked scans sorted newest-first.

    Fields: scan_id, target, mode, status, stage, progress, created_at.
    """
    return await run_in_threadpool(list_scans)


# ── GET /scans/{scan_id} ─────────────────────────────────────────────────────

@router.get("/{scan_id}", summary="Get scan status")
async def get_scan_endpoint(scan_id: str) -> dict[str, object]:
    """
    Return full scan status including current pipeline stage and progress.
    """
    job = await run_in_threadpool(get_scan, scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return job.to_dict()


# ── DELETE /scans/{scan_id} ──────────────────────────────────────────────────

@router.delete("/{scan_id}", summary="Cancel a running scan")
async def cancel_scan_endpoint(scan_id: str) -> dict[str, str]:
    """
    Mark a queued or running scan as cancelled.
    Returns 404 if the scan does not exist, 409 if it cannot be cancelled.
    """
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

    # Stop queued/running Celery task immediately to avoid further network activity.
    celery_app.control.revoke(scan_id, terminate=True, signal="SIGTERM")

    return {"message": "Scan cancelled", "scan_id": scan_id}
