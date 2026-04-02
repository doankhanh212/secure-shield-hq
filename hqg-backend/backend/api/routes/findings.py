from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, field_validator

from backend.api.deps import get_current_user
from scanner.scan_manager.scan_service import (
    get_discovery,
    get_findings,
    get_scan,
    store_findings,
)

router = APIRouter(prefix="/findings", tags=["findings"])
logger = logging.getLogger(__name__)


class FalsePositiveToggle(BaseModel):
    is_false_positive: bool
    false_positive_reason: str = ""

    @field_validator("false_positive_reason", mode="before")
    @classmethod
    def limit_reason_length(cls, v: object) -> object:
        if isinstance(v, str) and len(v) > 2000:
            raise ValueError("Reason must not exceed 2000 characters")
        return v


def _decode_finding_id(finding_id: str) -> tuple[str, int]:
    parts = finding_id.rsplit("_", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid finding id: {finding_id!r}")
    return parts[0], int(parts[1])


@router.put("/{finding_id}/false-positive", summary="Toggle false-positive state for a finding")
async def toggle_false_positive(
    finding_id: str,
    body: FalsePositiveToggle,
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    try:
        scan_id, idx = _decode_finding_id(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Malformed finding id: {finding_id!r}")

    def _toggle() -> dict[str, object]:
        job = get_scan(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

        findings = get_findings(scan_id)
        if idx < 0 or idx >= len(findings):
            raise HTTPException(status_code=404, detail=f"Finding {finding_id!r} not found")

        finding = dict(findings[idx])
        finding["is_false_positive"] = body.is_false_positive
        finding["false_positive_reason"] = (
            body.false_positive_reason.strip() if body.is_false_positive else ""
        )
        findings[idx] = finding
        store_findings(scan_id, findings)

        try:
            from backend.api.routes.assets import register_domain_from_scan

            register_domain_from_scan(
                target=job.target,
                scan_id=scan_id,
                scan_mode=job.mode,
                discovery=get_discovery(scan_id),
                findings=findings,
            )
        except Exception:
            logger.debug("Domain sync after FP toggle failed", exc_info=True)

        finding["id"] = finding_id
        finding["scan_id"] = scan_id
        return finding

    return await run_in_threadpool(_toggle)
