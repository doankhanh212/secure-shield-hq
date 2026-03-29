from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from scanner.scan_manager.scan_service import (
    get_discovery,
    get_findings,
    get_scan,
    store_findings,
)

router = APIRouter(prefix="/findings", tags=["findings"])


class FalsePositiveToggle(BaseModel):
    is_false_positive: bool
    false_positive_reason: str = ""


def _decode_finding_id(finding_id: str) -> tuple[str, int]:
    parts = finding_id.rsplit("_", 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid finding id: {finding_id!r}")
    scan_id, idx_str = parts
    return scan_id, int(idx_str)


@router.put("/{finding_id}/false-positive", summary="Toggle false-positive state for a finding")
async def toggle_false_positive(finding_id: str, body: FalsePositiveToggle) -> dict[str, object]:
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

        # Keep domain-level vulnerability counters in sync immediately.
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
            pass

        finding["id"] = finding_id
        finding["scan_id"] = scan_id
        return finding

    return await run_in_threadpool(_toggle)

