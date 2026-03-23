from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import redis

from backend.config import get_settings
from scanner.scan_manager.models import ScanJob, ScanStage, ScanStatus


def _redis_client() -> redis.Redis:
    settings = get_settings()
    return redis.from_url(settings.redis_url, decode_responses=True)


def _key(scan_id: str) -> str:
    return f"scan:{scan_id}"


def create_scan(target: str, mode: str) -> ScanJob:
    scan_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    job = ScanJob(scan_id=scan_id, target=target, mode=mode, created_at=created_at)
    r = _redis_client()
    r.sadd("scans:index", scan_id)
    _persist(job)
    return job


def get_scan(scan_id: str) -> ScanJob | None:
    r = _redis_client()
    raw = r.get(_key(scan_id))
    if not raw:
        return None
    data = json.loads(raw)
    return ScanJob(
        scan_id=data["scan_id"],
        target=data["target"],
        mode=data["mode"],
        status=ScanStatus(data["status"]),
        stage=ScanStage(data["stage"]),
        progress=data["progress"],
        error=data.get("error"),
        created_at=data.get("created_at", ""),
    )


def update_scan(
    scan_id: str,
    *,
    status: ScanStatus | None = None,
    stage: ScanStage | None = None,
    progress: float | None = None,
    error: str | None = None,
) -> None:
    job = get_scan(scan_id)
    if not job:
        return
    if status is not None:
        job.status = status
    if stage is not None:
        job.stage = stage
    if progress is not None:
        job.progress = progress
    if error is not None:
        job.error = error
    _persist(job)


def list_scans() -> list[dict[str, object]]:
    r = _redis_client()
    scan_ids = r.smembers("scans:index")
    scans: list[dict[str, object]] = []
    for sid in scan_ids:
        job = get_scan(sid)
        if job:
            scans.append(job.to_dict())
    return sorted(scans, key=lambda s: s.get("created_at", ""), reverse=True)


def cancel_scan(scan_id: str) -> bool:
    job = get_scan(scan_id)
    if not job or job.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
        return False
    update_scan(scan_id, status=ScanStatus.CANCELLED)
    return True


def store_findings(scan_id: str, findings: list[dict[str, object]]) -> None:
    r = _redis_client()
    r.set(f"scan:{scan_id}:findings", json.dumps(findings), ex=86400 * 7)


def get_findings(scan_id: str) -> list[dict[str, object]]:
    r = _redis_client()
    raw = r.get(f"scan:{scan_id}:findings")
    return json.loads(raw) if raw else []


def store_discovery(scan_id: str, discovery: dict[str, object]) -> None:
    r = _redis_client()
    r.set(f"scan:{scan_id}:discovery", json.dumps(discovery), ex=86400 * 7)


def get_discovery(scan_id: str) -> dict[str, object]:
    r = _redis_client()
    raw = r.get(f"scan:{scan_id}:discovery")
    return json.loads(raw) if raw else {}


def _persist(job: ScanJob) -> None:
    r = _redis_client()
    data = {
        "scan_id": job.scan_id,
        "target": job.target,
        "mode": job.mode,
        "status": job.status.value,
        "stage": job.stage.value,
        "progress": job.progress,
        "error": job.error,
        "created_at": job.created_at,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    r.set(_key(job.scan_id), json.dumps(data), ex=86400 * 7)
