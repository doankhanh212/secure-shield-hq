from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

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

class AssetCreate(BaseModel):
    domain: str
    ip: str = ""
    cloud: str = ""
    status: str = "active"
    exposure: str = "Public"
    open_ports: list[int] = []
    technologies: list[str] = []
    risk_score: float = 0


class AssetUpdate(BaseModel):
    domain: str | None = None
    ip: str | None = None
    cloud: str | None = None
    status: str | None = None
    exposure: str | None = None
    open_ports: list[int] | None = None
    technologies: list[str] | None = None
    risk_score: float | None = None


# ── Standalone asset CRUD (Redis-backed) ────────────────────────────────────

def _asset_key(asset_id: str) -> str:
    return f"asset:{asset_id}"


def _get_asset(r: _redis.Redis, asset_id: str) -> dict | None:
    raw = r.get(_asset_key(asset_id))
    return json.loads(raw) if raw else None


@router.get("", summary="List all stored assets")
async def list_assets() -> list[dict[str, object]]:
    def _load() -> list[dict[str, object]]:
        r = _r()
        ids = r.smembers("assets:index")
        out: list[dict[str, object]] = []
        for aid in ids:
            data = _get_asset(r, aid)
            if data:
                out.append(data)
        return sorted(out, key=lambda a: a.get("created_at", ""), reverse=True)
    return await run_in_threadpool(_load)


@router.post("", status_code=201, summary="Create a new asset")
async def create_asset(body: AssetCreate) -> dict[str, object]:
    def _create() -> dict[str, object]:
        r = _r()
        asset_id = str(uuid.uuid4())
        data = {
            "id": asset_id,
            "domain": body.domain,
            "ip": body.ip,
            "cloud": body.cloud,
            "status": body.status,
            "exposure": body.exposure,
            "open_ports": body.open_ports,
            "technologies": body.technologies,
            "risk_score": body.risk_score,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        r.set(_asset_key(asset_id), json.dumps(data))
        r.sadd("assets:index", asset_id)
        return data
    return await run_in_threadpool(_create)


@router.put("/{asset_id}", summary="Update an asset")
async def update_asset(asset_id: str, body: AssetUpdate) -> dict[str, object]:
    def _update() -> dict[str, object]:
        r = _r()
        existing = _get_asset(r, asset_id)
        if not existing:
            raise HTTPException(status_code=404, detail="Asset not found")
        updates = body.model_dump(exclude_none=True)
        existing.update(updates)
        r.set(_asset_key(asset_id), json.dumps(existing))
        return existing
    return await run_in_threadpool(_update)


@router.delete("/{asset_id}", summary="Delete an asset")
async def delete_asset(asset_id: str) -> dict[str, str]:
    def _delete() -> None:
        r = _r()
        if not _get_asset(r, asset_id):
            raise HTTPException(status_code=404, detail="Asset not found")
        r.delete(_asset_key(asset_id))
        r.srem("assets:index", asset_id)
    await run_in_threadpool(_delete)
    return {"message": "Asset deleted"}


# ── Scan-based discovery (existing) ─────────────────────────────────────────

@router.get("/{scan_id}/discovery", summary="Get asset discovery results for a scan")
async def get_assets_discovery(scan_id: str) -> dict[str, object]:
    """
    Return discovered domains, subdomains, HTTP services, and fingerprinted
    technologies for the given scan.
    """
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
