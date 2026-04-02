from __future__ import annotations

import json
import logging
import os

import httpx
from fastapi import APIRouter, Body, Depends
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

import redis as _redis

from backend.api.deps import get_current_user
from backend.config import get_settings

router = APIRouter(prefix="/settings", tags=["settings"])
logger = logging.getLogger(__name__)


def _r() -> _redis.Redis:
    return _redis.from_url(get_settings().redis_url, decode_responses=True)


_REDIS_SETTINGS_KEY = "hqg:settings"

_PERSIST_KEYS = {
    "platform_name", "language", "daily_scans",
    "ai_analysis", "distributed_scanning",
    "email_notifications", "scan_workers",
}


def _load_persisted() -> dict[str, object]:
    try:
        r = _r()
        raw = r.get(_REDIS_SETTINGS_KEY)
        return json.loads(raw) if raw else {}
    except Exception:
        logger.debug("Failed to load settings from Redis", exc_info=True)
        return {}


def _save_persisted(data: dict[str, object]) -> None:
    try:
        r = _r()
        r.set(_REDIS_SETTINGS_KEY, json.dumps(data))
    except Exception:
        logger.warning("Failed to save settings to Redis", exc_info=True)


@router.get("", summary="Get current platform settings")
async def get_platform_settings(
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    settings = get_settings()
    persisted = await run_in_threadpool(_load_persisted)

    return {
        "platform_name": persisted.get("platform_name", settings.app_name),
        "language": persisted.get("language", "vi"),
        "nvd_api_key_configured": bool(settings.nvd_api_key or os.environ.get("NVD_API_KEY")),
        "daily_scans": persisted.get("daily_scans", True),
        "ai_analysis": persisted.get("ai_analysis", True),
        "distributed_scanning": persisted.get("distributed_scanning", False),
        "email_notifications": persisted.get("email_notifications", True),
        "scan_workers": persisted.get("scan_workers", 4),
    }


@router.put("", summary="Update platform settings")
async def update_platform_settings(
    data: dict = Body(...),
    _: dict = Depends(get_current_user),
) -> dict[str, object]:
    settings = get_settings()

    if "nvd_api_key" in data and data["nvd_api_key"]:
        key_value = str(data["nvd_api_key"]).strip()
        os.environ["NVD_API_KEY"] = key_value
        object.__setattr__(settings, "nvd_api_key", key_value)

    persisted = await run_in_threadpool(_load_persisted)
    for k in _PERSIST_KEYS:
        if k in data:
            persisted[k] = data[k]
    await run_in_threadpool(_save_persisted, persisted)

    return {
        "status": "ok",
        "nvd_api_key_configured": bool(settings.nvd_api_key or os.environ.get("NVD_API_KEY")),
    }


@router.post("/verify-nvd-key", summary="Verify an NVD API key")
async def verify_nvd_key(
    data: dict = Body(...),
    _: dict = Depends(get_current_user),
) -> object:
    api_key = str(data.get("api_key", "")).strip()
    if not api_key:
        return {"valid": False, "message": "Invalid API key"}

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers={"apiKey": api_key})

        if response.status_code == 200:
            return {"valid": True}
        if response.status_code == 403:
            return JSONResponse(
                status_code=403,
                content={"valid": False, "message": "Invalid API key"},
            )
        return {"valid": False, "message": f"NVD returned {response.status_code}"}
    except httpx.TimeoutException:
        return {"valid": False, "message": "Connection timed out"}
    except Exception as exc:
        logger.debug("NVD key verification failed: %s", exc)
        return {"valid": False, "message": "Connection failed"}
