from __future__ import annotations

import json
import os

import httpx
from fastapi import APIRouter, Body
from fastapi.concurrency import run_in_threadpool

import redis as _redis

from backend.config import get_settings

router = APIRouter(prefix="/settings", tags=["settings"])


def _r() -> _redis.Redis:
    return _redis.from_url(get_settings().redis_url, decode_responses=True)


_REDIS_SETTINGS_KEY = "hqg:settings"

# Keys that are persisted to Redis (non-sensitive)
_PERSIST_KEYS = {
    "platform_name",
    "language",
    "daily_scans",
    "ai_analysis",
    "distributed_scanning",
    "email_notifications",
    "scan_workers",
}


def _load_persisted() -> dict[str, object]:
    try:
        r = _r()
        raw = r.get(_REDIS_SETTINGS_KEY)
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _save_persisted(data: dict[str, object]) -> None:
    try:
        r = _r()
        r.set(_REDIS_SETTINGS_KEY, json.dumps(data))
    except Exception:
        pass


@router.get("", summary="Get current platform settings")
async def get_platform_settings() -> dict[str, object]:
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
async def update_platform_settings(data: dict = Body(...)) -> dict[str, object]:
    settings = get_settings()

    # Handle NVD API key — stored in environment, not Redis
    if "nvd_api_key" in data and data["nvd_api_key"]:
        key_value = str(data["nvd_api_key"]).strip()
        os.environ["NVD_API_KEY"] = key_value
        # Update the cached settings object
        object.__setattr__(settings, "nvd_api_key", key_value)

    # Persist non-sensitive settings to Redis
    persisted = await run_in_threadpool(_load_persisted)
    for k in _PERSIST_KEYS:
        if k in data:
            persisted[k] = data[k]
    await run_in_threadpool(_save_persisted, persisted)

    return {
        "status": "ok",
        "nvd_api_key_configured": bool(
            settings.nvd_api_key or os.environ.get("NVD_API_KEY")
        ),
    }


# ── POST /settings/verify-nvd-key ────────────────────────────────────────────

@router.post("/verify-nvd-key", summary="Verify an NVD API key by sending a live probe")
async def verify_nvd_key(data: dict = Body(...)) -> dict[str, object]:
    """
    Send a minimal probe to the NVD REST API and confirm the provided key is valid.
    Returns ``{ "valid": true|false, "message": "..." }``.
    """
    api_key = str(data.get("api_key", "")).strip()
    if not api_key:
        return {"valid": False, "message": "API key không được để trống"}

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url, headers={"apiKey": api_key})

        if response.status_code == 200:
            return {"valid": True, "message": "Kết nối NVD thành công"}
        if response.status_code == 403:
            return {"valid": False, "message": "API key không hợp lệ (403 Forbidden)"}
        return {
            "valid": False,
            "message": f"NVD trả về lỗi {response.status_code}",
        }
    except httpx.TimeoutException:
        return {"valid": False, "message": "Không thể kết nối đến NVD (timeout 10s)"}
    except Exception as exc:
        return {"valid": False, "message": f"Lỗi kết nối: {exc}"}
