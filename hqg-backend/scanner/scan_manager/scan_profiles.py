"""
HQG Scan Profiles — chi tiết cấu hình từng stage cho mỗi scan mode.

Public API
----------
SCAN_MODE_PROFILES : dict[str, dict]
    Cấu hình đầy đủ cho từng mode.

get_profile(scan_mode) -> dict
    Trả về profile dict; fallback về "standard" nếu mode không tồn tại.
"""
from __future__ import annotations

SCAN_MODE_PROFILES: dict[str, dict] = {
    # ------------------------------------------------------------------
    # QUICK — nhanh, không inject payload, dùng security_checks
    # ------------------------------------------------------------------
    "quick": {
        "crawler": {
            "max_pages": 20,
            "max_depth": 2,
        },
        "template_engine": {
            "enabled": True,
            "categories": ["misconfig", "info_disclosure"],
        },
        "payload_engine": {
            "enabled": False,
        },
        "detection_engine": {
            "enabled": True,
            "methods": ["error_pattern"],
            "skip_timing": True,
            "skip_diff": True,
        },
        "security_checks": {
            "enabled": True,
        },
        "ai_analyzer": {
            "enabled": False,
        },
        "cve_intelligence": {
            "enabled": False,
        },
        "reporting": {
            "format": "summary",
            "html_report": False,
        },
    },

    # ------------------------------------------------------------------
    # STANDARD — đầy đủ, AI analysis, CVE intelligence, HTML report
    # ------------------------------------------------------------------
    "standard": {
        "crawler": {
            "max_pages": 200,
            "max_depth": 5,
        },
        "template_engine": {
            "enabled": True,
            "categories": ["all"],
        },
        "payload_engine": {
            "enabled": True,
            "mode": "safe",
            "max_payloads_per_param": 10,
        },
        "detection_engine": {
            "enabled": True,
            "skip_timing": False,
            "skip_diff": False,
        },
        "security_checks": {
            "enabled": False,
        },
        "ai_analyzer": {
            "enabled": True,
        },
        "cve_intelligence": {
            "enabled": True,
        },
        "reporting": {
            "format": "full",
            "html_report": True,
        },
    },
}


def get_profile(scan_mode: str) -> dict:
    """
    Trả về profile dict cho *scan_mode*.
    Fallback về 'standard' nếu mode không tồn tại.
    Không raise exception.
    """
    return SCAN_MODE_PROFILES.get(scan_mode.lower(), SCAN_MODE_PROFILES["standard"])
