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
            "timeout_seconds": 7.0,
            "allow_generic_fallback": False,
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

    # ------------------------------------------------------------------
    # DEEP — rộng hơn standard, cho phép fallback và payload nhiều hơn
    # ------------------------------------------------------------------
    "deep": {
        "crawler": {
            "max_pages": 500,
            "max_depth": 8,
            "follow_external": False,
            "timeout_per_page": 15,
            "discover_hidden_params": True,
            "parse_javascript": True,
        },
        "template_engine": {
            "enabled": True,
            "categories": ["all"],
        },
        "payload_engine": {
            "enabled": True,
            "mode": "aggressive",
            "max_payloads_per_param": 25,
            "timeout_seconds": 10.0,
            "allow_generic_fallback": True,
            "include_fuzzing": True,
        },
        "detection_engine": {
            "enabled": True,
            "methods": ["error_pattern", "reflection", "time_based", "diff",
                        "boolean_blind"],
            "skip_timing": False,
            "skip_diff": False,
        },
        "security_checks": {
            "enabled": False,
        },
        "ai_analyzer": {
            "enabled": True,
            "deep_analysis": True,
        },
        "cve_intelligence": {
            "enabled": True,
            "include_epss": True,
        },
        "attack_surface": {
            "enabled": True,
        },
        "attack_path": {
            "enabled": True,
        },
        "reporting": {
            "format": "intelligence",
            "html_report": True,
        },
    },

    # ------------------------------------------------------------------
    # FULL — coverage lớn nhất, vẫn có giới hạn để tránh request explosion
    # ------------------------------------------------------------------
    "full": {
        "crawler": {
            "max_pages": 500,
            "max_depth": 8,
        },
        "template_engine": {
            "enabled": True,
            "categories": ["all"],
        },
        "payload_engine": {
            "enabled": True,
            "mode": "full",
            "max_payloads_per_param": 24,
            "timeout_seconds": 12.0,
            "allow_generic_fallback": True,
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
