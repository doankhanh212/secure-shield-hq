"""Dynamic OWASP Top 10 2021 mapping engine.

Maps vulnerability findings to OWASP categories using a multi-layer
prioritized strategy:

    Layer 1 — CVE-based:   CVE → CWE (from NVD) → OWASP   (highest accuracy)
    Layer 2 — CWE-based:   finding CWE → OWASP
    Layer 3 — Rule-based:  heuristic rules on finding metadata
    Layer 4 — Fallback:    vulnerability_type → OWASP      (last resort)

Each finding is annotated with:
    owasp_category  — e.g. "A03:2021 Injection"
    owasp_source    — "cve" | "cwe" | "rule" | "fallback"

No hardcoded OWASP assignments exist outside this module.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# CWE → OWASP Top 10 2021 mapping table
# Source: https://cwe.mitre.org/data/definitions/1344.html (OWASP 2021 view)
# ═══════════════════════════════════════════════════════════════════════════

CWE_TO_OWASP: dict[str, str] = {
    # ── A01:2021 Broken Access Control ───────────────────────────────────
    "CWE-22":   "A01:2021 Broken Access Control",
    "CWE-23":   "A01:2021 Broken Access Control",
    "CWE-35":   "A01:2021 Broken Access Control",
    "CWE-59":   "A01:2021 Broken Access Control",
    "CWE-200":  "A01:2021 Broken Access Control",
    "CWE-201":  "A01:2021 Broken Access Control",
    "CWE-219":  "A01:2021 Broken Access Control",
    "CWE-264":  "A01:2021 Broken Access Control",
    "CWE-275":  "A01:2021 Broken Access Control",
    "CWE-276":  "A01:2021 Broken Access Control",
    "CWE-284":  "A01:2021 Broken Access Control",
    "CWE-285":  "A01:2021 Broken Access Control",
    "CWE-352":  "A01:2021 Broken Access Control",
    "CWE-359":  "A01:2021 Broken Access Control",
    "CWE-377":  "A01:2021 Broken Access Control",
    "CWE-402":  "A01:2021 Broken Access Control",
    "CWE-425":  "A01:2021 Broken Access Control",
    "CWE-441":  "A01:2021 Broken Access Control",
    "CWE-497":  "A01:2021 Broken Access Control",
    "CWE-538":  "A01:2021 Broken Access Control",
    "CWE-540":  "A01:2021 Broken Access Control",
    "CWE-548":  "A01:2021 Broken Access Control",
    "CWE-552":  "A01:2021 Broken Access Control",
    "CWE-566":  "A01:2021 Broken Access Control",
    "CWE-601":  "A01:2021 Broken Access Control",
    "CWE-639":  "A01:2021 Broken Access Control",
    "CWE-651":  "A01:2021 Broken Access Control",
    "CWE-668":  "A01:2021 Broken Access Control",
    "CWE-706":  "A01:2021 Broken Access Control",
    "CWE-862":  "A01:2021 Broken Access Control",
    "CWE-863":  "A01:2021 Broken Access Control",
    "CWE-913":  "A01:2021 Broken Access Control",
    "CWE-922":  "A01:2021 Broken Access Control",
    "CWE-1275":  "A01:2021 Broken Access Control",

    # ── A02:2021 Cryptographic Failures ──────────────────────────────────
    "CWE-261":  "A02:2021 Cryptographic Failures",
    "CWE-296":  "A02:2021 Cryptographic Failures",
    "CWE-310":  "A02:2021 Cryptographic Failures",
    "CWE-319":  "A02:2021 Cryptographic Failures",
    "CWE-321":  "A02:2021 Cryptographic Failures",
    "CWE-322":  "A02:2021 Cryptographic Failures",
    "CWE-323":  "A02:2021 Cryptographic Failures",
    "CWE-324":  "A02:2021 Cryptographic Failures",
    "CWE-325":  "A02:2021 Cryptographic Failures",
    "CWE-326":  "A02:2021 Cryptographic Failures",
    "CWE-327":  "A02:2021 Cryptographic Failures",
    "CWE-328":  "A02:2021 Cryptographic Failures",
    "CWE-329":  "A02:2021 Cryptographic Failures",
    "CWE-330":  "A02:2021 Cryptographic Failures",
    "CWE-331":  "A02:2021 Cryptographic Failures",
    "CWE-335":  "A02:2021 Cryptographic Failures",
    "CWE-336":  "A02:2021 Cryptographic Failures",
    "CWE-337":  "A02:2021 Cryptographic Failures",
    "CWE-338":  "A02:2021 Cryptographic Failures",
    "CWE-340":  "A02:2021 Cryptographic Failures",
    "CWE-347":  "A02:2021 Cryptographic Failures",
    "CWE-523":  "A02:2021 Cryptographic Failures",
    "CWE-720":  "A02:2021 Cryptographic Failures",
    "CWE-757":  "A02:2021 Cryptographic Failures",
    "CWE-759":  "A02:2021 Cryptographic Failures",
    "CWE-760":  "A02:2021 Cryptographic Failures",
    "CWE-780":  "A02:2021 Cryptographic Failures",
    "CWE-818":  "A02:2021 Cryptographic Failures",
    "CWE-916":  "A02:2021 Cryptographic Failures",

    # ── A03:2021 Injection ───────────────────────────────────────────────
    "CWE-20":   "A03:2021 Injection",
    "CWE-74":   "A03:2021 Injection",
    "CWE-75":   "A03:2021 Injection",
    "CWE-77":   "A03:2021 Injection",
    "CWE-78":   "A03:2021 Injection",
    "CWE-79":   "A03:2021 Injection",
    "CWE-80":   "A03:2021 Injection",
    "CWE-83":   "A03:2021 Injection",
    "CWE-87":   "A03:2021 Injection",
    "CWE-88":   "A03:2021 Injection",
    "CWE-89":   "A03:2021 Injection",
    "CWE-90":   "A03:2021 Injection",
    "CWE-91":   "A03:2021 Injection",
    "CWE-93":   "A03:2021 Injection",
    "CWE-94":   "A03:2021 Injection",
    "CWE-95":   "A03:2021 Injection",
    "CWE-96":   "A03:2021 Injection",
    "CWE-97":   "A03:2021 Injection",
    "CWE-98":   "A03:2021 Injection",
    "CWE-99":   "A03:2021 Injection",
    "CWE-100":  "A03:2021 Injection",
    "CWE-113":  "A03:2021 Injection",
    "CWE-116":  "A03:2021 Injection",
    "CWE-138":  "A03:2021 Injection",
    "CWE-184":  "A03:2021 Injection",
    "CWE-470":  "A03:2021 Injection",
    "CWE-471":  "A03:2021 Injection",
    "CWE-564":  "A03:2021 Injection",
    "CWE-610":  "A03:2021 Injection",
    "CWE-643":  "A03:2021 Injection",
    "CWE-644":  "A03:2021 Injection",
    "CWE-652":  "A03:2021 Injection",
    "CWE-917":  "A03:2021 Injection",

    # ── A04:2021 Insecure Design ─────────────────────────────────────────
    "CWE-209":  "A04:2021 Insecure Design",
    "CWE-256":  "A04:2021 Insecure Design",
    "CWE-501":  "A04:2021 Insecure Design",
    "CWE-522":  "A04:2021 Insecure Design",
    "CWE-525":  "A04:2021 Insecure Design",
    "CWE-539":  "A04:2021 Insecure Design",
    "CWE-579":  "A04:2021 Insecure Design",
    "CWE-598":  "A04:2021 Insecure Design",
    "CWE-602":  "A04:2021 Insecure Design",
    "CWE-642":  "A04:2021 Insecure Design",
    "CWE-646":  "A04:2021 Insecure Design",
    "CWE-650":  "A04:2021 Insecure Design",
    "CWE-653":  "A04:2021 Insecure Design",
    "CWE-656":  "A04:2021 Insecure Design",
    "CWE-657":  "A04:2021 Insecure Design",
    "CWE-799":  "A04:2021 Insecure Design",

    # ── A05:2021 Security Misconfiguration ───────────────────────────────
    "CWE-2":    "A05:2021 Security Misconfiguration",
    "CWE-11":   "A05:2021 Security Misconfiguration",
    "CWE-13":   "A05:2021 Security Misconfiguration",
    "CWE-15":   "A05:2021 Security Misconfiguration",
    "CWE-16":   "A05:2021 Security Misconfiguration",
    "CWE-260":  "A05:2021 Security Misconfiguration",
    "CWE-315":  "A05:2021 Security Misconfiguration",
    "CWE-520":  "A05:2021 Security Misconfiguration",
    "CWE-526":  "A05:2021 Security Misconfiguration",
    "CWE-537":  "A05:2021 Security Misconfiguration",
    "CWE-541":  "A05:2021 Security Misconfiguration",
    "CWE-547":  "A05:2021 Security Misconfiguration",
    "CWE-611":  "A05:2021 Security Misconfiguration",
    "CWE-614":  "A05:2021 Security Misconfiguration",
    "CWE-756":  "A05:2021 Security Misconfiguration",
    "CWE-776":  "A05:2021 Security Misconfiguration",
    "CWE-942":  "A05:2021 Security Misconfiguration",
    "CWE-1004":  "A05:2021 Security Misconfiguration",
    "CWE-1032":  "A05:2021 Security Misconfiguration",

    # ── A06:2021 Vulnerable and Outdated Components ──────────────────────
    "CWE-937":  "A06:2021 Vulnerable and Outdated Components",
    "CWE-1035": "A06:2021 Vulnerable and Outdated Components",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",

    # ── A07:2021 Identification and Authentication Failures ──────────────
    "CWE-255":  "A07:2021 Identification and Authentication Failures",
    "CWE-259":  "A07:2021 Identification and Authentication Failures",
    "CWE-287":  "A07:2021 Identification and Authentication Failures",
    "CWE-288":  "A07:2021 Identification and Authentication Failures",
    "CWE-290":  "A07:2021 Identification and Authentication Failures",
    "CWE-294":  "A07:2021 Identification and Authentication Failures",
    "CWE-295":  "A07:2021 Identification and Authentication Failures",
    "CWE-297":  "A07:2021 Identification and Authentication Failures",
    "CWE-300":  "A07:2021 Identification and Authentication Failures",
    "CWE-302":  "A07:2021 Identification and Authentication Failures",
    "CWE-304":  "A07:2021 Identification and Authentication Failures",
    "CWE-306":  "A07:2021 Identification and Authentication Failures",
    "CWE-307":  "A07:2021 Identification and Authentication Failures",
    "CWE-346":  "A07:2021 Identification and Authentication Failures",
    "CWE-384":  "A07:2021 Identification and Authentication Failures",
    "CWE-521":  "A07:2021 Identification and Authentication Failures",
    "CWE-613":  "A07:2021 Identification and Authentication Failures",
    "CWE-620":  "A07:2021 Identification and Authentication Failures",
    "CWE-640":  "A07:2021 Identification and Authentication Failures",
    "CWE-798":  "A07:2021 Identification and Authentication Failures",
    "CWE-940":  "A07:2021 Identification and Authentication Failures",
    "CWE-1216": "A07:2021 Identification and Authentication Failures",

    # ── A08:2021 Software and Data Integrity Failures ────────────────────
    "CWE-345":  "A08:2021 Software and Data Integrity Failures",
    "CWE-353":  "A08:2021 Software and Data Integrity Failures",
    "CWE-426":  "A08:2021 Software and Data Integrity Failures",
    "CWE-494":  "A08:2021 Software and Data Integrity Failures",
    "CWE-502":  "A08:2021 Software and Data Integrity Failures",
    "CWE-565":  "A08:2021 Software and Data Integrity Failures",
    "CWE-784":  "A08:2021 Software and Data Integrity Failures",
    "CWE-829":  "A08:2021 Software and Data Integrity Failures",
    "CWE-830":  "A08:2021 Software and Data Integrity Failures",
    "CWE-915":  "A08:2021 Software and Data Integrity Failures",

    # ── A09:2021 Security Logging and Monitoring Failures ────────────────
    "CWE-117":  "A09:2021 Security Logging and Monitoring Failures",
    "CWE-223":  "A09:2021 Security Logging and Monitoring Failures",
    "CWE-532":  "A09:2021 Security Logging and Monitoring Failures",
    "CWE-778":  "A09:2021 Security Logging and Monitoring Failures",

    # ── A10:2021 Server-Side Request Forgery ─────────────────────────────
    "CWE-918":  "A10:2021 Server-Side Request Forgery",
}


# ═══════════════════════════════════════════════════════════════════════════
# Layer 3 — Rule-based mapping (heuristic patterns)
# ═══════════════════════════════════════════════════════════════════════════

_RULE_MAP: list[tuple[str, str]] = [
    # A01 — Broken Access Control
    ("unauthorized", "A01:2021 Broken Access Control"),
    ("missing auth", "A01:2021 Broken Access Control"),
    ("idor", "A01:2021 Broken Access Control"),
    ("directory listing", "A01:2021 Broken Access Control"),
    ("directory traversal", "A01:2021 Broken Access Control"),
    ("path_traversal", "A01:2021 Broken Access Control"),
    ("open_redirect", "A01:2021 Broken Access Control"),

    # A02 — Cryptographic Failures
    ("http_no_tls", "A02:2021 Cryptographic Failures"),
    ("weak_crypto", "A02:2021 Cryptographic Failures"),
    ("cleartext", "A02:2021 Cryptographic Failures"),
    ("missing_hsts", "A02:2021 Cryptographic Failures"),

    # A03 — Injection
    ("sqli", "A03:2021 Injection"),
    ("time_based_sqli", "A03:2021 Injection"),
    ("xss", "A03:2021 Injection"),
    ("xss_reflected", "A03:2021 Injection"),
    ("xss_stored", "A03:2021 Injection"),
    ("cmdi", "A03:2021 Injection"),
    ("time_based_cmdi", "A03:2021 Injection"),
    ("lfi", "A03:2021 Injection"),
    ("ssti", "A03:2021 Injection"),
    ("xxe", "A03:2021 Injection"),
    ("ldap_injection", "A03:2021 Injection"),
    ("header_injection", "A03:2021 Injection"),

    # A05 — Security Misconfiguration
    ("info_disclosure", "A05:2021 Security Misconfiguration"),
    ("exposed_config", "A05:2021 Security Misconfiguration"),
    ("default_credentials", "A05:2021 Security Misconfiguration"),
    ("debug_enabled", "A05:2021 Security Misconfiguration"),
    ("missing_security_headers", "A05:2021 Security Misconfiguration"),
    ("cors_misconfiguration", "A05:2021 Security Misconfiguration"),

    # A06 — Vulnerable Components (presence of CVE → handled in Layer 1)
    ("outdated_component", "A06:2021 Vulnerable and Outdated Components"),
    ("known_cve", "A06:2021 Vulnerable and Outdated Components"),

    # A07 — Authentication Failures
    ("brute_force", "A07:2021 Identification and Authentication Failures"),
    ("weak_password", "A07:2021 Identification and Authentication Failures"),
    ("session_fixation", "A07:2021 Identification and Authentication Failures"),
    ("credential_exposure", "A07:2021 Identification and Authentication Failures"),

    # A08 — Software and Data Integrity Failures
    ("deserialization", "A08:2021 Software and Data Integrity Failures"),
    ("insecure_deserialization", "A08:2021 Software and Data Integrity Failures"),

    # A09 — Logging Failures
    ("missing_logging", "A09:2021 Security Logging and Monitoring Failures"),
    ("log_injection", "A09:2021 Security Logging and Monitoring Failures"),

    # A10 — SSRF
    ("ssrf", "A10:2021 Server-Side Request Forgery"),
]


# ═══════════════════════════════════════════════════════════════════════════
# Layer 4 — Absolute last-resort fallback
# Only used when no CWE, no CVE, no rule match.
# ═══════════════════════════════════════════════════════════════════════════

_FALLBACK_MAP: dict[str, str] = {
    "sqli":             "A03:2021 Injection",
    "time_based_sqli":  "A03:2021 Injection",
    "xss":              "A03:2021 Injection",
    "xss_reflected":    "A03:2021 Injection",
    "xss_stored":       "A03:2021 Injection",
    "cmdi":             "A03:2021 Injection",
    "time_based_cmdi":  "A03:2021 Injection",
    "lfi":              "A03:2021 Injection",
    "path_traversal":   "A01:2021 Broken Access Control",
    "ssrf":             "A10:2021 Server-Side Request Forgery",
    "info_disclosure":  "A05:2021 Security Misconfiguration",
    "open_redirect":    "A01:2021 Broken Access Control",
}


# ═══════════════════════════════════════════════════════════════════════════
# Public API
# ═══════════════════════════════════════════════════════════════════════════


def _normalise_cwe(raw: str) -> Optional[str]:
    """Normalise CWE strings to 'CWE-NNN' format."""
    if not raw:
        return None
    m = re.search(r"(\d+)", str(raw))
    if m:
        return f"CWE-{m.group(1)}"
    return None


def map_owasp_from_cve(cve_data: dict) -> Optional[tuple[str, str]]:
    """Layer 1: CVE → CWE (from NVD weaknesses) → OWASP.

    *cve_data* may be a CVE record dict containing 'weaknesses' or 'cwe'
    as returned by NVD API 2.0.

    Returns (owasp_category, "cve") or None.
    """
    # NVD 2.0 format: cve.weaknesses[].description[].value = "CWE-NNN"
    weaknesses = cve_data.get("weaknesses", [])
    for w in weaknesses:
        for desc in w.get("description", []):
            cwe_raw = desc.get("value", "")
            cwe_id = _normalise_cwe(cwe_raw)
            if cwe_id and cwe_id in CWE_TO_OWASP:
                return CWE_TO_OWASP[cwe_id], "cve"

    # Fallback: direct cwe field on the record
    cwe_field = cve_data.get("cwe") or cve_data.get("cwe_id") or ""
    cwe_id = _normalise_cwe(str(cwe_field))
    if cwe_id and cwe_id in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe_id], "cve"

    return None


def map_owasp_from_cwe(cwe_raw: str) -> Optional[tuple[str, str]]:
    """Layer 2: CWE → OWASP.

    Returns (owasp_category, "cwe") or None.
    """
    cwe_id = _normalise_cwe(cwe_raw)
    if cwe_id and cwe_id in CWE_TO_OWASP:
        return CWE_TO_OWASP[cwe_id], "cwe"
    return None


def map_owasp_from_rules(
    vulnerability_type: str,
    detection_method: str = "",
    evidence: str = "",
) -> Optional[tuple[str, str]]:
    """Layer 3: Heuristic rule matching on finding metadata.

    Returns (owasp_category, "rule") or None.
    """
    # Check vuln type first (most specific)
    vtype = vulnerability_type.lower()
    for pattern, owasp in _RULE_MAP:
        if pattern == vtype:
            return owasp, "rule"

    # Check in evidence / detection_method strings
    combined = f"{vtype} {detection_method} {evidence}".lower()
    for pattern, owasp in _RULE_MAP:
        if pattern in combined:
            return owasp, "rule"

    return None


def map_owasp_fallback(vulnerability_type: str) -> tuple[str, str]:
    """Layer 4: Direct type → OWASP fallback.

    Always returns a value (never None).
    """
    vtype = vulnerability_type.lower()
    category = _FALLBACK_MAP.get(vtype, "A03:2021 Injection")
    return category, "fallback"


def classify_finding(
    finding: dict[str, object],
    cve_records: Optional[list[dict]] = None,
) -> tuple[str, str]:
    """Classify a single finding through the 4-layer OWASP mapping.

    Parameters:
        finding      — a finding dict with keys like vulnerability_type,
                        cwe, cwe_id, related_cve_ids, etc.
        cve_records  — optional list of CVE dicts (from NVD) to resolve
                        CVE → CWE → OWASP in Layer 1.

    Returns:
        (owasp_category, owasp_source) tuple.
    """
    vtype = str(finding.get("vulnerability_type", ""))

    # ── Layer 1: CVE-based ───────────────────────────────────────────────
    if cve_records:
        related_ids = finding.get("related_cve_ids") or []
        if isinstance(related_ids, str):
            related_ids = [related_ids]
        cve_map = {str(c.get("cve_id", "")): c for c in cve_records if c.get("cve_id")}

        for cve_id in related_ids:
            cve_data = cve_map.get(cve_id)
            if cve_data:
                result = map_owasp_from_cve(cve_data)
                if result:
                    return result

    # ── Layer 2: CWE-based ───────────────────────────────────────────────
    cwe_raw = str(finding.get("cwe_id") or finding.get("cwe") or "")
    if cwe_raw:
        result = map_owasp_from_cwe(cwe_raw)
        if result:
            return result

    # ── Layer 3: Rule-based ──────────────────────────────────────────────
    result = map_owasp_from_rules(
        vulnerability_type=vtype,
        detection_method=str(finding.get("detection_method", "")),
        evidence=str(finding.get("evidence", "")),
    )
    if result:
        return result

    # ── Layer 4: Fallback ────────────────────────────────────────────────
    return map_owasp_fallback(vtype)


def enrich_findings_owasp(
    findings: list[dict[str, object]],
    cve_records: Optional[list[dict]] = None,
) -> list[dict[str, object]]:
    """Classify all findings and annotate each with owasp_category + owasp_source.

    Returns a new list (findings are shallow-copied, originals are not mutated).
    """
    enriched: list[dict[str, object]] = []
    for f in findings:
        fc = dict(f)
        owasp_cat, owasp_src = classify_finding(fc, cve_records=cve_records)
        fc["owasp_category"] = owasp_cat
        fc["owasp_source"] = owasp_src
        enriched.append(fc)

    # Log distribution summary
    dist: dict[str, int] = {}
    for fc in enriched:
        cat = str(fc.get("owasp_category", "Unknown"))
        dist[cat] = dist.get(cat, 0) + 1
    logger.info("OWASP classification: %s", dist)

    return enriched
