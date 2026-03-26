from __future__ import annotations

import html
import urllib.parse

from scanner.detection_engine.error_patterns import (
    extract_evidence,
    match_cmdi_patterns,
    match_info_disclosure,
    match_lfi_patterns,
    match_sql_errors,
    match_ssrf_patterns,
)
from scanner.detection_engine.models import VulnerabilityFinding


# XSS markers to detect partial reflection when full payload encoding differs
_XSS_MARKERS = [
    "<script",
    "onerror=",
    "onload=",
    "onfocus=",
    "ontoggle=",
    "javascript:",
    "alert(",
    "<svg",
    "<img",
    "<iframe",
    "<body",
    "<details",
]


def _vuln_type_from_injection(injection_type: str) -> str:
    mapping = {
        "sqli": "sqli",
        "xss": "xss",
        "ssrf": "ssrf",
        "cmdi": "cmdi",
        "lfi": "lfi",
        "path_traversal": "path_traversal",
    }
    return mapping.get(injection_type.lower(), injection_type.lower())


def _check_xss_reflection(payload: str, body: str) -> tuple[bool, str]:
    """Return (reflected, evidence_snippet) for XSS payloads."""
    # Try raw, HTML-decoded, and URL-decoded variants
    for variant_body in [body, html.unescape(body), urllib.parse.unquote(body)]:
        if payload in variant_body:
            idx = variant_body.find(payload)
            start = max(0, idx - 60)
            end = min(len(variant_body), idx + len(payload) + 60)
            return True, variant_body[start:end]

    # Partial marker detection — catches encoding-transformed reflection.
    # Only flag if BOTH the payload AND the response body contain this marker,
    # preventing false positives from ordinary HTML tags like <body>, <img>.
    body_lower = body.lower()
    payload_lower = payload.lower()
    for marker in _XSS_MARKERS:
        marker_lower = marker.lower()
        if marker_lower in payload_lower and marker_lower in body_lower:
            idx = body_lower.find(marker_lower)
            start = max(0, idx - 30)
            end = min(len(body), idx + len(marker) + 100)
            return True, body[start:end]

    return False, ""


def analyze_response(
    endpoint: str,
    payload: str,
    vulnerability_type: str,
    response_body: str,
    response_code: int | None,
) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    vtype = _vuln_type_from_injection(vulnerability_type)

    # 1. SQL error pattern match
    if vtype == "sqli":
        m = match_sql_errors(response_body)
        if m:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="sqli",
                    confidence="High",
                    detection_method="error_pattern",
                    evidence=extract_evidence(m, response_body),
                )
            )

    # 2. Reflected payload (XSS)
    if vtype == "xss":
        reflected, evidence = _check_xss_reflection(payload, response_body)
        if reflected:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="xss",
                    confidence="High" if payload in response_body else "Medium",
                    detection_method="reflection",
                    evidence=evidence[:300],
                )
            )

    # 3. SSRF — server tried to resolve internal resource
    if vtype == "ssrf":
        m = match_ssrf_patterns(response_body)
        if m:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="ssrf",
                    confidence="Medium",
                    detection_method="reflection",
                    evidence=extract_evidence(m, response_body),
                )
            )

    # 4. Command injection — shell output artifacts
    # Skip 404 responses: many error pages contain shell-like text (false positive)
    if vtype == "cmdi" and response_code != 404:
        m = match_cmdi_patterns(response_body)
        if m:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="cmdi",
                    confidence="High",
                    detection_method="error_pattern",
                    evidence=extract_evidence(m, response_body),
                )
            )

    # 5. LFI / Path traversal — file content in response
    if vtype in {"lfi", "path_traversal"}:
        m = match_lfi_patterns(response_body)
        if m:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type=vtype,
                    confidence="High",
                    detection_method="lfi_pattern",
                    evidence=extract_evidence(m, response_body),
                )
            )

    # 6. Information disclosure — only check when probing for it directly,
    # or when the server returns a 5xx error (stack traces, debug pages).
    # Avoids duplicate findings from pages that always show "PHP Version" in footer.
    if vtype == "info_disclosure" or (response_code is not None and response_code >= 500):
        m = match_info_disclosure(response_body)
        if m:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="info_disclosure",
                    confidence="Medium",
                    detection_method="error_pattern",
                    evidence=extract_evidence(m, response_body),
                )
            )

    return findings
