from __future__ import annotations

import html
import urllib.parse

from scanner.detection_engine.error_patterns import (
    CMDI_SKIP_RESPONSE_CODES,
    extract_evidence,
    is_ssrf_payload,
    match_cmdi_confirmed,
    match_cmdi_possible,
    match_info_disclosure,
    match_lfi_patterns,
    match_sql_errors,
    match_ssrf_patterns,
    payload_matches_cmdi_output,
)
from scanner.detection_engine.models import VulnerabilityFinding


# XSS markers — only used for partial reflection detection.
# Each marker is checked ONLY when it also appears in the injected payload.
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
    "<details",
    # NOTE: "<body" removed — every HTML page has <body>
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


# ---------------------------------------------------------------------------
# XSS detection with baseline comparison and HTML context analysis
# ---------------------------------------------------------------------------

def _get_html_context(body: str, position: int) -> str:
    """Determine what HTML context the given position is in."""
    before = body[max(0, position - 500):position]

    # Inside HTML comment?
    last_comment_open = before.rfind("<!--")
    if last_comment_open != -1 and "-->" not in before[last_comment_open:]:
        return "html_comment"

    # Inside <script> tag?
    last_script_open = before.rfind("<script")
    last_script_close = before.rfind("</script")
    if last_script_open > last_script_close:
        return "javascript"

    # Inside <style> tag?
    last_style_open = before.rfind("<style")
    last_style_close = before.rfind("</style")
    if last_style_open > last_style_close:
        return "css"

    # Inside HTML tag attribute?
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    if last_lt > last_gt:
        tag_content = before[last_lt:]
        if "=" in tag_content:
            return "html_attribute"
        return "html_tag"

    return "html_text"


def _check_xss_reflection(
    payload: str, body: str, baseline_body: str = ""
) -> tuple[bool, str, str]:
    """Return (reflected, evidence_snippet, confidence) for XSS payloads.

    Uses baseline comparison to avoid flagging content that already existed.
    Uses HTML context analysis to adjust confidence.
    """
    # Exact match — most reliable
    for variant_body in [body, html.unescape(body), urllib.parse.unquote(body)]:
        if payload in variant_body:
            # Verify payload was NOT already in the baseline response
            if baseline_body and payload in baseline_body:
                continue  # Payload existed before injection — not reflected

            idx = variant_body.find(payload)
            start = max(0, idx - 60)
            end = min(len(variant_body), idx + len(payload) + 60)
            snippet = variant_body[start:end]

            # Determine HTML context for confidence
            context = _get_html_context(variant_body, idx)
            if context == "html_comment":
                continue  # Inside comment — not exploitable
            if context == "css":
                return True, snippet, "Low"
            return True, snippet, "High"

    # Partial marker detection — catches encoding-transformed reflection
    body_lower = body.lower()
    payload_lower = payload.lower()
    baseline_lower = baseline_body.lower() if baseline_body else ""

    for marker in _XSS_MARKERS:
        marker_lower = marker.lower()
        if marker_lower in payload_lower and marker_lower in body_lower:
            # Verify marker was NOT in baseline
            if baseline_lower and marker_lower in baseline_lower:
                continue  # Marker existed before injection

            idx = body_lower.find(marker_lower)
            start = max(0, idx - 30)
            end = min(len(body), idx + len(marker) + 100)
            return True, body[start:end], "Medium"

    return False, "", ""


# ---------------------------------------------------------------------------
# Main analysis function
# ---------------------------------------------------------------------------

def analyze_response(
    endpoint: str,
    payload: str,
    vulnerability_type: str,
    response_body: str,
    response_code: int | None,
    baseline_body: str = "",
) -> list[VulnerabilityFinding]:
    """Analyze an injection response for vulnerability indicators.

    Args:
        baseline_body: The response body from a benign baseline request to
            the same endpoint.  Used for differential analysis to reduce
            false positives.
    """
    findings: list[VulnerabilityFinding] = []
    vtype = _vuln_type_from_injection(vulnerability_type)

    # 1. SQL error pattern match
    if vtype == "sqli":
        m = match_sql_errors(response_body)
        if m:
            # Verify SQL error is NOT present in baseline (some pages always show SQL)
            if not (baseline_body and match_sql_errors(baseline_body)):
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

    # 2. Reflected payload (XSS) — with baseline comparison and context
    if vtype == "xss":
        reflected, evidence, confidence = _check_xss_reflection(
            payload, response_body, baseline_body
        )
        if reflected and confidence:
            findings.append(
                VulnerabilityFinding(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type="xss",
                    confidence=confidence,
                    detection_method="reflection",
                    evidence=evidence[:300],
                )
            )

    # 3. SSRF — validate that payload is actually an internal URL
    if vtype == "ssrf":
        if is_ssrf_payload(payload):
            m = match_ssrf_patterns(response_body)
            if m:
                # Verify pattern not in baseline
                if not (baseline_body and match_ssrf_patterns(baseline_body)):
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

    # 4. Command injection — tiered detection with response code filtering
    if vtype == "cmdi":
        # Skip error pages entirely — they often contain shell-like text
        if response_code not in CMDI_SKIP_RESPONSE_CODES:
            # Try Tier 1 (confirmed) first
            m = match_cmdi_confirmed(response_body)
            if m:
                # Verify NOT in baseline
                if not (baseline_body and match_cmdi_confirmed(baseline_body)):
                    # Verify payload logically matches output
                    if payload_matches_cmdi_output(payload, m.group()):
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

            # Try Tier 2 (possible) only if Tier 1 didn't match
            if not findings or all(f.vulnerability_type != "cmdi" for f in findings):
                m = match_cmdi_possible(response_body)
                if m:
                    if not (baseline_body and match_cmdi_possible(baseline_body)):
                        if payload_matches_cmdi_output(payload, m.group()):
                            findings.append(
                                VulnerabilityFinding(
                                    endpoint=endpoint,
                                    payload=payload,
                                    vulnerability_type="cmdi",
                                    confidence="Medium",
                                    detection_method="error_pattern",
                                    evidence=extract_evidence(m, response_body),
                                )
                            )

    # 5. LFI / Path traversal — file content in response
    if vtype in {"lfi", "path_traversal"}:
        m = match_lfi_patterns(response_body)
        if m:
            # Verify NOT in baseline
            if not (baseline_body and match_lfi_patterns(baseline_body)):
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

    # 6. Information disclosure — with negative pattern filtering
    if vtype == "info_disclosure" or (response_code is not None and response_code >= 500):
        m = match_info_disclosure(response_body)  # Already filters CSRF tokens
        if m:
            # Verify NOT in baseline
            if not (baseline_body and match_info_disclosure(baseline_body)):
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
