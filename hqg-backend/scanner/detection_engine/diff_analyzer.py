from __future__ import annotations

from scanner.detection_engine.error_patterns import extract_evidence, match_sql_errors
from scanner.detection_engine.models import VulnerabilityFinding


# Thresholds for diff-based detection
STATUS_CODE_CHANGE_INTERESTING = {500, 503, 403, 200}
BODY_LENGTH_DIFF_THRESHOLD = 500  # bytes


def analyze_diff(
    endpoint: str,
    payload: str,
    vulnerability_type: str,
    baseline_code: int | None,
    baseline_length: int,
    injected_code: int | None,
    injected_length: int,
    injected_body: str,
) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []

    if baseline_code is None or injected_code is None:
        return findings

    status_changed = baseline_code != injected_code
    length_diff = abs(injected_length - baseline_length)
    sql_match = match_sql_errors(injected_body)

    # Only flag meaningful divergence from baseline
    if not (status_changed or length_diff > BODY_LENGTH_DIFF_THRESHOLD or sql_match):
        return findings

    vtype = vulnerability_type.lower()

    # Status code shifted into server-error range for an injection-type probe
    if (
        vtype in {"sqli", "cmdi", "lfi", "path_traversal"}
        and injected_code in {500, 503}
        and baseline_code not in {500, 503}
    ):
        evidence = extract_evidence(sql_match, injected_body) if sql_match else ""
        findings.append(
            VulnerabilityFinding(
                endpoint=endpoint,
                payload=payload,
                vulnerability_type=vtype,
                confidence="Medium",
                detection_method="diff",
                evidence=evidence,
            )
        )

    # Significant body growth on an XSS or SSRF probe can indicate reflection/leak
    if (
        vtype in {"xss", "ssrf"}
        and length_diff > BODY_LENGTH_DIFF_THRESHOLD
        and not status_changed
    ):
        findings.append(
            VulnerabilityFinding(
                endpoint=endpoint,
                payload=payload,
                vulnerability_type=vtype,
                confidence="Low",
                detection_method="diff",
            )
        )

    return findings
