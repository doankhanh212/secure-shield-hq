from __future__ import annotations

from scanner.detection_engine.models import VulnerabilityFinding

# Minimum response time in seconds to consider time-based injection
TIME_THRESHOLD_SECONDS = 5.0


def analyze_timing(
    endpoint: str,
    payload: str,
    vulnerability_type: str,
    response_time: float,
    baseline_time: float = 0.0,
) -> VulnerabilityFinding | None:
    vtype = vulnerability_type.lower()

    if vtype not in {"sqli", "cmdi"}:
        return None

    # Absolute threshold: response took too long
    absolute_hit = response_time >= TIME_THRESHOLD_SECONDS

    # Relative threshold: noticeably slower than baseline (at least 4× and >3 s)
    relative_hit = (
        baseline_time > 0
        and response_time >= 3.0
        and response_time >= baseline_time * 4
    )

    if not (absolute_hit or relative_hit):
        return None

    time_vtype = "time_based_sqli" if vtype == "sqli" else "time_based_cmdi"
    confidence = "High" if absolute_hit else "Medium"
    evidence = (
        f"Response time: {response_time:.2f}s | "
        f"Baseline: {baseline_time:.2f}s | "
        f"Delta: {response_time - baseline_time:.2f}s"
    )

    return VulnerabilityFinding(
        endpoint=endpoint,
        payload=payload,
        vulnerability_type=time_vtype,
        confidence=confidence,
        detection_method="time_based",
        evidence=evidence,
    )
