from __future__ import annotations

import asyncio
from collections import defaultdict

import httpx

from backend.celery_app import celery_app
from scanner.detection_engine.diff_analyzer import analyze_diff
from scanner.detection_engine.models import VulnerabilityFinding
from scanner.detection_engine.response_analyzer import analyze_response
from scanner.detection_engine.time_analyzer import analyze_timing


async def _fetch_baseline(
    client: httpx.AsyncClient, endpoint: str
) -> tuple[int | None, int, float, str]:
    """Send a benign GET request and return (status, length, time, body)."""
    import time

    from scanner.crawler.url_normalizer import normalize_url

    url = normalize_url(endpoint)
    if not url:
        return None, 0, 0.0, ""

    start = time.perf_counter()
    try:
        response = await client.get(url)
        elapsed = time.perf_counter() - start
        body = response.text
        return response.status_code, len(response.content), round(elapsed, 4), body
    except Exception:
        elapsed = time.perf_counter() - start
        return None, 0, round(elapsed, 4), ""


def _filter_low_quality_findings(
    findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    """Post-detection filter to remove near-certain false positives.

    Applied after all analyzers run but before findings are returned.
    """
    filtered: list[VulnerabilityFinding] = []
    for f in findings:
        # Rule 1: CmdI on error pages → reject
        if f.vulnerability_type in ("cmdi", "time_based_cmdi"):
            ev_lower = f.evidence.lower()
            if "not found" in ev_lower and "404" in ev_lower:
                continue

        # Rule 2: Info disclosure that is just a CSRF token → reject
        if f.vulnerability_type == "info_disclosure":
            ev_lower = f.evidence.lower()
            if "csrf" in ev_lower or "user_token" in ev_lower:
                continue

        # Rule 3: XSS on non-HTML response → downgrade confidence
        if f.vulnerability_type == "xss" and f.detection_method == "reflection":
            ev_lower = f.evidence.lower()
            # If evidence doesn't look like it came from an HTML page, downgrade
            if ev_lower and not any(
                tag in ev_lower for tag in ["<html", "<body", "<!doctype", "<div", "<p ", "<form"]
            ):
                # Could be JSON/text API response — XSS is much less exploitable
                if f.confidence == "High":
                    f.confidence = "Medium"
                elif f.confidence == "Medium":
                    f.confidence = "Low"

        filtered.append(f)

    return filtered


def _cross_validate_findings(
    findings: list[VulnerabilityFinding],
) -> list[VulnerabilityFinding]:
    """Cross-validate findings: boost confidence when multiple detection methods agree."""
    # Build a map of (endpoint, vuln_type_family) → list of detection methods
    from collections import Counter

    vuln_family_methods: dict[tuple[str, str], Counter[str]] = defaultdict(Counter)
    for f in findings:
        # Normalize vuln type family (time_based_sqli → sqli)
        family = f.vulnerability_type.replace("time_based_", "")
        vuln_family_methods[(f.endpoint, family)][f.detection_method] += 1

    # Boost confidence when multiple independent methods detected the same vuln
    for f in findings:
        family = f.vulnerability_type.replace("time_based_", "")
        methods = vuln_family_methods.get((f.endpoint, family))
        if methods and len(methods) >= 2:
            # Multiple detection methods agree — boost Low→Medium, Medium→High
            if f.confidence == "Low":
                f.confidence = "Medium"
            elif f.confidence == "Medium":
                f.confidence = "High"

    return findings


async def _detect_async(
    injection_results: list[dict[str, object]],
    detection_config: dict | None = None,
) -> list[VulnerabilityFinding]:
    _cfg = detection_config or {}
    _skip_timing = bool(_cfg.get("skip_timing", False))
    _skip_diff = bool(_cfg.get("skip_diff", False))

    # Group results by endpoint so we can compute a shared baseline per endpoint
    by_endpoint: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in injection_results:
        by_endpoint[str(item.get("endpoint", ""))].append(item)

    all_findings: list[VulnerabilityFinding] = []

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(8.0),
        verify=False,
    ) as client:
        # Fetch baselines for every unique endpoint concurrently
        endpoints = list(by_endpoint.keys())
        baseline_tasks = [_fetch_baseline(client, ep) for ep in endpoints]
        baselines_raw = await asyncio.gather(*baseline_tasks, return_exceptions=True)

    baselines: dict[str, tuple[int | None, int, float, str]] = {}
    for ep, result in zip(endpoints, baselines_raw):
        if isinstance(result, tuple):
            baselines[ep] = result
        else:
            baselines[ep] = (None, 0, 0.0, "")

    # Deduplicate findings by (endpoint, vulnerability_type, detection_method)
    seen: set[tuple[str, str, str]] = set()

    for endpoint, results in by_endpoint.items():
        baseline_code, baseline_length, baseline_time, baseline_body = baselines.get(
            endpoint, (None, 0, 0.0, "")
        )

        for item in results:
            payload = str(item.get("payload", ""))
            vuln_type = str(item.get("vulnerability_type", ""))
            body = str(item.get("response_body", ""))
            code = item.get("response_code")
            response_code = int(code) if code is not None else None
            response_length = int(item.get("response_length", 0))
            response_time = float(item.get("response_time", 0.0))
            parameter_name = str(item.get("parameter", ""))
            http_method = str(item.get("http_method", "GET"))

            # Skip responses that carry no exploitable signal:
            # - Error / loop / rate-limit codes from the target
            # - Redirects (3xx) — not meaningful for vuln detection
            # - Skipped endpoints (injector sets response_code=None with skip error)
            # - Empty / tiny response bodies
            _error = str(item.get("error", ""))
            if "endpoint_skipped" in _error:
                continue
            if response_code in (
                None, 0,
                301, 302, 303, 307, 308,   # redirects
                400, 403, 405, 406,         # client-side blocks
                429,                         # rate-limited
                500, 502, 503, 504, 508,    # server errors / loop detected
            ):
                continue
            if len(body) < 10:
                continue

            # Response analyzer: error patterns, reflection, artifacts
            # NOW with baseline_body for differential analysis
            for finding in analyze_response(
                endpoint, payload, vuln_type, body, response_code,
                baseline_body=baseline_body,
            ):
                finding.parameter = parameter_name
                finding.http_method = http_method
                key = (finding.endpoint, finding.vulnerability_type, finding.detection_method)
                if key not in seen:
                    seen.add(key)
                    all_findings.append(finding)

            # Diff analyzer: baseline vs injected
            if not _skip_diff:
                for finding in analyze_diff(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type=vuln_type,
                    baseline_code=baseline_code,
                    baseline_length=baseline_length,
                    injected_code=response_code,
                    injected_length=response_length,
                    injected_body=body,
                ):
                    finding.parameter = parameter_name
                    finding.http_method = http_method
                    key = (finding.endpoint, finding.vulnerability_type, finding.detection_method)
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(finding)

            # Time-based analyzer
            if not _skip_timing:
                time_finding = analyze_timing(
                    endpoint=endpoint,
                    payload=payload,
                    vulnerability_type=vuln_type,
                    response_time=response_time,
                    baseline_time=baseline_time,
                )
                if time_finding:
                    time_finding.parameter = parameter_name
                    time_finding.http_method = http_method
                    key = (time_finding.endpoint, time_finding.vulnerability_type, time_finding.detection_method)
                    if key not in seen:
                        seen.add(key)
                        all_findings.append(time_finding)

    # Post-processing: cross-validate then filter low quality
    all_findings = _cross_validate_findings(all_findings)
    all_findings = _filter_low_quality_findings(all_findings)

    return all_findings


@celery_app.task(name="scanner.detection_engine.detect_vulnerabilities")
def detect_vulnerabilities(
    scan_id: str,
    injection_results: list[dict[str, object]],
    detection_config: dict | None = None,
) -> dict[str, object]:
    findings = asyncio.run(_detect_async(injection_results, detection_config=detection_config))

    return {
        "scan_id": scan_id,
        "total_analyzed": len(injection_results),
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
