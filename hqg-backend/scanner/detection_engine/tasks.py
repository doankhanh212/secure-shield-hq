from __future__ import annotations

import asyncio
from collections import defaultdict

import httpx

from backend.celery_app import celery_app
from scanner.detection_engine.diff_analyzer import analyze_diff
from scanner.detection_engine.models import VulnerabilityFinding
from scanner.detection_engine.response_analyzer import analyze_response
from scanner.detection_engine.time_analyzer import analyze_timing


async def _fetch_baseline(client: httpx.AsyncClient, endpoint: str) -> tuple[int | None, int, float]:
    """Send a benign GET request to the endpoint and return (status, length, time)."""
    import time

    # Re-construct a safe baseline URL (strip any injected param values)
    from scanner.crawler.url_normalizer import normalize_url

    url = normalize_url(endpoint)
    if not url:
        return None, 0, 0.0

    start = time.perf_counter()
    try:
        response = await client.get(url)
        elapsed = time.perf_counter() - start
        return response.status_code, len(response.content), round(elapsed, 4)
    except Exception:
        elapsed = time.perf_counter() - start
        return None, 0, round(elapsed, 4)


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

    baselines: dict[str, tuple[int | None, int, float]] = {}
    for ep, result in zip(endpoints, baselines_raw):
        if isinstance(result, tuple):
            baselines[ep] = result
        else:
            baselines[ep] = (None, 0, 0.0)

    # Deduplicate findings by (endpoint, vulnerability_type, detection_method)
    seen: set[tuple[str, str, str]] = set()

    for endpoint, results in by_endpoint.items():
        baseline_code, baseline_length, baseline_time = baselines.get(endpoint, (None, 0, 0.0))

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

            # Response analyzer: error patterns, reflection, artifacts
            for finding in analyze_response(endpoint, payload, vuln_type, body, response_code):
                finding.parameter = parameter_name
                finding.http_method = http_method
                key = (finding.endpoint, finding.vulnerability_type, finding.detection_method)
                if key not in seen:
                    seen.add(key)
                    all_findings.append(finding)

            # Diff analyzer: baseline vs injected (skip trong quick mode)
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

            # Time-based analyzer (skip trong quick mode)
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
