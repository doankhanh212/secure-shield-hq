from __future__ import annotations

from collections import defaultdict
from statistics import mean
from urllib.parse import urlparse

from fastapi import APIRouter
from fastapi.concurrency import run_in_threadpool

from scanner.scan_manager.scan_service import get_discovery, get_findings, list_scans

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

_SEVERITY_BUCKETS = ("critical", "high", "medium", "low")
_CONFIDENCE_SCORES = {
    "critical": 95.0,
    "high": 85.0,
    "medium": 60.0,
    "low": 30.0,
    "info": 10.0,
}


def _normalize_domain(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    host = parsed.hostname or parsed.path.split("/")[0]
    return host.lower().strip()


def _severity_key(value: object) -> str:
    return str(value or "").strip().lower()


def _confidence_score(value: object) -> float:
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric <= 1.0:
            return max(0.0, min(100.0, numeric * 100.0))
        return max(0.0, min(100.0, numeric))

    text = str(value or "").strip().lower()
    if not text:
        return 0.0
    if text.endswith("%"):
        try:
            return max(0.0, min(100.0, float(text[:-1])))
        except ValueError:
            return 0.0
    if text in _CONFIDENCE_SCORES:
        return _CONFIDENCE_SCORES[text]
    try:
        numeric = float(text)
    except ValueError:
        return 0.0
    if numeric <= 1.0:
        return max(0.0, min(100.0, numeric * 100.0))
    return max(0.0, min(100.0, numeric))


def _is_open_finding(finding: dict[str, object]) -> bool:
    return str(finding.get("status", "open")).strip().lower() != "resolved"


def _completed_scans_sorted() -> list[dict[str, object]]:
    scans = list_scans()
    completed = [
        scan for scan in scans if str(scan.get("status", "")).strip().lower() == "completed"
    ]
    return sorted(completed, key=lambda scan: str(scan.get("created_at", "")))


def _count_api_endpoints(discovery: dict[str, object]) -> int:
    for key in ("api_endpoints", "crawled_endpoints", "endpoint_info", "endpoints"):
        value = discovery.get(key)
        if isinstance(value, list):
            return len(value)
    return 0


def _dashboard_stats() -> dict[str, object]:
    scans = list_scans()
    unique_targets: set[str] = set()
    unique_subdomains: set[str] = set()
    severity_counts = {bucket: 0 for bucket in _SEVERITY_BUCKETS}
    confidence_scores: list[float] = []
    open_vulnerabilities = 0
    active_scans = 0
    api_endpoints = 0

    for scan in scans:
        target = _normalize_domain(scan.get("target"))
        if target:
            unique_targets.add(target)

        status = str(scan.get("status", "")).strip().lower()
        if status in {"running", "queued"}:
            active_scans += 1

        if status != "completed":
            continue

        scan_id = str(scan.get("scan_id", "")).strip()
        if not scan_id:
            continue

        findings = get_findings(scan_id)
        discovery = get_discovery(scan_id)

        for finding in findings:
            severity = _severity_key(finding.get("severity"))
            if severity in severity_counts:
                severity_counts[severity] += 1
            if _is_open_finding(finding):
                open_vulnerabilities += 1
            confidence_scores.append(_confidence_score(finding.get("confidence")))

        for subdomain in discovery.get("subdomains") or []:
            normalized = _normalize_domain(subdomain)
            if normalized:
                unique_subdomains.add(normalized)

        api_endpoints += _count_api_endpoints(discovery)

    return {
        "total_assets": len(unique_targets),
        "open_vulnerabilities": open_vulnerabilities,
        "active_scans": active_scans,
        "risk_score": round(mean(confidence_scores), 2) if confidence_scores else 0.0,
        "critical_count": severity_counts["critical"],
        "high_count": severity_counts["high"],
        "medium_count": severity_counts["medium"],
        "low_count": severity_counts["low"],
        "domains": len(unique_targets),
        "subdomains": len(unique_subdomains),
        "api_endpoints": api_endpoints,
        "ips": 0,
        "exposed_services": 0,
    }


def _dashboard_posture() -> dict[str, object]:
    completed_scans = _completed_scans_sorted()
    recent_scans = completed_scans[-10:]

    trend: list[dict[str, object]] = []
    current_score = 0.0

    for index, scan in enumerate(recent_scans, start=1):
        scan_id = str(scan.get("scan_id", "")).strip()
        findings = get_findings(scan_id) if scan_id else []
        score = max(0.0, 100.0 - min(100.0, len(findings) * 5.0))
        trend.append({"label": f"#{index}", "score": round(score, 2)})
        current_score = score

    return {
        "current_score": round(current_score, 2),
        "trend": trend,
    }


def _dashboard_top_risks() -> dict[str, object]:
    assets: dict[str, dict[str, object]] = defaultdict(
        lambda: {"domain": "", "critical_count": 0, "high_count": 0}
    )

    for scan in _completed_scans_sorted():
        scan_id = str(scan.get("scan_id", "")).strip()
        scan_target = _normalize_domain(scan.get("target"))
        if not scan_id:
            continue

        for finding in get_findings(scan_id):
            domain = (
                _normalize_domain(finding.get("target"))
                or _normalize_domain(finding.get("endpoint"))
                or scan_target
            )
            if not domain:
                continue

            asset = assets[domain]
            asset["domain"] = domain

            severity = _severity_key(finding.get("severity"))
            if severity == "critical":
                asset["critical_count"] = int(asset["critical_count"]) + 1
            elif severity == "high":
                asset["high_count"] = int(asset["high_count"]) + 1

    ranked_assets = sorted(
        assets.values(),
        key=lambda asset: (
            int(asset["critical_count"]),
            int(asset["high_count"]),
            asset["domain"],
        ),
        reverse=True,
    )[:5]

    output_assets = []
    for asset in ranked_assets:
        critical_count = int(asset["critical_count"])
        high_count = int(asset["high_count"])
        output_assets.append(
            {
                "domain": str(asset["domain"]),
                "score": float(critical_count * 20 + high_count * 10),
                "critical_count": critical_count,
                "high_count": high_count,
            }
        )

    return {"assets": output_assets}


@router.get("/stats", summary="Get dashboard summary stats")
async def get_dashboard_stats() -> dict[str, object]:
    return await run_in_threadpool(_dashboard_stats)


@router.get("/posture", summary="Get dashboard risk posture trend")
async def get_dashboard_posture() -> dict[str, object]:
    return await run_in_threadpool(_dashboard_posture)


@router.get("/top-risks", summary="Get riskiest assets")
async def get_dashboard_top_risks() -> dict[str, object]:
    return await run_in_threadpool(_dashboard_top_risks)