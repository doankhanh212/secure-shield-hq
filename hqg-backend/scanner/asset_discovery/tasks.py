from __future__ import annotations

import asyncio
import ipaddress
import logging

import dns.asyncresolver
import httpx

from backend.celery_app import celery_app
from scanner.asset_discovery.dns_resolver import resolve_dns_records
from scanner.asset_discovery.models import AssetDiscoveryOutput, DNSResolution
from scanner.asset_discovery.service_detector import detect_http_services
from scanner.asset_discovery.subdomain_enum import discover_subdomains, extract_domain
from scanner.asset_discovery.tech_fingerprint import detect_technologies

logger = logging.getLogger(__name__)


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.is_global


async def _discover_assets_async(target: str) -> AssetDiscoveryOutput:
    domain = extract_domain(target)
    resolver = dns.asyncresolver.Resolver()

    async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
        subdomains = sorted(await discover_subdomains(domain, resolver, client))

    hosts = sorted(set([domain, *subdomains]))
    dns_results = await asyncio.gather(
        *(resolve_dns_records(host, resolver) for host in hosts)
    )

    dns_map: dict[str, DNSResolution] = {record.host: record for record in dns_results}

    ips = sorted(
        {
            ip
            for record in dns_results
            for ip in record.ips
            if _is_public_ip(ip)
        }
    )

    service_results = await detect_http_services(hosts)
    technologies = sorted(detect_technologies(service_results))

    # ── Wappalyzer multi-signal fingerprinting ─────────────────────────
    from scanner.asset_discovery.wappalyzer_engine import fingerprint_response

    wap_raw: list = []
    for svc in service_results:
        body = (
            getattr(svc, "body", None)
            or getattr(svc, "html", None)
            or getattr(svc, "response_body", None)
            or getattr(svc, "body_snippet", None)
            or ""
        )
        hdrs = getattr(svc, "headers", {}) or {}
        svc_url = getattr(svc, "url", None) or getattr(svc, "base_url", None) or ""
        if body or hdrs:
            try:
                wap_raw.extend(fingerprint_response(svc_url, body, hdrs))
            except Exception:
                continue

    # Deduplicate across subdomains: keep entry with version over one without
    seen: dict[str, object] = {}
    for t in wap_raw:
        existing = seen.get(t.name)
        if existing is None or (t.version and not existing.version):
            seen[t.name] = t
    wap_techs = list(seen.values())

    logger.info(
        "Wappalyzer unique: %d technologies (%d versioned, %d with CPE)",
        len(wap_techs),
        sum(1 for t in wap_techs if t.version),
        sum(1 for t in wap_techs if t.cpe),
    )

    service_labels = sorted(
        {
            result.scheme.upper()
            for result in service_results
            if result.status_code is not None
        }
    )

    return AssetDiscoveryOutput(
        domain=domain,
        subdomains=subdomains,
        ips=ips,
        services=service_labels,
        technologies=technologies,
        dns_records=dns_map,
        service_details=service_results,
        wappalyzer_technologies=[t.to_dict() for t in wap_techs],
    )


@celery_app.task(name="scanner.asset_discovery.discover_assets")
def discover_assets(scan_id: str, target: str) -> dict[str, object]:
    result = asyncio.run(_discover_assets_async(target))
    payload = result.to_dict()
    payload["scan_id"] = scan_id
    return payload
