from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import httpx

from backend.celery_app import celery_app
from scanner.asset_discovery.dns_resolver import resolve_dns_records
from scanner.asset_discovery.models import AssetDiscoveryOutput, DNSResolution
from scanner.asset_discovery.service_detector import detect_http_services
from scanner.asset_discovery.subdomain_enum import discover_subdomains, extract_domain
from scanner.asset_discovery.tech_fingerprint import detect_technologies


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
    )


@celery_app.task(name="scanner.asset_discovery.discover_assets")
def discover_assets(scan_id: str, target: str) -> dict[str, object]:
    result = asyncio.run(_discover_assets_async(target))
    payload = result.to_dict()
    payload["scan_id"] = scan_id
    return payload
