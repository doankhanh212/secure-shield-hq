from __future__ import annotations

import asyncio

import dns.asyncresolver
import dns.exception

from scanner.asset_discovery.models import DNSResolution


RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "NS")


async def _resolve_record(
    resolver: dns.asyncresolver.Resolver,
    host: str,
    record_type: str,
) -> list[str]:
    try:
        answers = await resolver.resolve(host, record_type, lifetime=5.0)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        return []
    except dns.resolver.NoNameservers:
        return []

    values: list[str] = []
    for answer in answers:
        text = answer.to_text().strip().rstrip(".")
        values.append(text)
    return values


async def resolve_dns_records(
    host: str,
    resolver: dns.asyncresolver.Resolver,
) -> DNSResolution:
    results = await asyncio.gather(
        _resolve_record(resolver, host, "A"),
        _resolve_record(resolver, host, "AAAA"),
        _resolve_record(resolver, host, "CNAME"),
        _resolve_record(resolver, host, "MX"),
        _resolve_record(resolver, host, "TXT"),
        _resolve_record(resolver, host, "NS"),
    )

    return DNSResolution(
        host=host,
        a=results[0],
        aaaa=results[1],
        cname=results[2],
        mx=results[3],
        txt=results[4],
        ns=results[5],
    )
