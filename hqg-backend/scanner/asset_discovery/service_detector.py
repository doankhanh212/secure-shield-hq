from __future__ import annotations

import asyncio

import httpx

from scanner.asset_discovery.models import ServiceProbeResult


async def _probe_url(client: httpx.AsyncClient, host: str, scheme: str) -> ServiceProbeResult:
    url = f"{scheme}://{host}"
    try:
        response = await client.get(url)
        server_banner = response.headers.get("server") or response.headers.get("x-powered-by")
        body = response.text[:4000]
        return ServiceProbeResult(
            host=host,
            scheme=scheme,
            url=url,
            status_code=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            server_banner=server_banner,
            body_snippet=body,
        )
    except Exception as exc:
        return ServiceProbeResult(
            host=host,
            scheme=scheme,
            url=url,
            status_code=None,
            error=str(exc),
        )


async def detect_http_services(
    hosts: list[str],
    timeout_seconds: float = 10.0,
    concurrency: int = 50,
) -> list[ServiceProbeResult]:
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
    timeout = httpx.Timeout(timeout_seconds)
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        verify=False,
        limits=limits,
    ) as client:

        async def probe_with_limit(host: str, scheme: str) -> ServiceProbeResult:
            async with semaphore:
                return await _probe_url(client, host, scheme)

        tasks = [
            probe_with_limit(host, scheme)
            for host in hosts
            for scheme in ("http", "https")
        ]
        return await asyncio.gather(*tasks)
