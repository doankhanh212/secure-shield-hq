from __future__ import annotations

import asyncio
import time

import httpx

from scanner.payload_engine.models import InjectionRequest, InjectionResult


async def _execute_request(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    request: InjectionRequest,
) -> InjectionResult:
    async with semaphore:
        start = time.perf_counter()
        try:
            # Build kwargs: POST/PUT get form_data as body, GET uses URL params
            kwargs: dict = {"headers": request.headers}
            if request.method in ("POST", "PUT", "PATCH"):
                if request.form_data:
                    kwargs["data"] = request.form_data

            response = await client.request(
                request.method,
                request.url,
                **kwargs,
            )
            elapsed = time.perf_counter() - start
            body = response.text[:10_000]
            return InjectionResult(
                endpoint=request.endpoint,
                vulnerability_type=request.vulnerability_type,
                payload=request.payload,
                response_code=response.status_code,
                response_time=round(elapsed, 4),
                response_body=body,
                response_length=len(response.content),
            )
        except Exception as exc:
            elapsed = time.perf_counter() - start
            return InjectionResult(
                endpoint=request.endpoint,
                vulnerability_type=request.vulnerability_type,
                payload=request.payload,
                response_code=None,
                response_time=round(elapsed, 4),
                error=str(exc),
            )


async def inject_requests_async(
    requests: list[InjectionRequest],
    concurrency: int = 40,
    timeout_seconds: float = 15.0,
) -> list[InjectionResult]:
    semaphore = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(timeout_seconds)
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False, limits=limits) as client:
        tasks = [_execute_request(client, semaphore, req) for req in requests]
        return await asyncio.gather(*tasks)
