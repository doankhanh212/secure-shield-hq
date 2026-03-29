from __future__ import annotations

import asyncio
import logging
import time

import httpx

from scanner.payload_engine.models import InjectionRequest, InjectionResult

logger = logging.getLogger(__name__)

# Response codes that indicate the endpoint is unreachable / misbehaving.
# Payloads sent to these endpoints should not count as useful injection data.
_SKIP_CODES: frozenset[int] = frozenset({403, 405, 429, 500, 502, 503, 508})

# After this many consecutive skip-code responses per endpoint, stop injecting it.
_MAX_ERRORS_PER_ENDPOINT: int = 3

# Maximum injection requests per scan mode (hard cap to prevent infinite loops).
_MAX_REQUESTS_BY_MODE: dict[str, int] = {
    "quick": 100,
    "standard": 2000,
    "deep": 10000,
    "full": 10000,
}

# Courtesy delay (seconds) between consecutive requests — reduces server hammering.
_RATE_DELAY_BY_MODE: dict[str, float] = {
    "quick": 0.2,
    "standard": 0.1,
    "deep": 0.05,
    "full": 0.05,
}


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
                parameter=request.parameter,
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
                parameter=request.parameter,
            )


_GLOBAL_ERROR_THRESHOLD: int = 50
"""When total skip-code responses across all endpoints exceed this, stop the scan."""


async def inject_requests_async(
    requests: list[InjectionRequest],
    concurrency: int = 40,
    timeout_seconds: float = 15.0,
    scan_mode: str = "standard",
) -> list[InjectionResult]:
    max_requests = _MAX_REQUESTS_BY_MODE.get(scan_mode, 2000)
    rate_delay = _RATE_DELAY_BY_MODE.get(scan_mode, 0.1)
    batch_size = min(concurrency, 20)  # process in small batches for error visibility

    # Hard-cap total requests upfront to prevent runaway scans.
    if len(requests) > max_requests:
        logger.warning(
            "Truncating injection queue: %d → %d requests (scan_mode=%s limit)",
            len(requests), max_requests, scan_mode,
        )
        requests = requests[:max_requests]

    semaphore = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(timeout_seconds)
    limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)

    # Per-endpoint consecutive-error counter (shared across concurrent tasks via asyncio).
    endpoint_errors: dict[str, int] = {}
    global_errors: int = 0
    all_results: list[InjectionResult] = []

    async def _execute_with_guards(req: InjectionRequest) -> InjectionResult:
        nonlocal global_errors

        # Skip endpoint if it already exceeded the error threshold.
        if endpoint_errors.get(req.endpoint, 0) >= _MAX_ERRORS_PER_ENDPOINT:
            return InjectionResult(
                endpoint=req.endpoint,
                vulnerability_type=req.vulnerability_type,
                payload=req.payload,
                response_code=None,
                response_time=0.0,
                error="endpoint_skipped: consecutive_errors",
                parameter=req.parameter,
            )

        result = await _execute_request(client, semaphore, req)

        # Track bad responses per endpoint.
        if result.response_code in _SKIP_CODES:
            endpoint_errors[req.endpoint] = endpoint_errors.get(req.endpoint, 0) + 1
            global_errors += 1
            if endpoint_errors[req.endpoint] >= _MAX_ERRORS_PER_ENDPOINT:
                logger.warning(
                    "Skipping endpoint %s after %d skip-code responses",
                    req.endpoint, _MAX_ERRORS_PER_ENDPOINT,
                )
        elif result.error and "endpoint_skipped" not in (result.error or ""):
            global_errors += 1

        # Courtesy delay to avoid overwhelming the target.
        if rate_delay > 0:
            await asyncio.sleep(rate_delay)

        return result

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        max_redirects=5,
        verify=False,
        limits=limits,
    ) as client:
        # Process requests in batches so endpoint error tracking is effective.
        # After each batch, check global error threshold before continuing.
        for i in range(0, len(requests), batch_size):
            if global_errors >= _GLOBAL_ERROR_THRESHOLD:
                logger.error(
                    "Global error threshold reached (%d errors) — aborting remaining %d requests",
                    global_errors, len(requests) - i,
                )
                break

            batch = requests[i : i + batch_size]
            # Filter out requests for already-dead endpoints before scheduling
            live_batch = [
                req for req in batch
                if endpoint_errors.get(req.endpoint, 0) < _MAX_ERRORS_PER_ENDPOINT
            ]
            if not live_batch:
                continue

            batch_results = await asyncio.gather(
                *[_execute_with_guards(req) for req in live_batch]
            )
            all_results.extend(batch_results)

    skipped = sum(1 for r in all_results if r.error and "endpoint_skipped" in (r.error or ""))
    if skipped or global_errors:
        logger.info(
            "Injection complete: %d results, %d skipped, %d global errors",
            len(all_results), skipped, global_errors,
        )

    return all_results
