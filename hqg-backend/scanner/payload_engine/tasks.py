from __future__ import annotations

import asyncio
import logging

from backend.celery_app import celery_app
from scanner.payload_engine.injector import inject_requests_async
from scanner.payload_engine.payload_loader import load_payloads
from scanner.payload_engine.payload_mutator import mutate_payloads
from scanner.payload_engine.request_builder import (
    build_form_injection_requests,
    build_injection_requests,
)

logger = logging.getLogger(__name__)


def _limit_payload_sets(
    payload_sets: dict[str, list[str]],
    max_payloads_per_param: int | None,
) -> dict[str, list[str]]:
    if not max_payloads_per_param or max_payloads_per_param <= 0:
        return payload_sets

    return {
        vuln_type: payloads[:max_payloads_per_param]
        for vuln_type, payloads in payload_sets.items()
    }


def _request_key(request: object) -> tuple[object, ...]:
    return (
        request.method,
        request.url,
        request.vulnerability_type,
        request.payload,
        request.parameter,
        tuple(sorted((request.headers or {}).items())),
        tuple(sorted((request.form_data or {}).items())),
    )


async def _inject_payloads_async(
    endpoints: list[str],
    concurrency: int,
    inject_headers: bool,
    payload_mutation: bool = False,
    forms: list[dict] | None = None,
    endpoint_info: list[dict] | None = None,
    max_payloads_per_param: int | None = None,
    timeout_seconds: float = 15.0,
    allow_generic_fallback: bool = True,
    scan_mode: str = "standard",
) -> list[dict[str, object]]:
    payload_sets = load_payloads()

    if payload_mutation:
        payload_sets = mutate_payloads(payload_sets)

    payload_sets = _limit_payload_sets(payload_sets, max_payloads_per_param)

    # Build a quick lookup of url → known params from crawler EndpointInfo
    param_map: dict[str, list[str]] = {}
    for info in (endpoint_info or []):
        url = info.get("url", "")
        params = info.get("parameters") or []
        if url and params:
            param_map[url] = params

    all_requests = []
    for endpoint in endpoints:
        known_params = param_map.get(endpoint)
        all_requests.extend(
            build_injection_requests(
                endpoint=endpoint,
                payload_sets=payload_sets,
                inject_headers=inject_headers,
                known_params=known_params,
                allow_generic_fallback=allow_generic_fallback,
            )
        )

    # Also inject into forms (POST fields, GET form params)
    for form in (forms or []):
        all_requests.extend(
            build_form_injection_requests(form=form, payload_sets=payload_sets)
        )

    # InjectionRequest is not hashable; dedupe via explicit signature.
    seen: set[tuple[object, ...]] = set()
    unique_requests = []
    for request in all_requests:
        key = _request_key(request)
        if key in seen:
            continue
        seen.add(key)
        unique_requests.append(request)

    if len(unique_requests) != len(all_requests):
        logger.info(
            "Payload injection deduped %d duplicate requests (%d -> %d) timeout=%.1fs generic_fallback=%s",
            len(all_requests) - len(unique_requests),
            len(all_requests),
            len(unique_requests),
            timeout_seconds,
            allow_generic_fallback,
        )
    else:
        logger.info(
            "Payload injection generated %d requests timeout=%.1fs generic_fallback=%s",
            len(unique_requests),
            timeout_seconds,
            allow_generic_fallback,
        )

    results = await inject_requests_async(
        requests=unique_requests,
        concurrency=concurrency,
        timeout_seconds=timeout_seconds,
        scan_mode=scan_mode,
    )
    return [result.to_dict() for result in results]


@celery_app.task(name="scanner.payload_engine.inject_payloads")
def inject_payloads(
    scan_id: str,
    endpoints: list[str],
    concurrency: int = 40,
    inject_headers: bool = False,
    payload_mutation: bool = False,
    forms: list[dict] | None = None,
    endpoint_info: list[dict] | None = None,
    max_payloads_per_param: int | None = None,
    timeout_seconds: float = 15.0,
    allow_generic_fallback: bool = True,
    scan_mode: str = "standard",
) -> dict[str, object]:
    findings = asyncio.run(
        _inject_payloads_async(
            endpoints=endpoints,
            concurrency=concurrency,
            inject_headers=inject_headers,
            payload_mutation=payload_mutation,
            forms=forms,
            endpoint_info=endpoint_info,
            max_payloads_per_param=max_payloads_per_param,
            timeout_seconds=timeout_seconds,
            allow_generic_fallback=allow_generic_fallback,
            scan_mode=scan_mode,
        )
    )

    return {
        "scan_id": scan_id,
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
        "findings": findings,
    }
