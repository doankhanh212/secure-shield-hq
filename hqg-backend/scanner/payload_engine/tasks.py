from __future__ import annotations

import asyncio

from backend.celery_app import celery_app
from scanner.payload_engine.injector import inject_requests_async
from scanner.payload_engine.payload_loader import load_payloads
from scanner.payload_engine.payload_mutator import mutate_payloads
from scanner.payload_engine.request_builder import (
    build_form_injection_requests,
    build_injection_requests,
)


async def _inject_payloads_async(
    endpoints: list[str],
    concurrency: int,
    inject_headers: bool,
    payload_mutation: bool = False,
    forms: list[dict] | None = None,
    endpoint_info: list[dict] | None = None,
) -> list[dict[str, object]]:
    payload_sets = load_payloads()

    if payload_mutation:
        payload_sets = mutate_payloads(payload_sets)

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
            )
        )

    # Also inject into forms (POST fields, GET form params)
    for form in (forms or []):
        all_requests.extend(
            build_form_injection_requests(form=form, payload_sets=payload_sets)
        )

    results = await inject_requests_async(
        requests=all_requests,
        concurrency=concurrency,
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
) -> dict[str, object]:
    findings = asyncio.run(
        _inject_payloads_async(
            endpoints=endpoints,
            concurrency=concurrency,
            inject_headers=inject_headers,
            payload_mutation=payload_mutation,
            forms=forms,
            endpoint_info=endpoint_info,
        )
    )

    return {
        "scan_id": scan_id,
        "total_endpoints": len(endpoints),
        "total_findings": len(findings),
        "findings": findings,
    }
