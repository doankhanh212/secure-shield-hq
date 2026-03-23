"""Template executor — sends requests with payloads and evaluates matchers."""
from __future__ import annotations

import asyncio
import logging
import time as time_mod
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from scanner.template_engine.matchers import evaluate_matchers
from scanner.template_engine.models import (
    ScanTemplate,
    TemplateMatch,
)

logger = logging.getLogger(__name__)

_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _inject_payload_into_url(base_url: str, payload: str, known_params: list[str] | None = None) -> str:
    """Inject payload into every query-string parameter value.

    If *known_params* is provided and the URL has no existing params,
    the known param names are seeded so we don't fall back to just "id".
    """
    parsed = urlparse(base_url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    if params:
        injected = [(k, payload) for k, _ in params]
    elif known_params:
        injected = [(p, payload) for p in known_params]
    else:
        injected = [("id", payload)]
    query = urlencode(injected)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))


def _inject_payload_into_body(body_template: str, payload: str) -> str:
    """Replace {{payload}} placeholder; fallback: append to body."""
    if "{{payload}}" in body_template:
        return body_template.replace("{{payload}}", payload)
    return payload


async def _execute_template_request(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    endpoint: str,
    template: ScanTemplate,
    payload: str,
    known_params: list[str] | None = None,
) -> TemplateMatch | None:
    """Send one request for *template* × *payload* against *endpoint*, evaluate matchers."""
    async with semaphore:
        method = template.request.method
        headers = {**_DEFAULT_HEADERS, **template.request.headers}

        # Build the target URL
        if template.request.inject_in == "query":
            url = _inject_payload_into_url(endpoint, payload, known_params=known_params)
            body_content = None
        elif template.request.inject_in == "body":
            url = endpoint
            body_content = _inject_payload_into_body(template.request.body, payload)
        elif template.request.inject_in == "header":
            url = endpoint
            for hdr_name in list(template.request.headers.keys()) or ["X-Forwarded-For"]:
                headers[hdr_name] = payload
            body_content = None
        elif template.request.inject_in == "path":
            parsed = urlparse(endpoint)
            new_path = f"{parsed.path}/{payload}" if parsed.path != "/" else f"/{payload}"
            url = urlunparse((parsed.scheme, parsed.netloc, new_path, "", parsed.query, ""))
            body_content = None
        else:
            url = _inject_payload_into_url(endpoint, payload, known_params=known_params)
            body_content = None

        # Execute request
        start = time_mod.perf_counter()
        try:
            kwargs: dict = {"headers": headers}
            if body_content and method in ("POST", "PUT", "PATCH"):
                kwargs["content"] = body_content

            response = await client.request(method, url, **kwargs)
            elapsed = time_mod.perf_counter() - start

            resp_body = response.text[:10_000]
            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            resp_code = response.status_code
        except Exception as exc:
            logger.warning(
                "Template %s request failed for %s: [%s] %r",
                template.id, url, type(exc).__name__, str(exc)[:200],
            )
            return None

        # Evaluate matchers
        matched, evidence = evaluate_matchers(
            template.matchers,
            body=resp_body,
            headers=resp_headers,
            status_code=resp_code,
            response_time=elapsed,
            condition=template.match_condition,
        )

        if not matched:
            logger.debug(
                "Template %s no match on %s (status=%d, body_len=%d, time=%.2fs)",
                template.id, url, resp_code, len(resp_body), elapsed,
            )
            return None

        return TemplateMatch(
            endpoint=endpoint,
            payload=payload,
            template_id=template.id,
            vulnerability_name=template.name,
            vulnerability_type=template.vulnerability_type,
            severity=template.severity,
            confidence="High",
            owasp=template.owasp,
            cwe=template.cwe,
            evidence=evidence,
        )


async def run_templates_async(
    endpoints: list[str],
    templates: list[ScanTemplate],
    concurrency: int = 30,
    timeout_seconds: float = 15.0,
    endpoint_info: list[dict] | None = None,
) -> list[TemplateMatch]:
    """Execute all templates across all endpoints with async concurrency.

    Parameters
    ----------
    endpoint_info:
        Optional list of EndpointInfo dicts from the crawler (each has
        ``url``, ``parameters``, ``method``, ``source`` keys).  When provided,
        param names are passed to the injector so template requests target the
        real discovered parameters rather than falling back to generic "id".
    """
    semaphore = asyncio.Semaphore(concurrency)
    timeout = httpx.Timeout(timeout_seconds)
    limits = httpx.Limits(
        max_keepalive_connections=concurrency,
        max_connections=concurrency,
    )

    # Build lookup: endpoint_url → list[param_name]
    param_map: dict[str, list[str]] = {}
    for info in (endpoint_info or []):
        url = info.get("url", "")
        params = info.get("parameters") or []
        if url and params:
            param_map[url] = params

    # De-duplicate: (endpoint, template_id) → only test once per template per endpoint
    seen: set[tuple[str, str]] = set()
    tasks: list[asyncio.Task] = []

    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=True, verify=False, limits=limits,
    ) as client:
        for endpoint in endpoints:
            known_params = param_map.get(endpoint)
            for template in templates:
                key = (endpoint, template.id)
                if key in seen:
                    continue
                seen.add(key)

                for payload in template.payloads:
                    tasks.append(
                        asyncio.create_task(
                            _execute_template_request(
                                client, semaphore, endpoint, template, payload,
                                known_params=known_params,
                            )
                        )
                    )

        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect matches, de-duplicate by (endpoint, template_id)
    match_dedup: dict[tuple[str, str], TemplateMatch] = {}
    errors = 0
    nones = 0
    for result in results:
        if isinstance(result, TemplateMatch):
            dedup_key = (result.endpoint, result.template_id)
            if dedup_key not in match_dedup:
                match_dedup[dedup_key] = result
        elif isinstance(result, Exception):
            errors += 1
        else:
            nones += 1

    if errors:
        logger.warning("Template engine: %d tasks raised exceptions", errors)
    logger.info(
        "Template engine: %d tasks total, %d no-match, %d errors",
        len(results), nones, errors,
    )

    matches = list(match_dedup.values())
    logger.info(
        "Template engine: %d templates × %d endpoints → %d findings",
        len(templates), len(endpoints), len(matches),
    )
    return matches

    # Collect matches, de-duplicate by (endpoint, template_id)
    match_dedup: dict[tuple[str, str], TemplateMatch] = {}
    errors = 0
    nones = 0
    for result in results:
        if isinstance(result, TemplateMatch):
            dedup_key = (result.endpoint, result.template_id)
            if dedup_key not in match_dedup:
                match_dedup[dedup_key] = result
        elif isinstance(result, Exception):
            errors += 1
        else:
            nones += 1

    if errors:
        logger.warning("Template engine: %d tasks raised exceptions", errors)
    logger.info(
        "Template engine: %d tasks total, %d no-match, %d errors",
        len(results), nones, errors,
    )

    matches = list(match_dedup.values())
    logger.info(
        "Template engine: %d templates × %d endpoints → %d findings",
        len(templates), len(endpoints), len(matches),
    )
    return matches
