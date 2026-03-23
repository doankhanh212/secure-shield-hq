from __future__ import annotations

import asyncio
from collections import deque
from urllib.parse import parse_qsl, urlparse

import httpx

from scanner.crawler.html_parser import parse_html_document
from scanner.crawler.js_parser import extract_js_endpoints, extract_js_parameters
from scanner.crawler.models import CrawlOutput, EndpointInfo, FormModel, GraphQLEndpoint
from scanner.crawler.scope_filter import (
    extract_domain,
    is_api_endpoint,
    is_graphql_endpoint,
    is_in_scope,
    is_static_resource,
)
from scanner.crawler.url_normalizer import endpoint_from_url, normalize_url


_INTROSPECTION_QUERY = '{"query":"{__schema{types{name}}}"}'


async def _fetch_text(client: httpx.AsyncClient, url: str) -> tuple[str, dict[str, str], int] | None:
    try:
        response = await client.get(url)
    except Exception:
        return None

    content_type = response.headers.get("content-type", "")
    if "text" not in content_type and "json" not in content_type and "javascript" not in content_type:
        return None

    return response.text, {k.lower(): v for k, v in response.headers.items()}, response.status_code


def _collect_query_params(url: str) -> list[str]:
    parsed = urlparse(url)
    return [key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]


def _root_url(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return f"https://{target.strip().strip('/')}"


async def _check_graphql_introspection(
    client: httpx.AsyncClient,
    url: str,
) -> bool:
    """Send an introspection probe to *url* and return True if it succeeds."""
    try:
        resp = await client.post(
            url,
            content=_INTROSPECTION_QUERY,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200 and "__schema" in resp.text:
            return True
    except Exception:
        pass
    return False


def _register_endpoint(
    url: str,
    source: str,
    method: str,
    extra_params: list[str],
    *,
    endpoint_info_map: dict[str, EndpointInfo],
    endpoints: set[str],
    parameters: set[str],
    api_endpoints: set[str],
    graphql_urls: set[str],
) -> None:
    """Classify and record a discovered URL, merging parameter information."""
    ep = endpoint_from_url(url)
    endpoints.add(ep)

    url_params = _collect_query_params(url)
    all_params = list(dict.fromkeys(url_params + extra_params))  # dedup, preserve order
    parameters.update(all_params)

    if ep in endpoint_info_map:
        existing = endpoint_info_map[ep]
        merged = list(dict.fromkeys(existing.parameters + all_params))
        endpoint_info_map[ep] = EndpointInfo(
            url=ep,
            parameters=merged,
            method=existing.method if existing.method != "GET" else method,
            source=existing.source,
        )
    else:
        endpoint_info_map[ep] = EndpointInfo(
            url=ep,
            parameters=all_params,
            method=method,
            source=source,
        )

    if is_graphql_endpoint(url):
        graphql_urls.add(url)
    elif is_api_endpoint(url):
        api_endpoints.add(ep)


async def crawl_target_async(target: str, max_depth: int = 2) -> CrawlOutput:
    base = _root_url(target)
    target_domain = extract_domain(base)
    start_url = normalize_url(base)
    if not start_url:
        return CrawlOutput()

    seen_urls: set[str] = set()
    endpoints: set[str] = set()
    parameters: set[str] = set()
    api_endpoints: set[str] = set()
    graphql_urls: set[str] = set()
    forms_map: dict[tuple[str, str], FormModel] = {}
    endpoint_info_map: dict[str, EndpointInfo] = {}

    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    js_candidates: set[str] = set()
    inline_script_bodies: set[tuple[str, str]] = set()

    limits = httpx.Limits(max_keepalive_connections=40, max_connections=40)
    timeout = httpx.Timeout(10.0)

    reg_kwargs = dict(
        endpoint_info_map=endpoint_info_map,
        endpoints=endpoints,
        parameters=parameters,
        api_endpoints=api_endpoints,
        graphql_urls=graphql_urls,
    )

    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False, limits=limits) as client:
        for suffix in ("/robots.txt", "/sitemap.xml"):
            seed_url = normalize_url(base + suffix)
            if seed_url and is_in_scope(seed_url, target_domain):
                queue.append((seed_url, 1))

        while queue:
            current_url, depth = queue.popleft()
            if current_url in seen_urls:
                continue
            if depth > max_depth:
                continue
            if not is_in_scope(current_url, target_domain):
                continue
            if is_static_resource(current_url):
                continue

            seen_urls.add(current_url)
            _register_endpoint(current_url, source="html", method="GET", extra_params=[], **reg_kwargs)

            fetched = await _fetch_text(client, current_url)
            if not fetched:
                continue

            body, headers, _ = fetched
            content_type = headers.get("content-type", "")

            if "javascript" in content_type or current_url.endswith(".js"):
                js_endpoints = extract_js_endpoints(body, current_url)
                js_params = extract_js_parameters(body)
                parameters |= js_params
                for found in js_endpoints:
                    normalized = normalize_url(found, current_url)
                    if normalized and is_in_scope(normalized, target_domain) and not is_static_resource(normalized):
                        ep_params = _collect_query_params(normalized)
                        _register_endpoint(
                            normalized, source="js", method="GET",
                            extra_params=ep_params, **reg_kwargs,
                        )
                        if normalized not in seen_urls and depth + 1 <= max_depth:
                            queue.append((normalized, depth + 1))
                continue

            links, js_files, forms, inline_scripts = parse_html_document(body, current_url)

            for found_url in links:
                normalized = normalize_url(found_url, current_url)
                if not normalized or not is_in_scope(normalized, target_domain):
                    continue
                if is_static_resource(normalized):
                    continue
                ep_params = _collect_query_params(normalized)
                _register_endpoint(
                    normalized, source="html", method="GET",
                    extra_params=ep_params, **reg_kwargs,
                )
                if normalized not in seen_urls and depth + 1 <= max_depth:
                    queue.append((normalized, depth + 1))

            for js_file in js_files:
                normalized_js = normalize_url(js_file, current_url)
                if normalized_js and is_in_scope(normalized_js, target_domain):
                    js_candidates.add(normalized_js)

            for script_text in inline_scripts:
                inline_script_bodies.add((current_url, script_text))

            for form in forms:
                normalized_action = normalize_url(form.action, current_url)
                action = normalized_action or current_url
                form_key = (action, form.method)
                if form_key not in forms_map:
                    forms_map[form_key] = FormModel(action=action, method=form.method, fields=[])

                merged_fields = set(forms_map[form_key].fields)
                merged_fields.update(form.fields)
                forms_map[form_key].fields = sorted(merged_fields)

                # Register the form action endpoint with its fields as parameters
                _register_endpoint(
                    action, source="form", method=form.method,
                    extra_params=sorted(merged_fields), **reg_kwargs,
                )
                parameters.update(form.fields)

        # --- Fetch external JS files ---
        js_fetches = await asyncio.gather(
            *(_fetch_text(client, js_url) for js_url in sorted(js_candidates)),
            return_exceptions=True,
        )

        # --- Process JS results ---
        for js_url, fetched in zip(sorted(js_candidates), js_fetches):
            if not fetched or isinstance(fetched, Exception):
                continue
            body, _, _ = fetched
            js_endpoints = extract_js_endpoints(body, js_url)
            js_params = extract_js_parameters(body)
            parameters |= js_params
            for found in js_endpoints:
                normalized = normalize_url(found, js_url)
                if normalized and is_in_scope(normalized, target_domain) and not is_static_resource(normalized):
                    ep_params = _collect_query_params(normalized)
                    _register_endpoint(
                        normalized, source="js", method="GET",
                        extra_params=ep_params, **reg_kwargs,
                    )

        for base_url, script_body in inline_script_bodies:
            js_endpoints = extract_js_endpoints(script_body, base_url)
            js_params = extract_js_parameters(script_body)
            parameters |= js_params
            for found in js_endpoints:
                normalized = normalize_url(found, base_url)
                if normalized and is_in_scope(normalized, target_domain) and not is_static_resource(normalized):
                    ep_params = _collect_query_params(normalized)
                    _register_endpoint(
                        normalized, source="js", method="GET",
                        extra_params=ep_params, **reg_kwargs,
                    )

        # --- GraphQL introspection probes ---
        graphql_results: list[GraphQLEndpoint] = []
        for gql_url in sorted(graphql_urls):
            introspection_ok = await _check_graphql_introspection(client, gql_url)
            graphql_results.append(GraphQLEndpoint(url=gql_url, introspection_enabled=introspection_ok))

    endpoint_info_list = sorted(endpoint_info_map.values(), key=lambda e: e.url)

    return CrawlOutput(
        endpoints=sorted(endpoints),
        endpoint_info=endpoint_info_list,
        parameters=sorted(parameters),
        forms=sorted(forms_map.values(), key=lambda x: (x.action, x.method)),
        api_endpoints=sorted(api_endpoints),
        graphql_endpoints=graphql_results,
    )
