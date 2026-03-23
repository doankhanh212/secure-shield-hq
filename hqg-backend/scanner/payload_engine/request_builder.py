from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from scanner.payload_engine.models import InjectionRequest


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_HEADER_INJECTION_TARGETS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "User-Agent",
    "Referer",
]


def _normalize_target(endpoint: str) -> tuple[str, str]:
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
        query = parsed.query
    else:
        base = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        query = ""
    return base, query


def _extract_query_params(query: str) -> dict[str, str]:
    if not query:
        return {}
    return {key: value for key, value in parse_qsl(query, keep_blank_values=True)}


def _build_url_with_params(url: str, params: dict[str, str]) -> str:
    parsed = urlparse(url)
    query = urlencode(sorted(params.items()), doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))


def build_injection_requests(
    endpoint: str,
    payload_sets: dict[str, list[str]],
    inject_headers: bool = False,
    known_params: list[str] | None = None,
) -> list[InjectionRequest]:
    """Build GET injection requests for *endpoint*.

    Parameters
    ----------
    endpoint:
        Normalized endpoint URL (values may be empty, e.g. ``/search.php?q=``).
    payload_sets:
        Dict mapping vulnerability type → list of payloads.
    inject_headers:
        Whether to add header-injection variants.
    known_params:
        Parameter names discovered by the crawler (from URL, forms, JS).
        When provided these take precedence over params parsed from the URL.
    """
    base, query = _normalize_target(endpoint)
    existing_params = _extract_query_params(query)

    # Build the definitive list of param names to inject into.
    # Priority: known_params (crawler-discovered) → params from URL → generic fallback
    if known_params:
        injection_param_names = list(dict.fromkeys(known_params))
        # Seed existing_params with discovered names so we always have something to inject
        for p in injection_param_names:
            if p not in existing_params:
                existing_params[p] = "1"
    elif existing_params:
        injection_param_names = list(existing_params.keys())
    else:
        # No params at all — inject common probe param names
        injection_param_names = ["id", "q", "search", "cat", "page", "item", "name"]
        existing_params = {p: "1" for p in injection_param_names}

    requests: list[InjectionRequest] = []

    for vulnerability_type, payloads in payload_sets.items():
        for payload in payloads:
            for param_name in injection_param_names:
                params = dict(existing_params)
                params[param_name] = payload

                # Ensure we have a full URL
                full_url = base
                if full_url.startswith("/"):
                    full_url = f"http://localhost{full_url}"
                full_url = _build_url_with_params(full_url, params)

                headers = dict(DEFAULT_HEADERS)

                requests.append(
                    InjectionRequest(
                        endpoint=endpoint,
                        vulnerability_type=vulnerability_type,
                        payload=payload,
                        url=full_url,
                        method="GET",
                        params=params,
                        json_body=None,
                        form_data=None,
                        headers=headers,
                    )
                )

                # Header injection variant
                if inject_headers:
                    for header_name in _HEADER_INJECTION_TARGETS:
                        hdr = dict(DEFAULT_HEADERS)
                        hdr[header_name] = payload
                        requests.append(
                            InjectionRequest(
                                endpoint=endpoint,
                                vulnerability_type=vulnerability_type,
                                payload=payload,
                                url=_build_url_with_params(base if not base.startswith("/") else f"http://localhost{base}", existing_params),
                                method="GET",
                                params=existing_params,
                                json_body=None,
                                form_data=None,
                                headers=hdr,
                            )
                        )

    return requests


def build_form_injection_requests(
    form: dict,
    payload_sets: dict[str, list[str]],
) -> list[InjectionRequest]:
    """Build injection requests by injecting payloads into HTML form fields."""
    action = form.get("action", "")
    method = (form.get("method") or "GET").upper()
    fields: list[str] = form.get("fields") or []

    if not action or not fields:
        return []

    requests: list[InjectionRequest] = []

    # Default safe values for all fields
    safe_values = {f: "test" for f in fields}

    for vulnerability_type, payloads in payload_sets.items():
        for payload in payloads:
            for target_field in fields:
                injected_data = dict(safe_values)
                injected_data[target_field] = payload

                if method == "POST":
                    requests.append(
                        InjectionRequest(
                            endpoint=action,
                            vulnerability_type=vulnerability_type,
                            payload=payload,
                            url=action,
                            method="POST",
                            params={},
                            json_body=None,
                            form_data=injected_data,
                            headers=dict(DEFAULT_HEADERS),
                        )
                    )
                else:
                    # GET form — append injected fields as query params
                    parsed = urlparse(action)
                    query = urlencode(sorted(injected_data.items()))
                    get_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))
                    requests.append(
                        InjectionRequest(
                            endpoint=action,
                            vulnerability_type=vulnerability_type,
                            payload=payload,
                            url=get_url,
                            method="GET",
                            params=injected_data,
                            json_body=None,
                            form_data=None,
                            headers=dict(DEFAULT_HEADERS),
                        )
                    )

    return requests
