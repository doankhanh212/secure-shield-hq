from __future__ import annotations

from scanner.asset_discovery.models import ServiceProbeResult


def _from_headers(headers: dict[str, str]) -> set[str]:
    detected: set[str] = set()

    server = headers.get("server", "").lower()
    powered_by = headers.get("x-powered-by", "").lower()

    if "nginx" in server:
        detected.add("nginx")
    if "apache" in server:
        detected.add("apache")
    if "express" in powered_by:
        detected.add("express")
    if "django" in powered_by:
        detected.add("django")
    if "laravel" in powered_by:
        detected.add("laravel")
    if "next.js" in powered_by or "nextjs" in powered_by:
        detected.add("next.js")

    set_cookie = headers.get("set-cookie", "").lower()
    if "laravel_session" in set_cookie:
        detected.add("laravel")
    if "csrftoken" in set_cookie:
        detected.add("django")

    return detected


def _from_body(body: str) -> set[str]:
    text = body.lower()
    detected: set[str] = set()

    if "data-reactroot" in text or "react" in text and "__next" not in text:
        detected.add("react")
    if "__next_data__" in text or "_next/static" in text:
        detected.add("next.js")
    if "django" in text and "csrfmiddlewaretoken" in text:
        detected.add("django")
    if "laravel" in text or "laravel_session" in text:
        detected.add("laravel")

    return detected


def detect_technologies(results: list[ServiceProbeResult]) -> set[str]:
    technologies: set[str] = set()
    for result in results:
        if result.status_code is None:
            continue
        technologies |= _from_headers(result.headers)
        if result.body_snippet:
            technologies |= _from_body(result.body_snippet)
    return technologies
