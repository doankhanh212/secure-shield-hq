from __future__ import annotations

import re
from urllib.parse import urlparse


_STATIC_EXTENSIONS = frozenset({
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".avi", ".webm", ".webp",
    ".pdf", ".zip", ".tar", ".gz",
    # Script / font extensions that should not be crawled as HTML pages
    ".js", ".ts", ".map", ".ttf", ".woff",
})

# Subdomain prefixes that suggest CDN / static-asset hosts; skip crawling them
_CDN_PREFIXES = frozenset({
    "cdn.", "static.", "assets.", "media.", "images.", "img.",
    "fonts.", "js.", "css.", "files.", "downloads.",
})

_API_PATTERNS = re.compile(
    r"/(api|v[0-9]+|rest|internal/api|graphql)",
    re.IGNORECASE,
)

_GRAPHQL_PATTERNS = re.compile(
    r"/graphql(/|$|\?)",
    re.IGNORECASE,
)


def extract_domain(target: str) -> str:
    parsed = urlparse(target)
    if parsed.hostname:
        return parsed.hostname.lower()
    return target.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]


def is_cdn_subdomain(hostname: str) -> bool:
    """Return True if *hostname* looks like a CDN or static-asset subdomain."""
    h = hostname.lower()
    return any(h.startswith(prefix) for prefix in _CDN_PREFIXES)


def is_in_scope(url: str, target_domain: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    base = target_domain.lower()
    in_domain = hostname == base or hostname.endswith(f".{base}")
    if not in_domain:
        return False
    # Skip CDN/static subdomains even when they share the same parent domain
    if hostname != base and is_cdn_subdomain(hostname):
        return False
    return True


def is_static_resource(url: str) -> bool:
    """Return True if *url* points to a static asset that should not be crawled."""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTENSIONS)


def is_api_endpoint(url: str) -> bool:
    """Return True if *url* looks like a REST API endpoint."""
    return bool(_API_PATTERNS.search(urlparse(url).path))


def is_graphql_endpoint(url: str) -> bool:
    """Return True if *url* looks like a GraphQL endpoint."""
    return bool(_GRAPHQL_PATTERNS.search(urlparse(url).path))
