from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse


DEFAULT_PORTS = {"http": 80, "https": 443}


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    if path != "/" and path.endswith("/"):
        return path.rstrip("/")
    return path


def normalize_url(raw_url: str, base_url: str | None = None) -> str | None:
    if not raw_url:
        return None

    absolute = urljoin(base_url or "", raw_url.strip())
    parsed = urlparse(absolute)

    if parsed.scheme not in {"http", "https"}:
        return None
    if not parsed.netloc:
        return None

    host = parsed.hostname.lower() if parsed.hostname else ""
    if not host:
        return None

    port = parsed.port
    if port and DEFAULT_PORTS.get(parsed.scheme) != port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = _normalize_path(parsed.path)

    query_pairs = sorted(parse_qsl(parsed.query, keep_blank_values=True))
    query = urlencode(query_pairs, doseq=True)

    return urlunparse((parsed.scheme, netloc, path, "", query, ""))


def endpoint_from_url(url: str) -> str:
    """Return a canonical endpoint key.

    The scheme + host are preserved so request_builder can construct the
    correct injection URL.  Parameter *values* are stripped (keys kept)
    to enable deduplication of e.g. /search.php?q=foo and /search.php?q=bar.
    """
    parsed = urlparse(url)

    # Build base URL: include scheme+netloc when available
    if parsed.netloc:
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    else:
        base = parsed.path or "/"

    if not parsed.query:
        return base

    keys = sorted({key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)})
    if not keys:
        return base

    suffix = "&".join(f"{key}=" for key in keys)
    return f"{base}?{suffix}"
