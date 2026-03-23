from __future__ import annotations

import re
from urllib.parse import urljoin


PATTERNS = [
    re.compile(r"fetch\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"axios\.(?:get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"\.open\(\s*[\"'][A-Z]+[\"']\s*,\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"url\s*:\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    # Additional patterns for advanced JS route extraction
    re.compile(r"\$\.(?:get|post|ajax)\(\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"(?:path|route|endpoint|api_?url|baseURL|href)\s*[:=]\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"(?:window|document)\.location(?:\.href)?\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE),
    re.compile(r"(?:navigate|redirect|pushState|replaceState)\([^)]*[\"']([^\"']+)[\"']", re.IGNORECASE),
]

# Compiled once: extracts parameter names from URL-like strings e.g. /api?id=&name=
_PARAM_PATTERN = re.compile(r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)(?:=|&|$)")


def extract_js_endpoints(source: str, base_url: str) -> set[str]:
    endpoints: set[str] = set()
    for pattern in PATTERNS:
        for match in pattern.findall(source):
            endpoint = match.strip()
            if endpoint.startswith("data:") or endpoint.startswith("javascript:"):
                continue
            if not endpoint.startswith(("http://", "https://", "/")):
                # skip template literals, plain words, etc.
                if not endpoint.startswith("."):
                    continue
            endpoints.add(urljoin(base_url, endpoint))
    return endpoints


def extract_js_parameters(source: str) -> set[str]:
    """Extract parameter names from URL-like strings embedded in JS."""
    return set(_PARAM_PATTERN.findall(source))
