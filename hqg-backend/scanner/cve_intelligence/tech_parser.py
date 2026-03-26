"""
Parse technology strings into (normalized_name, version) tuples.

Input formats handled:
  "Apache/2.4.49"     → ("apache httpd", "2.4.49")
  "PHP 7.4.3"         → ("php", "7.4.3")
  "nginx-1.21.0"      → ("nginx", "1.21.0")
  "jQuery v3.6.0"     → ("jquery", "3.6.0")
  "apache"            → ("apache httpd", "")   # bare name, no version
"""
from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Name normalization table (lowercase input → NVD search keyword)
# ---------------------------------------------------------------------------

TECH_NAME_NORMALIZE: dict[str, str] = {
    "apache": "apache httpd",
    "httpd": "apache httpd",
    "apache httpd": "apache httpd",
    "nginx": "nginx",
    "php": "php",
    "wordpress": "wordpress",
    "jquery": "jquery",
    "express": "express.js",
    "express.js": "express.js",
    "django": "django",
    "laravel": "laravel",
    "tomcat": "apache tomcat",
    "apache tomcat": "apache tomcat",
    "iis": "microsoft iis",
    "microsoft-iis": "microsoft iis",
    "microsoft iis": "microsoft iis",
    "flask": "flask",
    "spring": "spring framework",
    "spring framework": "spring framework",
    "next.js": "next.js",
    "nextjs": "next.js",
    "react": "react",
    "openssl": "openssl",
    "node.js": "node.js",
    "nodejs": "node.js",
}

# Matches: "Name/1.2.3" | "Name 1.2.3" | "Name-1.2.3" | "Name v1.2.3"
_PARSE_RE = re.compile(
    r"^([a-zA-Z][\w.\-]*?)"        # tech name (greedy up to separator)
    r"[\s/\-]+"                     # separator: space, slash, or dash
    r"v?(\d[\d.]*[\w.-]*)$",        # optional "v" then version
    re.IGNORECASE,
)

# Detect standalone version-looking string to avoid treating it as name
_VERSION_ONLY_RE = re.compile(r"^\d[\d.]+$")


def parse_technology(tech_string: str) -> tuple[str, str]:
    """
    Parse a single technology string into (normalized_name, version).

    Returns ("", "") when the string cannot be meaningfully parsed.
    """
    s = tech_string.strip()
    if not s:
        return "", ""

    # If it looks like a pure version number, skip it
    if _VERSION_ONLY_RE.match(s):
        return "", ""

    version = ""
    raw_name = s

    m = _PARSE_RE.match(s)
    if m:
        raw_name = m.group(1).strip()
        version = m.group(2).strip()

    # Normalize the name through the lookup table (case-insensitive)
    norm = TECH_NAME_NORMALIZE.get(raw_name.lower())
    if norm:
        return norm, version

    # Unknown name: if it has a version, still return it lowercased
    if version:
        return raw_name.lower(), version

    # Bare unknown name with no version
    name_lower = raw_name.lower()
    # Only return if it looks like a tech name (alphabetic, not a URL/path)
    if re.match(r"^[a-z][\w.\-]*$", name_lower) and len(name_lower) >= 2:
        return name_lower, ""

    return "", ""


def parse_all(technologies: list[str]) -> list[tuple[str, str]]:
    """
    Parse a list of technology strings. Filters empty results and deduplicates.

    Returns list of (normalized_name, version) tuples, ordered by name.
    """
    seen: set[tuple[str, str]] = set()
    result: list[tuple[str, str]] = []

    for tech in technologies:
        name, version = parse_technology(tech)
        if not name:
            continue
        key = (name, version)
        if key not in seen:
            seen.add(key)
            result.append(key)

    return sorted(result, key=lambda t: t[0])
