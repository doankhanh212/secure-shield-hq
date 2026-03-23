from __future__ import annotations

import asyncio
import re
from pathlib import Path
from urllib.parse import urlparse

import dns.asyncresolver
import httpx

WORDLIST_PATH = Path(__file__).parent / "wordlists" / "subdomains.txt"
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9.-]+$")


def extract_domain(target: str) -> str:
    candidate = target.strip()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or candidate
    return candidate.strip().lower().strip(".")


def _load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        return []
    rows = path.read_text(encoding="utf-8").splitlines()
    return [row.strip() for row in rows if row.strip() and not row.startswith("#")]


async def _resolves_host(resolver: dns.asyncresolver.Resolver, host: str) -> bool:
    for record_type in ("A", "AAAA", "CNAME"):
        try:
            await resolver.resolve(host, record_type, lifetime=4.0)
            return True
        except Exception:
            continue
    return False


async def discover_wordlist_subdomains(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
    wordlist_path: Path = WORDLIST_PATH,
    concurrency: int = 100,
) -> set[str]:
    words = _load_wordlist(wordlist_path)
    semaphore = asyncio.Semaphore(concurrency)

    async def check(word: str) -> str | None:
        host = f"{word}.{domain}".lower()
        async with semaphore:
            if await _resolves_host(resolver, host):
                return host
        return None

    results = await asyncio.gather(*(check(word) for word in words), return_exceptions=True)
    discovered = {item for item in results if isinstance(item, str)}
    return discovered


async def discover_ct_log_subdomains(domain: str, client: httpx.AsyncClient) -> set[str]:
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}

    try:
        response = await client.get(url, params=params)
        response.raise_for_status()
        rows = response.json()
    except Exception:
        return set()

    discovered: set[str] = set()
    for row in rows:
        name_value = str(row.get("name_value", ""))
        for raw_host in name_value.splitlines():
            host = raw_host.replace("*.", "").strip().lower().strip(".")
            if host.endswith(f".{domain}") and DOMAIN_PATTERN.match(host):
                discovered.add(host)
    return discovered


async def discover_dns_record_subdomains(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> set[str]:
    discovered: set[str] = set()

    for record_type in ("NS", "MX"):
        try:
            answers = await resolver.resolve(domain, record_type, lifetime=5.0)
        except Exception:
            continue

        for answer in answers:
            value = answer.to_text().strip().rstrip(".").lower()
            parts = value.split()
            host = parts[-1] if parts else value
            if host.endswith(f".{domain}"):
                discovered.add(host)

    try:
        txt_answers = await resolver.resolve(domain, "TXT", lifetime=5.0)
        for answer in txt_answers:
            txt = answer.to_text().strip().strip('"')
            matches = re.findall(r"([a-zA-Z0-9-]+\.%s)" % re.escape(domain), txt)
            for match in matches:
                discovered.add(match.lower())
    except Exception:
        pass

    return discovered


async def discover_subdomains(
    target: str,
    resolver: dns.asyncresolver.Resolver,
    client: httpx.AsyncClient,
) -> set[str]:
    domain = extract_domain(target)
    brute_force, ct_logs, dns_records = await asyncio.gather(
        discover_wordlist_subdomains(domain, resolver),
        discover_ct_log_subdomains(domain, client),
        discover_dns_record_subdomains(domain, resolver),
    )
    return brute_force | ct_logs | dns_records
