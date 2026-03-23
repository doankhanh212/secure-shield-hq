"""Matcher engine — evaluates template matchers against HTTP responses."""
from __future__ import annotations

import re

from scanner.template_engine.models import TemplateMatcher


def evaluate_matcher(
    matcher: TemplateMatcher,
    *,
    body: str,
    headers: dict[str, str],
    status_code: int | None,
    response_time: float,
) -> tuple[bool, str]:
    """Evaluate a single matcher and return (matched, evidence_snippet)."""
    hit = False
    evidence = ""

    if matcher.type == "word":
        target = _get_part(matcher.part, body=body, headers=headers)
        if matcher.value in target:
            hit = True
            idx = target.find(matcher.value)
            start = max(0, idx - 80)
            end = min(len(target), idx + len(matcher.value) + 80)
            evidence = target[start:end]

    elif matcher.type == "regex":
        target = _get_part(matcher.part, body=body, headers=headers)
        m = re.search(matcher.value, target, re.IGNORECASE)
        if m:
            hit = True
            start = max(0, m.start() - 60)
            end = min(len(target), m.end() + 60)
            evidence = target[start:end]

    elif matcher.type == "status":
        try:
            expected = int(matcher.value)
            if status_code == expected:
                hit = True
                evidence = f"HTTP {status_code}"
        except ValueError:
            pass

    elif matcher.type == "time":
        try:
            threshold = float(matcher.value)
            if response_time >= threshold:
                hit = True
                evidence = f"Response time {response_time:.2f}s >= {threshold}s"
        except ValueError:
            pass

    # Respect negative matchers
    if matcher.negative:
        hit = not hit
        if hit:
            evidence = f"[negative] {evidence}" if evidence else "[negative match]"

    return hit, evidence


def evaluate_matchers(
    matchers: list[TemplateMatcher],
    *,
    body: str,
    headers: dict[str, str],
    status_code: int | None,
    response_time: float,
    condition: str = "or",
) -> tuple[bool, str]:
    """Evaluate all matchers with OR/AND logic.

    Returns (overall_match, combined_evidence).
    """
    if not matchers:
        return False, ""

    evidences: list[str] = []
    results: list[bool] = []

    for matcher in matchers:
        hit, ev = evaluate_matcher(
            matcher,
            body=body,
            headers=headers,
            status_code=status_code,
            response_time=response_time,
        )
        results.append(hit)
        if hit and ev:
            evidences.append(ev)

    if condition == "and":
        matched = all(results)
    else:
        matched = any(results)

    combined_evidence = " | ".join(evidences) if evidences else ""
    return matched, combined_evidence[:500]


def _get_part(part: str, *, body: str, headers: dict[str, str]) -> str:
    if part == "header":
        return "\n".join(f"{k}: {v}" for k, v in headers.items())
    return body  # default: body
