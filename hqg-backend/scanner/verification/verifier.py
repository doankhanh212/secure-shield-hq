"""Verification layer for vulnerability findings.

Converts single-signal detections into multi-step verified reports with
explicit confidence levels and traceable evidence.

Primary interface for the pipeline::

    from scanner.verification.verifier import verify_findings_async
    all_findings = await verify_findings_async(all_findings)

Synchronous single-finding interface (for external callers)::

    from scanner.verification.verifier import verify_finding
    updated = verify_finding(finding, request_func=None)
"""
from __future__ import annotations

import asyncio
import logging
from typing import Callable

import httpx

from scanner.verification.strategies import (
    verify_cmdi,
    verify_sqli,
    verify_ssrf,
    verify_xss,
)

logger = logging.getLogger(__name__)

# Maps vulnerability_type (lowercase) → async verification strategy
_STRATEGY_MAP: dict[str, Callable] = {
    "sqli": verify_sqli,
    "time_based_sqli": verify_sqli,
    "xss": verify_xss,
    "cmdi": verify_cmdi,
    "time_based_cmdi": verify_cmdi,
    "ssrf": verify_ssrf,
}

# Normalise confidence from the detection engine (mixed-case) to lowercase
_NORMALISE: dict[str, str] = {
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "confirmed": "confirmed",
}


def _normalise_confidence(raw: str) -> str:
    """Return lowercase confidence string, defaulting to 'medium'."""
    return _NORMALISE.get(raw, "medium")


async def _verify_one(finding: dict, client: httpx.AsyncClient) -> dict:
    """Run the appropriate strategy for *finding*.

    Always returns a dict.  On error, the original finding is returned with
    the confidence normalised and ``verified=False``.
    """
    vuln_type = str(finding.get("vulnerability_type", "")).lower()
    strategy = _STRATEGY_MAP.get(vuln_type)
    existing_conf = _normalise_confidence(str(finding.get("confidence", "medium")))

    if strategy is None:
        # No verification strategy for this type — pass through with normalised confidence
        return {
            **finding,
            "confidence": existing_conf,
            "verification_steps": [],
            "verified": False,
        }

    try:
        verified, new_confidence, steps = await strategy(finding, client)
        return {
            **finding,
            "confidence": new_confidence,
            "verification_steps": steps,
            "verified": verified,
        }
    except Exception as exc:
        logger.debug(
            "verify_one error [%s endpoint=%s]: %s",
            vuln_type,
            finding.get("endpoint"),
            exc,
        )
        return {
            **finding,
            "confidence": existing_conf,
            "verification_steps": [f"Verification error: {exc}"],
            "verified": False,
        }


async def verify_findings_async(findings: list[dict]) -> list[dict]:
    """Verify all findings concurrently using a shared HTTP client.

    A single ``httpx.AsyncClient`` is used so keep-alive connections are
    reused across probes.  All strategies run concurrently; the result list
    preserves input order.

    Args:
        findings:  Raw finding dicts produced by the detection engine.

    Returns:
        Updated finding dicts with ``confidence``, ``verification_steps``,
        and ``verified`` fields set.
    """
    if not findings:
        return findings

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=httpx.Timeout(8.0),
        verify=False,
    ) as client:
        tasks = [_verify_one(f, client) for f in findings]
        results: list[dict] = list(await asyncio.gather(*tasks))

    verified_count = sum(1 for r in results if r.get("verified"))
    logger.info(
        "verification: %d/%d findings verified",
        verified_count,
        len(results),
    )
    return results


def verify_finding(finding: dict, request_func: Callable | None = None) -> dict:
    """Synchronous single-finding interface.

    *request_func* is accepted for API compatibility but the function creates
    its own internal httpx client for the verification probes.

    Args:
        finding:       Raw finding dict from the detection engine.
        request_func:  Accepted but unused (reserved for future callers that
                       pass a custom transport).

    Returns:
        Updated finding dict with ``confidence``, ``verification_steps``, and
        ``verified`` fields set.
    """
    return asyncio.run(verify_findings_async([finding]))[0]
