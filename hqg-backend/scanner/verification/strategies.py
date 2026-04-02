"""Per-vulnerability verification strategies.

Each strategy:
  • Makes at most 2–3 lightweight HTTP requests (no scanning).
  • Returns (verified: bool, confidence: str, steps: list[str]).
  • Never raises — all exceptions are caught by the caller.

Confidence levels (lowercase):
  confirmed → multiple consistent signals
  high      → strong single signal, verified
  medium    → partial or inconclusive signal
  low       → verification failed (e.g. marker was encoded/stripped)
"""
from __future__ import annotations

import logging
import random
import string
import time
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

logger = logging.getLogger(__name__)

# Minimum response-length difference required to call SQLi boolean verified
_SQLI_LENGTH_DIFF_THRESHOLD = 30

# Maximum response body retained for comparison
_MAX_BODY = 10_000

# Per-probe request timeout (seconds)
_PROBE_TIMEOUT = 6.0

# External reference host used for SSRF divergence check (IANA-assigned)
_SSRF_EXTERNAL = "http://example.com/"
_SSRF_INTERNAL = "http://127.0.0.1/"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _short_id() -> str:
    """Return an 8-character alphanumeric token suitable for use as a marker."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def _inject(endpoint: str, parameter: str, payload: str) -> str:
    """Return *endpoint* with *parameter* replaced by *payload* in the query string.

    If *parameter* is absent from the existing query, it is appended.
    If *parameter* is empty, the endpoint is returned unchanged.
    """
    if not parameter:
        return endpoint
    parsed = urlparse(endpoint)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[parameter] = [payload]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def _get(
    client: httpx.AsyncClient,
    url: str,
) -> tuple[int | None, str]:
    """Send a GET request; return (status_code, body) or (None, '') on error."""
    try:
        r = await client.get(url, timeout=_PROBE_TIMEOUT)
        return r.status_code, r.text[:_MAX_BODY]
    except Exception:
        return None, ""


# ---------------------------------------------------------------------------
# SQL Injection — boolean-based verification
# ---------------------------------------------------------------------------

_SQLI_TRUE_PAYLOAD = "' OR '1'='1"
_SQLI_FALSE_PAYLOAD = "' AND '1'='2"


async def verify_sqli(
    finding: dict,
    client: httpx.AsyncClient,
) -> tuple[bool, str, list[str]]:
    """Boolean-based SQLi check: TRUE condition vs FALSE condition.

    Confirmed when the server returns meaningfully different content for
    a tautology vs a contradiction injected into the same parameter.
    """
    endpoint = str(finding.get("endpoint", ""))
    parameter = str(finding.get("parameter", ""))
    steps: list[str] = []

    true_url = _inject(endpoint, parameter, _SQLI_TRUE_PAYLOAD)
    false_url = _inject(endpoint, parameter, _SQLI_FALSE_PAYLOAD)

    true_status, true_body = await _get(client, true_url)
    false_status, false_body = await _get(client, false_url)

    steps.append(
        f"TRUE probe ({_SQLI_TRUE_PAYLOAD!r}): status={true_status}, len={len(true_body)}"
    )
    steps.append(
        f"FALSE probe ({_SQLI_FALSE_PAYLOAD!r}): status={false_status}, len={len(false_body)}"
    )

    if true_status is None or false_status is None:
        steps.append("One or both probes failed — inconclusive")
        return False, "medium", steps

    len_diff = len(true_body) - len(false_body)
    steps.append(f"Response length difference: {len_diff} characters")

    if true_status != false_status:
        if len_diff > _SQLI_LENGTH_DIFF_THRESHOLD:
            steps.append("HTTP status AND body length both differ — confirmed boolean SQLi")
            return True, "confirmed", steps
        steps.append("HTTP status differs — strong boolean signal")
        return True, "high", steps

    if len_diff > _SQLI_LENGTH_DIFF_THRESHOLD * 3:
        steps.append("Large body length difference — confirmed boolean SQLi")
        return True, "confirmed", steps

    if len_diff > _SQLI_LENGTH_DIFF_THRESHOLD:
        steps.append("Moderate body length difference — likely boolean SQLi")
        return True, "high", steps

    steps.append("Responses too similar — boolean test inconclusive")
    return False, "medium", steps


# ---------------------------------------------------------------------------
# XSS — reflection verification
# ---------------------------------------------------------------------------

async def verify_xss(
    finding: dict,
    client: httpx.AsyncClient,
) -> tuple[bool, str, list[str]]:
    """Inject a unique marker and check for un-encoded reflection in the response.

    Distinguishes genuine reflection from HTML-encoded output to avoid
    false positives on sanitised responses.
    """
    endpoint = str(finding.get("endpoint", ""))
    parameter = str(finding.get("parameter", ""))
    steps: list[str] = []

    marker = f"HQGx{_short_id()}"
    xss_payload = f"<{marker}>"
    encoded_form = f"&lt;{marker}&gt;"

    url = _inject(endpoint, parameter, xss_payload)
    status, body = await _get(client, url)

    steps.append(
        f"Unique marker probe ({xss_payload!r}): status={status}, len={len(body)}"
    )

    if status is None:
        steps.append("Probe failed — inconclusive")
        return False, "medium", steps

    # Un-encoded reflection → XSS confirmed
    if xss_payload in body:
        steps.append("Marker reflected without HTML encoding — XSS confirmed")
        return True, "confirmed", steps

    # Marker present but tag stripped (WAF/sanitiser removed angle brackets)
    if marker in body:
        steps.append("Marker text reflected but tag brackets were stripped — high confidence")
        return True, "high", steps

    # HTML-encoded → server is properly escaping → likely false positive
    if encoded_form in body:
        steps.append("Marker was HTML-encoded — output is sanitised, not exploitable")
        return False, "low", steps

    steps.append("Marker not found in response — inconclusive")
    return False, "medium", steps


# ---------------------------------------------------------------------------
# Command Injection — output-based verification
# ---------------------------------------------------------------------------

async def verify_cmdi(
    finding: dict,
    client: httpx.AsyncClient,
) -> tuple[bool, str, list[str]]:
    """Inject echo-command probes and look for the unique marker in the response.

    Tries Unix (semicolon, pipe) and Windows (ampersand) separators in order;
    stops on the first positive match.
    """
    endpoint = str(finding.get("endpoint", ""))
    parameter = str(finding.get("parameter", ""))
    steps: list[str] = []

    marker = f"HQGcmd{_short_id()}"
    probes = [
        (f"; echo {marker}", "unix-semicolon"),
        (f"| echo {marker}", "unix-pipe"),
        (f"& echo {marker}", "windows-amp"),
    ]

    for payload, label in probes:
        url = _inject(endpoint, parameter, payload)
        status, body = await _get(client, url)
        steps.append(f"Command probe [{label}] ({payload!r}): status={status}")

        if status is None:
            steps.append(f"Probe [{label}] failed — skipping")
            continue

        if marker in body:
            steps.append(
                f"Command output {marker!r} found in response — command injection confirmed"
            )
            return True, "confirmed", steps

    steps.append(f"Marker {marker!r} not found in any probe — inconclusive")
    return False, "medium", steps


# ---------------------------------------------------------------------------
# SSRF — response divergence verification
# ---------------------------------------------------------------------------

async def verify_ssrf(
    finding: dict,
    client: httpx.AsyncClient,
) -> tuple[bool, str, list[str]]:
    """Compare server behaviour when the parameter is set to an internal vs
    external URL.

    A server that blindly forwards the URL will produce meaningfully different
    responses for loopback vs external destinations (different status codes,
    response bodies, or timing).  An unaffected server will return the same
    application error for both.
    """
    endpoint = str(finding.get("endpoint", ""))
    parameter = str(finding.get("parameter", ""))
    steps: list[str] = []

    internal_url = _inject(endpoint, parameter, _SSRF_INTERNAL)
    external_url = _inject(endpoint, parameter, _SSRF_EXTERNAL)

    t0 = time.monotonic()
    int_status, int_body = await _get(client, internal_url)
    int_elapsed = round(time.monotonic() - t0, 3)

    t0 = time.monotonic()
    ext_status, ext_body = await _get(client, external_url)
    ext_elapsed = round(time.monotonic() - t0, 3)

    steps.append(
        f"Internal probe ({_SSRF_INTERNAL!r}): "
        f"status={int_status}, len={len(int_body)}, time={int_elapsed}s"
    )
    steps.append(
        f"External probe ({_SSRF_EXTERNAL!r}): "
        f"status={ext_status}, len={len(ext_body)}, time={ext_elapsed}s"
    )

    if int_status is None and ext_status is None:
        steps.append("Both probes failed — inconclusive")
        return False, "medium", steps

    body_len_diff = abs(len(int_body) - len(ext_body))
    status_differs = int_status != ext_status

    if status_differs and body_len_diff > 50:
        steps.append(
            "HTTP status AND body content differ for internal vs external — SSRF confirmed"
        )
        return True, "confirmed", steps

    if status_differs:
        steps.append("HTTP status differs for internal vs external — strong SSRF signal")
        return True, "high", steps

    if body_len_diff > 200:
        steps.append(
            f"Body length difference {body_len_diff} chars — server likely made the request"
        )
        return True, "high", steps

    # Timing heuristic: loopback is much faster than an external round-trip
    if int_elapsed > 0 and ext_elapsed > 0 and int_elapsed < ext_elapsed * 0.25:
        steps.append(
            f"Internal request ({int_elapsed}s) much faster than external ({ext_elapsed}s) "
            "— potential SSRF (timing)"
        )
        return True, "medium", steps

    steps.append("Responses too similar for internal vs external — inconclusive")
    return False, "medium", steps
