from __future__ import annotations

# ---------------------------------------------------------------------------
# AI client – explanation generator
#
# This module provides a local rule-based explanation engine that runs with
# zero external dependencies.  An optional LLM path is stubbed so a real
# provider (OpenAI, Anthropic, local model) can be wired in later without
# changing the public interface.
# ---------------------------------------------------------------------------

_EXPLANATION_TEMPLATES: dict[str, str] = {
    "sqli": (
        "The payload {payload!r} caused the server to return a database error "
        "at {endpoint}, indicating that user input reaches a SQL query without "
        "proper sanitisation."
    ),
    "time_based_sqli": (
        "A time-delay SQL payload sent to {endpoint} caused an abnormally slow "
        "response, which is a strong indicator that the injected SQL was "
        "executed by the database."
    ),
    "xss": (
        "The injected script payload was reflected verbatim in the response "
        "body at {endpoint}, suggesting the application does not escape "
        "user-controlled output."
    ),
    "ssrf": (
        "The server at {endpoint} attempted to fetch an internal resource "
        "specified by the payload, indicating a Server-Side Request Forgery "
        "vulnerability."
    ),
    "cmdi": (
        "The command injection payload triggered execution artifacts in the "
        "response from {endpoint}, indicating that OS commands are constructed "
        "from unsanitised input."
    ),
    "time_based_cmdi": (
        "A time-delay command injection payload sent to {endpoint} caused "
        "the server to respond significantly slower than the baseline, "
        "suggesting that the injected command was executed."
    ),
    "lfi": (
        "The payload caused the server at {endpoint} to disclose local file "
        "contents (e.g. /etc/passwd), indicating a Local File Inclusion "
        "vulnerability."
    ),
    "path_traversal": (
        "The path traversal payload allowed reading files outside the web "
        "root at {endpoint}, indicating improper input validation of "
        "file-path parameters."
    ),
    "info_disclosure": (
        "The server response at {endpoint} contained sensitive information "
        "such as stack traces, credentials, or internal configuration."
    ),
}


def generate_explanation(
    vulnerability_type: str,
    endpoint: str,
    payload: str,
) -> str:
    """Return a human-readable explanation for the given finding."""
    template = _EXPLANATION_TEMPLATES.get(vulnerability_type)
    if template:
        return template.format(endpoint=endpoint, payload=payload)
    return (
        f"A potential {vulnerability_type} vulnerability was detected at "
        f"{endpoint} using payload {payload!r}."
    )


async def generate_explanation_llm(
    vulnerability_type: str,
    endpoint: str,
    payload: str,
    evidence: str = "",
) -> str:
    """Placeholder for LLM-based explanation generation.

    Wire a real provider (e.g. OpenAI, Anthropic, local Llama) here.
    Falls back to the rule-based engine for now.
    """
    return generate_explanation(vulnerability_type, endpoint, payload)
