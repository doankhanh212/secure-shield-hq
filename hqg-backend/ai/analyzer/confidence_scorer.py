"""
Deterministic confidence scorer for vulnerability findings.
Inputs: detection_method + evidence string from finding dict.
Output: float 0.0–1.0 + human label.
"""
from __future__ import annotations

import re

# Regex to pull timing delta from time_analyzer evidence format:
# "Response time: Xs | Baseline: Ys | Delta: Zs"
_DELTA_RE = re.compile(r"Delta:\s*([\d.]+)s", re.IGNORECASE)

# SQL error keywords that indicate a high-quality evidence snippet
_SQL_SYNTAX_KEYWORDS = (
    "you have an error in your sql syntax",
    "unclosed quotation mark",
    "ora-",
    "sqlite error",
    "sqlsyntaxerrorexception",
    "pg_query",
    "mysql_fetch",
    "incorrect syntax near",
)


def calculate_confidence(finding_dict: dict) -> float:
    """
    Return a confidence score in [0.0, 1.0] based on detection evidence.

    Scoring rules (ordered, first match wins):
    - error_pattern + sqli:    SQL syntax error in evidence  → 0.85
                               other DB error               → 0.50
    - reflection + xss:        payload exact in evidence    → 0.90
                               only marker match            → 0.40
    - time_based (any):        delta > 10s                  → 0.85
                               delta 5–10s                  → 0.60
                               delta 3–5s                   → 0.35
    - lfi_pattern:             "root:x:0:0" in evidence     → 0.95
                               other LFI match              → 0.70
    - diff:                    always                       → 0.30
    - default fallback:                                      → 0.50
    """
    detection_method = str(finding_dict.get("detection_method", "")).lower()
    vuln_type = str(finding_dict.get("vulnerability_type", "")).lower()
    evidence = str(finding_dict.get("evidence", "")).lower()
    payload = str(finding_dict.get("payload", "")).lower()

    # --- Error pattern (SQL) ------------------------------------------------
    if detection_method == "error_pattern" and vuln_type in {"sqli", "time_based_sqli"}:
        for kw in _SQL_SYNTAX_KEYWORDS:
            if kw in evidence:
                return 0.85
        return 0.50

    # --- Reflection (XSS) ---------------------------------------------------
    if detection_method == "reflection" and vuln_type in {"xss", "xss_stored"}:
        if payload and payload in evidence:
            return 0.90
        return 0.40

    # --- Time-based ---------------------------------------------------------
    if detection_method == "time_based":
        m = _DELTA_RE.search(finding_dict.get("evidence", ""))
        if m:
            try:
                delta = float(m.group(1))
                if delta > 10.0:
                    return 0.85
                if delta >= 5.0:
                    return 0.60
                return 0.35
            except ValueError:
                pass
        # Fallback if evidence string not parseable
        return 0.50

    # --- LFI pattern --------------------------------------------------------
    if detection_method == "lfi_pattern":
        if "root:x:0:0" in evidence:
            return 0.95
        return 0.70

    # --- Diff-based ---------------------------------------------------------
    if detection_method == "diff":
        return 0.30

    # --- Default ------------------------------------------------------------
    return 0.50


def confidence_label(score: float) -> str:
    """
    Map confidence score to human-readable label.

    >= 0.7  → "Confirmed"
    0.4–0.7 → "Likely"
    < 0.4   → "Potential"
    """
    if score >= 0.7:
        return "Confirmed"
    if score >= 0.4:
        return "Likely"
    return "Potential"
