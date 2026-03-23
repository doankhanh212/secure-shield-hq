from __future__ import annotations

# ---------------------------------------------------------------------------
# OWASP / CWE / Severity mapping tables
#
# These intentionally duplicate the detection_engine maps so the AI module
# can run independently and override / extend mappings without coupling.
# ---------------------------------------------------------------------------

OWASP_MAP: dict[str, str] = {
    "sqli":            "A03:2021 Injection",
    "xss":             "A03:2021 Injection",
    "ssrf":            "A10:2021 SSRF",
    "cmdi":            "A03:2021 Injection",
    "lfi":             "A01:2021 Broken Access Control",
    "path_traversal":  "A01:2021 Broken Access Control",
    "info_disclosure": "A02:2021 Cryptographic Failures",
    "time_based_sqli": "A03:2021 Injection",
    "time_based_cmdi": "A03:2021 Injection",
}

CWE_MAP: dict[str, str] = {
    "sqli":            "CWE-89",
    "xss":             "CWE-79",
    "ssrf":            "CWE-918",
    "cmdi":            "CWE-78",
    "lfi":             "CWE-98",
    "path_traversal":  "CWE-22",
    "info_disclosure": "CWE-200",
    "time_based_sqli": "CWE-89",
    "time_based_cmdi": "CWE-78",
}

SEVERITY_MAP: dict[str, str] = {
    "sqli":            "Critical",
    "xss":             "High",
    "ssrf":            "High",
    "cmdi":            "Critical",
    "lfi":             "High",
    "path_traversal":  "High",
    "info_disclosure": "Medium",
    "time_based_sqli": "Critical",
    "time_based_cmdi": "Critical",
}

VULN_DISPLAY_NAME: dict[str, str] = {
    "sqli":            "SQL Injection",
    "xss":             "Cross-Site Scripting (XSS)",
    "ssrf":            "Server-Side Request Forgery",
    "cmdi":            "Command Injection",
    "lfi":             "Local File Inclusion",
    "path_traversal":  "Path Traversal",
    "info_disclosure": "Information Disclosure",
    "time_based_sqli": "Time-Based SQL Injection",
    "time_based_cmdi": "Time-Based Command Injection",
}


def map_owasp(vulnerability_type: str) -> str:
    return OWASP_MAP.get(vulnerability_type, "Unknown")


def map_cwe(vulnerability_type: str) -> str:
    return CWE_MAP.get(vulnerability_type, "CWE-0")


def map_severity(vulnerability_type: str) -> str:
    return SEVERITY_MAP.get(vulnerability_type, "Medium")


def map_display_name(vulnerability_type: str) -> str:
    return VULN_DISPLAY_NAME.get(vulnerability_type, vulnerability_type)
