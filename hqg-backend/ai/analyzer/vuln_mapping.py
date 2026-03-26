"""
Vulnerability → OWASP / CWE / CVSS mapping table.
Pure data, zero dependencies, zero network calls.
"""
from __future__ import annotations

from typing import TypedDict


class VulnMappingEntry(TypedDict):
    owasp: str            # e.g. "A03:2021-Injection"
    cwe_id: str           # e.g. "CWE-89"
    cwe_name: str         # human-readable CWE name
    cvss_vector: str      # CVSS v3.1 vector string
    cvss_score: float     # base score


VULN_MAPPING: dict[str, VulnMappingEntry] = {
    "sqli": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
    },
    "time_based_sqli": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
    },
    "xss": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation (XSS)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1,
    },
    "xss_stored": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation (Stored XSS)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 5.4,
    },
    "cmdi": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cvss_score": 9.8,
    },
    "time_based_cmdi": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-78",
        "cwe_name": "Improper Neutralization of Special Elements used in an OS Command",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
    },
    "ssrf": {
        "owasp": "A10:2021-SSRF",
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery (SSRF)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cvss_score": 8.6,
    },
    "lfi": {
        "owasp": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
    },
    "path_traversal": {
        "owasp": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-22",
        "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
    },
    "info_disclosure": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-200",
        "cwe_name": "Exposure of Sensitive Information to an Unauthorized Actor",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cvss_score": 5.3,
    },
    "open_redirect": {
        "owasp": "A01:2021-Broken Access Control",
        "cwe_id": "CWE-601",
        "cwe_name": "URL Redirection to Untrusted Site (Open Redirect)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 6.1,
    },
    "cors_misconfiguration": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-942",
        "cwe_name": "Permissive Cross-domain Policy with Untrusted Domains",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        "cvss_score": 6.5,
    },
    "xxe": {
        "owasp": "A05:2021-Security Misconfiguration",
        "cwe_id": "CWE-611",
        "cwe_name": "Improper Restriction of XML External Entity Reference",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cvss_score": 7.5,
    },
    "crlf_injection": {
        "owasp": "A03:2021-Injection",
        "cwe_id": "CWE-93",
        "cwe_name": "Improper Neutralization of CRLF Sequences (CRLF Injection)",
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cvss_score": 4.7,
    },
}

_UNKNOWN_ENTRY: VulnMappingEntry = {
    "owasp": "Unknown",
    "cwe_id": "CWE-0",
    "cwe_name": "Unknown Vulnerability",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    "cvss_score": 0.0,
}


def lookup(vuln_type: str) -> VulnMappingEntry:
    """Return mapping entry for vuln_type, or a safe default for unknowns."""
    return VULN_MAPPING.get(vuln_type.lower().strip(), _UNKNOWN_ENTRY)
