from __future__ import annotations

import re


# ---------------------------------------------------------------------------
# SQL / Database error signatures
# ---------------------------------------------------------------------------

SQL_ERROR_PATTERNS: list[re.Pattern[str]] = [
    # MySQL-specific (highest priority — testphp.vulnweb.com)
    re.compile(r"You have an error in your SQL syntax", re.IGNORECASE),
    re.compile(r"check the manual that corresponds to your MySQL", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"mysql_num_rows", re.IGNORECASE),
    re.compile(r"mysql_query", re.IGNORECASE),
    re.compile(r"mysql_result", re.IGNORECASE),
    re.compile(r"Warning.*mysqli?", re.IGNORECASE),
    re.compile(r"Warning.*mysql_", re.IGNORECASE),
    re.compile(r"supplied\s+argument\s+is\s+not\s+a\s+valid\s+mysql", re.IGNORECASE),
    re.compile(r"com\.mysql\.jdbc", re.IGNORECASE),
    # Generic SQL
    re.compile(r"sql\s+syntax", re.IGNORECASE),
    re.compile(r"unclosed\s+quotation\s+mark", re.IGNORECASE),
    re.compile(r"quoted\s+string\s+not\s+properly\s+terminated", re.IGNORECASE),
    re.compile(r"Incorrect syntax near", re.IGNORECASE),
    re.compile(r"unexpected end of SQL command", re.IGNORECASE),
    re.compile(r"SQLSyntaxErrorException", re.IGNORECASE),
    re.compile(r"Syntax error.*in query expression", re.IGNORECASE),
    re.compile(r"division\s+by\s+zero", re.IGNORECASE),
    re.compile(r"invalid\s+column\s+name", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    # Oracle
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    # PostgreSQL
    re.compile(r"postgresql\s+error", re.IGNORECASE),
    re.compile(r"org\.hibernate\.QueryException", re.IGNORECASE),
    # SQLite
    re.compile(r"sqlite\s+error", re.IGNORECASE),
    re.compile(r"sqliteexception", re.IGNORECASE),
    # MSSQL
    re.compile(r"sql\s+server.*driver", re.IGNORECASE),
    re.compile(r"Microsoft.*ODBC.*Driver", re.IGNORECASE),
    re.compile(r"\[Microsoft\]\[ODBC", re.IGNORECASE),
    # Java/Hibernate
    re.compile(r"DB2 SQL error", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# File Inclusion / Path Traversal artifacts
# ---------------------------------------------------------------------------

LFI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"root:x:0:0", re.IGNORECASE),
    re.compile(r"root:.*:0:0:", re.IGNORECASE),
    re.compile(r"/etc/passwd", re.IGNORECASE),
    re.compile(r"daemon:.*:/sbin", re.IGNORECASE),
    re.compile(r"\[boot\s+loader\]", re.IGNORECASE),
    re.compile(r"windows\s+directory", re.IGNORECASE),
    re.compile(r"win\.ini", re.IGNORECASE),
    re.compile(r"\[fonts\]", re.IGNORECASE),
    re.compile(r"for\s+16-bit\s+app\s+support", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# SSRF / Internal resource patterns
# ---------------------------------------------------------------------------

SSRF_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"169\.254\.169\.254", re.IGNORECASE),
    re.compile(r"ami-id", re.IGNORECASE),
    re.compile(r"iam.*security-credentials", re.IGNORECASE),
    re.compile(r"latest/meta-data", re.IGNORECASE),
    re.compile(r"computeMetadata", re.IGNORECASE),
    re.compile(r"opc-request-id", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Command Injection artifacts
# ---------------------------------------------------------------------------

CMDI_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"uid=\d+\(", re.IGNORECASE),
    re.compile(r"gid=\d+\(", re.IGNORECASE),
    re.compile(r"root\s+\d+\s+\d+", re.IGNORECASE),
    re.compile(r"sh:\s+\d+:", re.IGNORECASE),
    re.compile(r"command\s+not\s+found", re.IGNORECASE),
    re.compile(r"/usr/bin", re.IGNORECASE),
    re.compile(r"Microsoft\s+Windows\s+\[Version", re.IGNORECASE),
    re.compile(r"\(c\).*Microsoft", re.IGNORECASE),
]

# ---------------------------------------------------------------------------
# Information Disclosure
# ---------------------------------------------------------------------------

INFO_DISCLOSURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"phpinfo\(\)", re.IGNORECASE),
    re.compile(r"PHP\s+Version\s+\d+\.\d+", re.IGNORECASE),
    re.compile(r"stack\s+trace", re.IGNORECASE),
    re.compile(r"traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
    re.compile(r"exception\s+in\s+thread\s+.main.", re.IGNORECASE),
    re.compile(r"secret_key\s*=", re.IGNORECASE),
    re.compile(r"password\s*=\s*['\"]", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*=", re.IGNORECASE),
]


def _first_match(patterns: list[re.Pattern[str]], body: str) -> re.Match[str] | None:
    for p in patterns:
        m = p.search(body)
        if m:
            return m
    return None


def match_sql_errors(body: str) -> re.Match[str] | None:
    return _first_match(SQL_ERROR_PATTERNS, body)


def match_lfi_patterns(body: str) -> re.Match[str] | None:
    return _first_match(LFI_PATTERNS, body)


def match_ssrf_patterns(body: str) -> re.Match[str] | None:
    return _first_match(SSRF_PATTERNS, body)


def match_cmdi_patterns(body: str) -> re.Match[str] | None:
    return _first_match(CMDI_PATTERNS, body)


def match_info_disclosure(body: str) -> re.Match[str] | None:
    return _first_match(INFO_DISCLOSURE_PATTERNS, body)


def extract_evidence(m: re.Match[str], body: str, context: int = 120) -> str:
    """Return a body snippet centred on the match, for use as evidence."""
    start = max(0, m.start() - context)
    end = min(len(body), m.end() + context)
    return body[start:end].strip()
