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
# Command Injection artifacts — TIERED approach
# ---------------------------------------------------------------------------
# Tier 1: Confirmed command output (confidence 0.85+)
# These patterns can ONLY appear as output of shell commands.

CMDI_CONFIRMED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"uid=\d+\([\w-]+\)\s+gid=\d+", re.IGNORECASE),     # output of `id`
    re.compile(r"root\s+\d+\s+\d+.*\d+:\d+", re.IGNORECASE),        # output of `ps`
    re.compile(r"(?:total\s+\d+\n)?[drwx-]{10}", re.IGNORECASE),     # output of `ls -la`
    re.compile(r"(?:Linux|Darwin)\s+\S+\s+\d+\.\d+", re.IGNORECASE), # output of `uname`
    re.compile(r"inet\s+\d+\.\d+\.\d+\.\d+", re.IGNORECASE),        # output of `ifconfig`/`ip`
]

# Tier 2: Possible command artifacts (confidence 0.5) — need additional validation
CMDI_POSSIBLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"sh:\s+\d+:\s+\w+:\s+not found", re.IGNORECASE),     # specific shell error
    re.compile(r"bash:\s+\w+:\s+command not found", re.IGNORECASE),   # specific bash error
    re.compile(r"uid=\d+\(", re.IGNORECASE),                          # partial `id` output
    re.compile(r"gid=\d+\(", re.IGNORECASE),                          # partial `id` output
]

# REMOVED (too generic, cause false positives):
# - "/usr/bin"               → appears in every Apache error page
# - "command not found"      → too generic, appears in docs/text
# - "Microsoft Windows [Version" → just a banner, not cmd output
# - "(c).*Microsoft"         → copyright notice, appears everywhere

# Response codes where CmdI detection should be SKIPPED entirely
CMDI_SKIP_RESPONSE_CODES = {404, 403, 405}

# ---------------------------------------------------------------------------
# Information Disclosure
# ---------------------------------------------------------------------------

# Positive patterns — things that indicate real info disclosure
INFO_DISCLOSURE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"phpinfo\(\)", re.IGNORECASE),
    re.compile(r"PHP\s+Version\s+\d+\.\d+", re.IGNORECASE),
    re.compile(r"Traceback\s+\(most\s+recent\s+call\s+last\)", re.IGNORECASE),
    re.compile(r"stack\s+trace", re.IGNORECASE),
    re.compile(r"exception\s+in\s+thread\s+.main.", re.IGNORECASE),
    re.compile(r"(?:DB_PASSWORD|SECRET_KEY|AWS_SECRET)\s*=\s*\S+", re.IGNORECASE),
    re.compile(r"(?:mysql|postgres|mongodb)://\w+:\w+@", re.IGNORECASE),
    re.compile(r"SELECT\s+\S+.*\bFROM\s+\S+.*\bWHERE\b", re.IGNORECASE),
    re.compile(r"secret_key\s*=", re.IGNORECASE),
    re.compile(r"password\s*=\s*['\"]", re.IGNORECASE),
    re.compile(r"api[_-]?key\s*=", re.IGNORECASE),
]

# Negative patterns — normal security mechanisms, NOT info disclosure
INFO_DISCLOSURE_NEGATIVE: list[re.Pattern[str]] = [
    re.compile(r"<input[^>]*type=['\"]hidden['\"][^>]*name=['\"].*token", re.IGNORECASE),
    re.compile(r"csrf[_-]?token", re.IGNORECASE),
    re.compile(r"<meta[^>]*name=['\"]csrf", re.IGNORECASE),
    re.compile(r"_token\s*=\s*['\"][a-f0-9]{32,}['\"]", re.IGNORECASE),
    re.compile(r"X-CSRF-Token", re.IGNORECASE),
    re.compile(r"__RequestVerificationToken", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Matching functions
# ---------------------------------------------------------------------------

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


def match_cmdi_confirmed(body: str) -> re.Match[str] | None:
    """Match only high-confidence command output patterns (Tier 1)."""
    return _first_match(CMDI_CONFIRMED_PATTERNS, body)


def match_cmdi_possible(body: str) -> re.Match[str] | None:
    """Match possible command output patterns (Tier 2) — needs additional validation."""
    return _first_match(CMDI_POSSIBLE_PATTERNS, body)


def match_cmdi_patterns(body: str) -> re.Match[str] | None:
    """Legacy wrapper: try confirmed first, then possible."""
    return match_cmdi_confirmed(body) or match_cmdi_possible(body)


def match_info_disclosure(body: str) -> re.Match[str] | None:
    """Match info disclosure patterns, excluding normal security tokens (CSRF etc.)."""
    m = _first_match(INFO_DISCLOSURE_PATTERNS, body)
    if not m:
        return None
    # Check if the matched area is actually a normal security mechanism
    context_start = max(0, m.start() - 100)
    context_end = min(len(body), m.end() + 100)
    context = body[context_start:context_end]
    for neg in INFO_DISCLOSURE_NEGATIVE:
        if neg.search(context):
            return None  # Normal security token, not real disclosure
    return m


def is_ssrf_payload(payload: str) -> bool:
    """Check if the payload contains an internal/cloud metadata URL."""
    internal_indicators = [
        "127.", "169.254.", "10.", "192.168.", "172.16.", "172.17.",
        "172.18.", "172.19.", "172.2", "172.3",
        "localhost", "0.0.0.0", "metadata.google", "169.254.169.254",
        "[::1]", "localtest.me",
    ]
    payload_lower = payload.lower()
    return any(ind in payload_lower for ind in internal_indicators)


def payload_matches_cmdi_output(payload: str, output: str) -> bool:
    """Check if the detected output is logically related to the injected payload."""
    payload_lower = payload.lower().strip()

    # Payload contains `id` command → output should contain "uid="
    if any(cmd in payload_lower for cmd in [";id", "|id", "`id`", "$(id)", "&&id"]):
        return "uid=" in output

    # Payload contains `whoami` → output should be a short username
    if "whoami" in payload_lower:
        return bool(re.match(r"^\w+$", output.strip()))

    # Payload contains `cat /etc/passwd` → output should contain "root:"
    if "/etc/passwd" in payload_lower:
        return "root:" in output

    # Payload contains `ls` → output should contain file listing format
    if any(cmd in payload_lower for cmd in [";ls", "|ls", "`ls`", "$(ls)"]):
        return bool(re.search(r"[drwx-]{10}", output))

    # Payload contains `uname` → output should contain kernel info
    if "uname" in payload_lower:
        return bool(re.search(r"(?:Linux|Darwin)", output))

    # Payload contains `ifconfig` or `ip addr` → output should contain inet
    if "ifconfig" in payload_lower or "ip addr" in payload_lower:
        return "inet" in output

    # Generic: any confirmed pattern match is OK for unknown commands
    return True


def extract_evidence(m: re.Match[str], body: str, context: int = 120) -> str:
    """Return a body snippet centred on the match, for use as evidence."""
    start = max(0, m.start() - context)
    end = min(len(body), m.end() + context)
    return body[start:end].strip()
