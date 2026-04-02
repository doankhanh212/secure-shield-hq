"""Vulnerability knowledge base.

Provides structured descriptions, impact statements, and remediation guidance
for every vulnerability type the detection engine can produce.  Used by the
enrichment layer to guarantee non-empty display fields in the frontend.

Key: vulnerability_type string from detection_engine/models.py (lowercase).
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Template structure
# ---------------------------------------------------------------------------
# Each entry MUST have:
#   description   (str)  — what the vulnerability is and how it was detected
#   impact        (str)  — concrete business / security consequences
#   remediation   (str)  — actionable developer guidance
#   owasp         (str)  — OWASP Top-10 reference
#   references    (list) — external links / standards
# ---------------------------------------------------------------------------

VULN_TEMPLATES: dict[str, dict[str, object]] = {

    # ── SQL Injection ────────────────────────────────────────────────────────
    "sqli": {
        "description": (
            "SQL Injection was detected by observing database error messages or "
            "anomalous query behaviour in response to crafted payloads injected "
            "into the vulnerable parameter. An attacker can manipulate the SQL "
            "query executed by the application's database layer, bypassing "
            "authentication or accessing arbitrary data."
        ),
        "impact": (
            "Full database read/write access including sensitive tables (users, "
            "credentials, PII). Authentication bypass allowing login as any user. "
            "Potential remote code execution via database features (xp_cmdshell, "
            "LOAD_FILE). Data exfiltration, modification, or deletion. Compliance "
            "violations (GDPR, PCI-DSS)."
        ),
        "remediation": (
            "Use parameterised queries (prepared statements) for ALL database "
            "interactions — never concatenate user input into SQL strings. "
            "Apply a Web Application Firewall (WAF) as a defence-in-depth layer. "
            "Enforce least-privilege database accounts (no DBA rights for the app "
            "user). Validate and sanitise all inputs server-side."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-89", "OWASP Testing Guide: OTG-INPVAL-005"],
    },

    # ── Time-Based SQL Injection ─────────────────────────────────────────────
    "time_based_sqli": {
        "description": (
            "A time-based blind SQL injection was detected. The application "
            "responded with a measurable delay (e.g., SLEEP / WAITFOR DELAY) "
            "only when a conditional SQL payload evaluated to TRUE, confirming "
            "that unsanitised input is passed directly to the database engine "
            "even though no error messages or data differences are visible."
        ),
        "impact": (
            "Blind data extraction character-by-character, enabling full database "
            "dump despite no visible error output. Authentication bypass and "
            "privilege escalation. In some database configurations, potential "
            "OS-level command execution. Data integrity risk from blind UPDATE/DELETE "
            "payloads."
        ),
        "remediation": (
            "Use parameterised queries / prepared statements for every database "
            "call. Never allow query structure to be influenced by user-supplied "
            "input. Apply network-level timeouts and query execution limits to "
            "reduce the impact of time-based probing. Audit all database calls "
            "for dynamic string concatenation."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-89", "OWASP Testing Guide: OTG-INPVAL-005"],
    },

    # ── Cross-Site Scripting ─────────────────────────────────────────────────
    "xss": {
        "description": (
            "Cross-Site Scripting (XSS) was detected by injecting a unique "
            "JavaScript marker into the vulnerable parameter and observing its "
            "unencoded reflection in the HTML response. An attacker can inject "
            "arbitrary scripts that execute in the browser of any user who views "
            "the affected page."
        ),
        "impact": (
            "Session hijacking via theft of authentication cookies. Credential "
            "phishing by injecting fake login forms. Redirection to malicious "
            "sites. Keylogging user input. Defacement of the application interface. "
            "Bypassing CSRF protections. Sensitive data leakage via DOM APIs."
        ),
        "remediation": (
            "Encode all user-supplied output using a context-aware encoding library "
            "(HTML-encode in HTML context, JS-encode in script context). Set the "
            "Content-Security-Policy (CSP) header to restrict script sources. "
            "Use HttpOnly and Secure flags on session cookies. Validate and reject "
            "input containing HTML/JS syntax at the server."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-79", "OWASP XSS Prevention Cheat Sheet"],
    },

    # ── Reflected XSS ────────────────────────────────────────────────────────
    "xss_reflected": {
        "description": (
            "Reflected Cross-Site Scripting was detected. The injected script "
            "payload was reflected in the HTTP response without encoding, meaning "
            "it is returned from the server in the same request. An attacker can "
            "deliver a crafted URL to victims causing the script to execute in "
            "their browser session."
        ),
        "impact": (
            "Session hijacking, credential theft, malicious redirects, and UI "
            "manipulation. Particularly effective via phishing links that embed "
            "the reflected XSS payload in a URL sent to targeted users."
        ),
        "remediation": (
            "Apply output encoding for all reflected user input. Implement a "
            "strict Content-Security-Policy. Mark cookies as HttpOnly. Validate "
            "URL parameters server-side and reject inputs containing script syntax."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-79", "OWASP XSS Prevention Cheat Sheet"],
    },

    # ── Stored XSS ───────────────────────────────────────────────────────────
    "xss_stored": {
        "description": (
            "Stored (persistent) Cross-Site Scripting was detected. The malicious "
            "script is saved to the application's data store and served to every "
            "user who views the affected page, making it the most dangerous XSS "
            "variant as no victim interaction beyond normal page load is required."
        ),
        "impact": (
            "Mass session hijacking affecting all users of the page. Persistent "
            "malware delivery, cryptomining injection, or keylogging for every "
            "visitor. Administrative account takeover if the stored payload fires "
            "on an admin panel."
        ),
        "remediation": (
            "Sanitise stored input using a trusted allowlist HTML library "
            "(e.g., DOMPurify) before persistence. Encode on output in all "
            "rendering contexts. Enforce strict CSP. Audit all stored fields for "
            "existing payloads and purge if found."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-79", "OWASP XSS Prevention Cheat Sheet"],
    },

    # ── Command Injection ────────────────────────────────────────────────────
    "cmdi": {
        "description": (
            "OS Command Injection was detected. The application passes user-supplied "
            "input to a system shell without adequate sanitisation, allowing an "
            "attacker to append arbitrary OS commands using shell metacharacters "
            "(e.g., ;, &&, |, $()). Command output was observed in the HTTP response."
        ),
        "impact": (
            "Full remote code execution on the server. Ability to read any file "
            "accessible to the application process (/etc/passwd, private keys, "
            "environment variables). Lateral movement to internal network hosts. "
            "Installation of backdoors, reverse shells, or ransomware. Complete "
            "host and application compromise."
        ),
        "remediation": (
            "Never pass user input to shell functions (system(), exec(), popen(), "
            "subprocess.call(shell=True)). Use language-native APIs with argument "
            "arrays that bypass the shell entirely. If shell is unavoidable, "
            "whitelist the exact characters allowed in the input. Run the application "
            "with the minimum OS permissions required."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-78", "OWASP OS Command Injection Defense Cheat Sheet"],
    },

    # ── Time-Based Command Injection ─────────────────────────────────────────
    "time_based_cmdi": {
        "description": (
            "A time-based blind OS Command Injection was detected. The application "
            "executes a sleep/ping command injected via a user-controlled parameter, "
            "causing a measurable response delay. This confirms command execution "
            "even when no output is visible in the response body."
        ),
        "impact": (
            "Remote code execution confirmed via out-of-band delay. Full server "
            "compromise, file system access, network pivoting, and persistent "
            "backdoor installation — all achievable despite the output-less nature "
            "of the injection channel."
        ),
        "remediation": (
            "Eliminate all shell invocations that include user-supplied data. "
            "Use argument-list subprocess APIs. Apply network-level egress "
            "filtering to limit data exfiltration channels. Implement application-"
            "level request timeouts to detect and alert on delay-based probing."
        ),
        "owasp": "A03:2021 Injection",
        "references": ["CWE-78", "OWASP OS Command Injection Defense Cheat Sheet"],
    },

    # ── Server-Side Request Forgery ──────────────────────────────────────────
    "ssrf": {
        "description": (
            "Server-Side Request Forgery (SSRF) was detected. The application "
            "fetches remote resources using a URL supplied by the attacker, "
            "allowing it to be used as a proxy to reach internal network addresses "
            "or cloud metadata endpoints that are not directly accessible from the "
            "internet."
        ),
        "impact": (
            "Access to internal services (databases, admin panels, message queues) "
            "behind the firewall. Retrieval of cloud instance metadata (AWS IMDSv1: "
            "http://169.254.169.254) including IAM credentials. Port scanning of "
            "the internal network using the server as a pivot. Potential RCE if "
            "an internal service is exploitable."
        ),
        "remediation": (
            "Implement an allowlist of permitted destination URLs/IPs. Block "
            "requests to RFC-1918 ranges (10/8, 172.16/12, 192.168/16) and "
            "link-local addresses (169.254/16). Disable redirects in the HTTP "
            "client used for outbound fetches. Require IMDSv2 (token-based) on "
            "cloud instances to block unauthenticated metadata access."
        ),
        "owasp": "A10:2021 Server-Side Request Forgery",
        "references": ["CWE-918", "OWASP SSRF Prevention Cheat Sheet"],
    },

    # ── Local File Inclusion ─────────────────────────────────────────────────
    "lfi": {
        "description": (
            "Local File Inclusion (LFI) was detected. The application includes "
            "files from the server's filesystem based on a user-controlled path "
            "parameter. Distinct content from system files (e.g., /etc/passwd, "
            "Windows boot.ini) was observed in the response, confirming arbitrary "
            "file read."
        ),
        "impact": (
            "Disclosure of sensitive configuration files (database credentials, "
            "API keys, private keys). Exposure of source code, logs, and user data. "
            "In PHP environments, LFI combined with log poisoning or /proc/self/fd "
            "can lead to Remote Code Execution. Information gathered may enable "
            "further targeted attacks."
        ),
        "remediation": (
            "Never use user input to construct filesystem paths. Maintain an "
            "explicit allowlist of permitted file identifiers and resolve to "
            "absolute paths server-side. Apply open_basedir restrictions (PHP). "
            "Ensure the application user has no read access to sensitive system "
            "files. Validate and reject path traversal sequences (../, %2e%2e)."
        ),
        "owasp": "A05:2021 Security Misconfiguration",
        "references": ["CWE-22", "OWASP Path Traversal"],
    },

    # ── Path Traversal ───────────────────────────────────────────────────────
    "path_traversal": {
        "description": (
            "Path Traversal was detected. By injecting directory traversal sequences "
            "(../), the application resolved a file path outside its intended web "
            "root, exposing arbitrary files on the server's filesystem. Successful "
            "traversal output was confirmed in the response."
        ),
        "impact": (
            "Arbitrary file read — attacker can access any file readable by the "
            "web server process. Targets include /etc/shadow, application config "
            "files, SSH private keys, and session stores. Combined with upload "
            "functionality, may enable remote code execution."
        ),
        "remediation": (
            "Canonicalise all file paths using the platform's path resolution "
            "function (realpath / Path.resolve) and verify the result starts "
            "with the expected base directory. Reject requests containing traversal "
            "sequences before path construction. Run the web server with the "
            "minimum filesystem permissions required."
        ),
        "owasp": "A05:2021 Security Misconfiguration",
        "references": ["CWE-22", "OWASP Path Traversal Cheat Sheet"],
    },

    # ── Information Disclosure ───────────────────────────────────────────────
    "info_disclosure": {
        "description": (
            "Information Disclosure was detected. The application leaked internal "
            "technical details — such as stack traces, version strings, internal "
            "IP addresses, debug output, or configuration values — in its HTTP "
            "response. This information aids attackers in fingerprinting the "
            "technology stack and crafting targeted exploits."
        ),
        "impact": (
            "Disclosure of technology versions enabling targeted CVE exploitation. "
            "Exposure of internal network topology or database schema. Leaked "
            "credentials or API keys in responses. Reduced attacker effort required "
            "for subsequent, more damaging attacks."
        ),
        "remediation": (
            "Disable detailed error pages and stack traces in production — use "
            "generic error messages. Remove Server, X-Powered-By, and X-AspNet-Version "
            "HTTP headers. Suppress debug output via environment-specific config. "
            "Audit API responses for fields that reveal internal implementation details."
        ),
        "owasp": "A02:2021 Cryptographic Failures",
        "references": ["CWE-200", "OWASP Error Handling Cheat Sheet"],
    },

    # ── Open Redirect ────────────────────────────────────────────────────────
    "open_redirect": {
        "description": (
            "An Open Redirect vulnerability was detected. The application accepts "
            "a user-supplied URL in a redirect parameter and forwards the user's "
            "browser to that destination without validation. This allows an "
            "attacker to craft trusted-looking links that redirect victims to "
            "malicious sites."
        ),
        "impact": (
            "Phishing campaigns leveraging the trusted domain reputation to steal "
            "credentials. OAuth token theft by redirecting authorisation callbacks. "
            "Malware distribution via drive-by-download redirects. Bypassing "
            "referrer-based access controls on downstream services."
        ),
        "remediation": (
            "Validate redirect destinations against an explicit allowlist of "
            "permitted URLs or domains. Avoid accepting full URLs in redirect "
            "parameters — prefer route identifiers that are resolved server-side. "
            "Warn users before external redirects. Implement SSRF-style URL "
            "validation to block redirection to private/internal addresses."
        ),
        "owasp": "A01:2021 Broken Access Control",
        "references": ["CWE-601", "OWASP Unvalidated Redirects and Forwards Cheat Sheet"],
    },
}

# ---------------------------------------------------------------------------
# Generic fallback template (used when vulnerability_type not in VULN_TEMPLATES)
# ---------------------------------------------------------------------------

_GENERIC_TEMPLATE: dict[str, object] = {
    "description": (
        "A security vulnerability was detected in the scanned endpoint. "
        "The detection engine identified anomalous application behaviour "
        "in response to crafted test payloads, indicating the presence of "
        "a security weakness that may be exploitable by an attacker."
    ),
    "impact": (
        "Depending on the nature of the vulnerability, potential impact includes "
        "unauthorised data access, authentication bypass, or further exploitation "
        "of the application or underlying infrastructure. Severity is rated based "
        "on the CVSS score assigned by the detection engine."
    ),
    "remediation": (
        "Review the affected endpoint and parameter for insufficient input "
        "validation or output encoding. Apply the principle of least privilege, "
        "ensure error messages do not leak internal details, and consider a "
        "Web Application Firewall as a defence-in-depth control. Conduct a "
        "targeted code review of the affected functionality."
    ),
    "owasp": "OWASP Top 10",
    "references": ["https://owasp.org/www-project-top-ten/"],
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_template(vulnerability_type: str) -> dict[str, object]:
    """Return the knowledge-base template for *vulnerability_type*.

    Falls back to a generic template if the type is not found.
    Always returns a dict with ``description``, ``impact``, and ``remediation``.
    """
    return VULN_TEMPLATES.get(vulnerability_type.lower(), _GENERIC_TEMPLATE)


def enrich_finding(finding: dict[str, object]) -> dict[str, object]:
    """Return a copy of *finding* with template-derived fields filled in.

    Only fills fields that are currently absent or empty so that values set
    by the AI analyser (or other upstream enrichers) are preserved.

    Fields populated from template (when missing/empty):
        explanation   ← template description
        impact        ← template impact
        remediation   ← template remediation
        owasp_category← template owasp  (also back-fills from ``owasp`` key)
        cwe_id        ← template references[0] when it starts with 'CWE-'

    Fields always preserved from the original finding:
        payload, evidence, verification_steps, confidence, severity, etc.
    """
    vuln_type = str(finding.get("vulnerability_type", "")).lower()
    tmpl = get_template(vuln_type)

    result = dict(finding)  # shallow copy — preserves all original fields

    # explanation / description
    if not result.get("explanation"):
        result["explanation"] = tmpl["description"]

    # impact
    if not result.get("impact"):
        result["impact"] = tmpl["impact"]

    # remediation  (also check alternate keys)
    if not result.get("remediation") and not result.get("fix_recommendation"):
        result["remediation"] = tmpl["remediation"]
    elif not result.get("remediation") and result.get("fix_recommendation"):
        result["remediation"] = result["fix_recommendation"]

    # owasp_category — prefer existing finding value, then template, then ``owasp`` key
    if not result.get("owasp_category"):
        if result.get("owasp"):
            result["owasp_category"] = result["owasp"]
        else:
            result["owasp_category"] = tmpl.get("owasp", "")

    # cwe_id — the detection engine already sets this via CWE_MAP, but fill from
    # template references as a last resort (e.g. for template-engine findings)
    if not result.get("cwe_id"):
        # Try the ``cwe`` key written by VulnerabilityFinding.to_dict()
        if result.get("cwe"):
            result["cwe_id"] = result["cwe"]
        else:
            refs: list = tmpl.get("references", [])  # type: ignore[assignment]
            cwe_refs = [r for r in refs if str(r).startswith("CWE-")]
            if cwe_refs:
                result["cwe_id"] = cwe_refs[0]

    # Normalise evidence: treat empty string as absent so the frontend shows
    # the payload-only Proof of Exploit block rather than an empty evidence box.
    # (No change to the actual evidence value — we just ensure the field exists.)
    if "evidence" not in result:
        result["evidence"] = ""

    return result
