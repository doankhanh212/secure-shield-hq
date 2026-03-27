"""Attack Path Analysis — generate attack chain scenarios from findings."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from scanner.attack_surface.graph import AttackSurfaceGraph


@dataclass
class AttackStep:
    """One step in an attack chain."""
    order: int
    finding_id: str
    vuln_type: str
    endpoint: str
    parameter: str
    action: str
    outcome: str
    cvss_score: float = 0.0


@dataclass
class AttackPath:
    """A complete attack chain from entry to impact."""
    path_id: str = ""
    name: str = ""
    description: str = ""
    steps: list[AttackStep] = field(default_factory=list)
    total_impact: str = ""
    likelihood: str = ""
    priority: str = ""

    def to_dict(self) -> dict:
        return {
            "path_id": self.path_id,
            "name": self.name,
            "description": self.description,
            "steps": [vars(s) for s in self.steps],
            "total_impact": self.total_impact,
            "likelihood": self.likelihood,
            "priority": self.priority,
            "step_count": len(self.steps),
        }


CHAIN_TEMPLATES = [
    {
        "name": "Chiếm quyền qua XSS \u2192 Session Hijacking",
        "requires": ["xss"],
        "optional": ["info_disclosure"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng khai th\u00E1c l\u1ED7 h\u1ED5ng XSS \u0111\u1EC3 \u0111\u00E1nh c\u1EAFp session cookie "
            "c\u1EE7a ng\u01B0\u1EDDi d\u00F9ng/admin, sau \u0111\u00F3 s\u1EED d\u1EE5ng session b\u1ECB \u0111\u00E1nh c\u1EAFp \u0111\u1EC3 "
            "truy c\u1EADp \u1EE9ng d\u1EE5ng v\u1EDBi quy\u1EC1n c\u1EE7a n\u1EA1n nh\u00E2n."
        ),
        "steps_template": [
            {"action": "Craft URL ch\u1EE9a XSS payload v\u00E0 g\u1EEDi cho n\u1EA1n nh\u00E2n (phishing/social engineering)",
             "outcome": "N\u1EA1n nh\u00E2n click link, JavaScript \u0111\u1ED9c th\u1EF1c thi trong browser"},
            {"action": "JavaScript payload \u0111\u00E1nh c\u1EAFp document.cookie v\u00E0 g\u1EEDi v\u1EC1 server attacker",
             "outcome": "Attacker c\u00F3 session cookie/token c\u1EE7a n\u1EA1n nh\u00E2n"},
            {"action": "Attacker s\u1EED d\u1EE5ng session cookie \u0111\u1EC3 truy c\u1EADp \u1EE9ng d\u1EE5ng",
             "outcome": "Chi\u1EBFm quy\u1EC1n t\u00E0i kho\u1EA3n n\u1EA1n nh\u00E2n, th\u1EF1c hi\u1EC7n h\u00E0nh \u0111\u1ED9ng thay m\u1EB7t h\u1ECD"},
        ],
        "total_impact": "Chi\u1EBFm quy\u1EC1n t\u00E0i kho\u1EA3n ng\u01B0\u1EDDi d\u00F9ng, c\u00F3 th\u1EC3 bao g\u1ED3m t\u00E0i kho\u1EA3n admin",
    },
    {
        "name": "Tr\u00EDch xu\u1EA5t Database qua SQL Injection",
        "requires": ["sqli"],
        "optional": ["time_based_sqli"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng khai th\u00E1c SQL Injection \u0111\u1EC3 tr\u00EDch xu\u1EA5t d\u1EEF li\u1EC7u nh\u1EA1y c\u1EA3m "
            "t\u1EEB database, bao g\u1ED3m th\u00F4ng tin ng\u01B0\u1EDDi d\u00F9ng, m\u1EADt kh\u1EA9u, v\u00E0 d\u1EEF li\u1EC7u kinh doanh."
        ),
        "steps_template": [
            {"action": "X\u00E1c \u0111\u1ECBnh injection point v\u00E0 database type qua error messages ho\u1EB7c timing",
             "outcome": "Bi\u1EBFt \u0111\u01B0\u1EE3c endpoint vulnerable, lo\u1EA1i DB, v\u00E0 c\u1EA5u tr\u00FAc query"},
            {"action": "S\u1EED d\u1EE5ng UNION SELECT ho\u1EB7c blind extraction \u0111\u1EC3 l\u1EA5y t\u00EAn tables/columns",
             "outcome": "Map \u0111\u01B0\u1EE3c schema database: tables, columns, data types"},
            {"action": "Tr\u00EDch xu\u1EA5t d\u1EEF li\u1EC7u nh\u1EA1y c\u1EA3m: users, passwords, emails, PII",
             "outcome": "To\u00E0n b\u1ED9 database b\u1ECB \u0111\u00E1nh c\u1EAFp, bao g\u1ED3m password hashes"},
            {"action": "Crack password hashes offline (rainbow tables, hashcat)",
             "outcome": "C\u00F3 plaintext passwords, s\u1EED d\u1EE5ng \u0111\u1EC3 \u0111\u0103ng nh\u1EADp ho\u1EB7c credential stuffing"},
        ],
        "total_impact": "L\u1ED9 to\u00E0n b\u1ED9 d\u1EEF li\u1EC7u database, c\u00F3 th\u1EC3 bao g\u1ED3m PII, credentials, d\u1EEF li\u1EC7u t\u00E0i ch\u00EDnh",
    },
    {
        "name": "Chi\u1EBFm quy\u1EC1n Server qua Command Injection",
        "requires": ["cmdi"],
        "optional": ["time_based_cmdi"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng khai th\u00E1c Command Injection \u0111\u1EC3 th\u1EF1c thi l\u1EC7nh OS tr\u00EAn server, "
            "t\u1EEB \u0111\u00F3 c\u00E0i backdoor, leo thang \u0111\u1EB7c quy\u1EC1n, v\u00E0 di chuy\u1EC3n ngang trong m\u1EA1ng."
        ),
        "steps_template": [
            {"action": "X\u00E1c nh\u1EADn command execution qua sleep/ping ho\u1EB7c output-based payload",
             "outcome": "Ch\u1EE9ng minh OS command \u0111\u01B0\u1EE3c th\u1EF1c thi v\u1EDBi quy\u1EC1n web application"},
            {"action": "Thu th\u1EADp th\u00F4ng tin server: OS, users, network config, running processes",
             "outcome": "Hi\u1EC3u r\u00F5 m\u00F4i tr\u01B0\u1EDDng server, t\u00ECm c\u00E1ch leo thang \u0111\u1EB7c quy\u1EC1n"},
            {"action": "C\u00E0i reverse shell ho\u1EB7c web shell \u0111\u1EC3 duy tr\u00EC truy c\u1EADp",
             "outcome": "Persistent access \u2014 attacker c\u00F3 th\u1EC3 quay l\u1EA1i b\u1EA5t k\u1EF3 l\u00FAc n\u00E0o"},
            {"action": "Lateral movement: scan m\u1EA1ng n\u1ED9i b\u1ED9, truy c\u1EADp c\u00E1c server kh\u00E1c",
             "outcome": "T\u1EEB 1 server b\u1ECB compromise, m\u1EDF r\u1ED9ng sang to\u00E0n b\u1ED9 infrastructure"},
        ],
        "total_impact": "Chi\u1EBFm quy\u1EC1n ho\u00E0n to\u00E0n server, c\u00E0i backdoor, lateral movement trong m\u1EA1ng n\u1ED9i b\u1ED9",
    },
    {
        "name": "Truy c\u1EADp t\u00E0i nguy\u00EAn n\u1ED9i b\u1ED9 qua SSRF",
        "requires": ["ssrf"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng khai th\u00E1c SSRF \u0111\u1EC3 truy c\u1EADp d\u1ECBch v\u1EE5 n\u1ED9i b\u1ED9 kh\u00F4ng \u0111\u01B0\u1EE3c b\u1EA3o v\u1EC7, "
            "bao g\u1ED3m cloud metadata, database, admin panels n\u1ED9i b\u1ED9."
        ),
        "steps_template": [
            {"action": "G\u1EEDi request \u0111\u1EBFn cloud metadata endpoint (169.254.169.254)",
             "outcome": "L\u1EA5y \u0111\u01B0\u1EE3c IAM credentials, instance ID, security groups"},
            {"action": "S\u1EED d\u1EE5ng IAM credentials \u0111\u1EC3 truy c\u1EADp cloud services (S3, RDS, etc.)",
             "outcome": "Truy c\u1EADp d\u1EEF li\u1EC7u tr\u00EAn cloud m\u00E0 kh\u00F4ng c\u1EA7n authentication"},
            {"action": "Scan port n\u1ED9i b\u1ED9 qua SSRF \u0111\u1EC3 t\u00ECm services kh\u00F4ng \u0111\u01B0\u1EE3c b\u1EA3o v\u1EC7",
             "outcome": "Ph\u00E1t hi\u1EC7n database, cache, admin panel accessible t\u1EEB server"},
        ],
        "total_impact": "Truy c\u1EADp t\u00E0i nguy\u00EAn n\u1ED9i b\u1ED9, cloud credentials, c\u00F3 th\u1EC3 chi\u1EBFm to\u00E0n b\u1ED9 cloud account",
    },
    {
        "name": "\u0110\u1ECDc file nh\u1EA1y c\u1EA3m qua Path Traversal/LFI",
        "requires": ["lfi"],
        "optional": ["path_traversal"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng khai th\u00E1c Local File Inclusion \u0111\u1EC3 \u0111\u1ECDc file c\u1EA5u h\u00ECnh, "
            "source code, v\u00E0 credentials tr\u00EAn server."
        ),
        "steps_template": [
            {"action": "\u0110\u1ECDc /etc/passwd \u0111\u1EC3 x\u00E1c nh\u1EADn LFI v\u00E0 li\u1EC7t k\u00EA system users",
             "outcome": "Bi\u1EBFt \u0111\u01B0\u1EE3c danh s\u00E1ch users tr\u00EAn server"},
            {"action": "\u0110\u1ECDc file c\u1EA5u h\u00ECnh: .env, config.php, database.yml, settings.py",
             "outcome": "L\u1EA5y \u0111\u01B0\u1EE3c database credentials, API keys, secret keys"},
            {"action": "S\u1EED d\u1EE5ng credentials \u0111\u1EC3 truy c\u1EADp database ho\u1EB7c d\u1ECBch v\u1EE5 kh\u00E1c",
             "outcome": "Truy c\u1EADp tr\u1EF1c ti\u1EBFp database, tr\u00EDch xu\u1EA5t d\u1EEF li\u1EC7u"},
        ],
        "total_impact": "L\u1ED9 credentials, source code, c\u1EA5u h\u00ECnh server \u2014 c\u00F3 th\u1EC3 d\u1EABn \u0111\u1EBFn chi\u1EBFm quy\u1EC1n ho\u00E0n to\u00E0n",
    },
    {
        "name": "Chu\u1ED7i t\u1EA5n c\u00F4ng k\u1EBFt h\u1EE3p: XSS \u2192 SQLi Escalation",
        "requires": ["xss", "sqli"],
        "description": (
            "K\u1EBB t\u1EA5n c\u00F4ng k\u1EBFt h\u1EE3p XSS v\u00E0 SQLi: d\u00F9ng XSS chi\u1EBFm session admin, "
            "sau \u0111\u00F3 khai th\u00E1c SQLi tr\u00EAn admin panel \u0111\u1EC3 tr\u00EDch xu\u1EA5t database."
        ),
        "steps_template": [
            {"action": "Khai th\u00E1c XSS tr\u00EAn trang public \u0111\u1EC3 \u0111\u00E1nh c\u1EAFp admin session",
             "outcome": "C\u00F3 quy\u1EC1n truy c\u1EADp admin panel"},
            {"action": "T\u00ECm v\u00E0 khai th\u00E1c SQLi tr\u00EAn admin endpoints (th\u01B0\u1EDDng \u00EDt \u0111\u01B0\u1EE3c b\u1EA3o v\u1EC7)",
             "outcome": "Tr\u00EDch xu\u1EA5t to\u00E0n b\u1ED9 database v\u1EDBi quy\u1EC1n admin"},
            {"action": "S\u1EED d\u1EE5ng admin access \u0111\u1EC3 upload webshell ho\u1EB7c modify code",
             "outcome": "Persistent access + full control"},
        ],
        "total_impact": "Chi\u1EBFm quy\u1EC1n admin + database + server \u2014 worst case scenario",
    },
]


def _matches_type(req_type: str, found_types: set[str]) -> bool:
    if req_type in found_types:
        return True
    variations = {
        "xss": ["xss", "xss_reflected", "xss_stored"],
        "sqli": ["sqli", "time_based_sqli"],
        "cmdi": ["cmdi", "time_based_cmdi"],
        "lfi": ["lfi", "path_traversal"],
    }
    return any(var in found_types for var in variations.get(req_type, []))


def analyze_attack_paths(
    graph: AttackSurfaceGraph,
    analyzed_vulnerabilities: list[dict],
) -> list[AttackPath]:
    paths: list[AttackPath] = []
    found_types: set[str] = set()
    type_to_vulns: dict[str, list[dict]] = {}

    for vuln in analyzed_vulnerabilities:
        vtype = vuln.get("vulnerability_type", "")
        found_types.add(vtype)
        type_to_vulns.setdefault(vtype, []).append(vuln)

    for template in CHAIN_TEMPLATES:
        required = template["requires"]
        if not all(_matches_type(r, found_types) for r in required):
            continue

        path = AttackPath(
            path_id=str(uuid.uuid4())[:8],
            name=template["name"],
            description=template["description"],
        )

        for i, step_tmpl in enumerate(template["steps_template"]):
            step_vuln_type = required[min(i, len(required) - 1)]
            actual_vuln = None
            for var_type in [step_vuln_type] + template.get("optional", []):
                if var_type in type_to_vulns:
                    actual_vuln = type_to_vulns[var_type][0]
                    break
            # Also check variations
            if not actual_vuln:
                variations = {
                    "xss": ["xss_reflected", "xss_stored"],
                    "sqli": ["time_based_sqli"],
                    "cmdi": ["time_based_cmdi"],
                    "lfi": ["path_traversal"],
                }
                for var in variations.get(step_vuln_type, []):
                    if var in type_to_vulns:
                        actual_vuln = type_to_vulns[var][0]
                        break

            step = AttackStep(
                order=i + 1,
                finding_id=actual_vuln.get("finding_id", "") if actual_vuln else "",
                vuln_type=step_vuln_type,
                endpoint=actual_vuln.get("endpoint", "") if actual_vuln else "",
                parameter=actual_vuln.get("parameter", "") if actual_vuln else "",
                action=step_tmpl["action"],
                outcome=step_tmpl["outcome"],
                cvss_score=float(actual_vuln.get("cvss_score", 0)) if actual_vuln else 0,
            )
            path.steps.append(step)

        path.total_impact = template["total_impact"]

        max_cvss = max((s.cvss_score for s in path.steps), default=0)
        if max_cvss >= 9.0:
            path.likelihood = "High"
            path.priority = "P0"
        elif max_cvss >= 7.0:
            path.likelihood = "Medium"
            path.priority = "P1"
        else:
            path.likelihood = "Low"
            path.priority = "P2"

        paths.append(path)

    priority_order = {"P0": 0, "P1": 1, "P2": 2}
    paths.sort(key=lambda p: priority_order.get(p.priority, 3))

    return paths
