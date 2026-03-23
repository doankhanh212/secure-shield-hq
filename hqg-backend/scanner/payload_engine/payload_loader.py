from __future__ import annotations

from pathlib import Path


PAYLOAD_DIR = Path(__file__).parent / "payloads"

PAYLOAD_FILES: dict[str, str] = {
    "sqli": "sqli.txt",
    "xss": "xss.txt",
    "ssrf": "ssrf.txt",
    "cmdi": "cmdi.txt",
    "lfi": "lfi.txt",
    "path_traversal": "lfi.txt",
}


def _read_payload_file(file_path: Path) -> list[str]:
    if not file_path.exists():
        return []
    lines = file_path.read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.startswith("#")]


def load_payloads() -> dict[str, list[str]]:
    return {
        vuln_type: _read_payload_file(PAYLOAD_DIR / filename)
        for vuln_type, filename in PAYLOAD_FILES.items()
    }
