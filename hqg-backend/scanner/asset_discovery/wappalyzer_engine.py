from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# fingerprints_data.json sits at project root (hqg-backend/),
# this file is 3 levels deep: scanner/asset_discovery/wappalyzer_engine.py
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_FINGERPRINTS_PATH = _PROJECT_ROOT / "fingerprints_data.json"

# Module-level singletons — initialised once, reused for every call
_wappalyzer_instance = None
_cpe_lookup: dict[str, str] | None = None

# Library-emitted names that differ from keys in fingerprints_data.json
_NAME_ALIASES: dict[str, str] = {
    "Apache": "Apache HTTP Server",
    "ASP.NET": "Microsoft ASP.NET",
    "IIS": "Microsoft IIS",
    "Outlook Web App": "Microsoft Outlook Web Access",
}


def _get_wappalyzer():
    """Return a cached Wappalyzer.latest() instance. None on failure."""
    global _wappalyzer_instance
    if _wappalyzer_instance is None:
        try:
            from Wappalyzer import Wappalyzer  # type: ignore[import]
            _wappalyzer_instance = Wappalyzer.latest()
            logger.info(
                "Wappalyzer initialised: %d bundled technologies",
                len(_wappalyzer_instance.technologies),
            )
        except Exception as exc:
            logger.error("Failed to init Wappalyzer: %s", exc)
    return _wappalyzer_instance


def _get_cpe_lookup() -> dict[str, str]:
    """
    Load CPE templates from local fingerprints_data.json.
    Returns a dict of {tech_name: cpe_template}.
    Cached after first call.
    """
    global _cpe_lookup
    if _cpe_lookup is not None:
        return _cpe_lookup
    _cpe_lookup = {}
    if not _FINGERPRINTS_PATH.exists():
        logger.warning(
            "fingerprints_data.json not found at %s — CPE lookup disabled",
            _FINGERPRINTS_PATH,
        )
        return _cpe_lookup
    try:
        with open(_FINGERPRINTS_PATH, encoding="utf-8") as f:
            apps = json.load(f).get("apps", {})
        for name, fp in apps.items():
            cpe = fp.get("cpe")
            if cpe:
                _cpe_lookup[name] = cpe
        logger.info("CPE lookup loaded: %d entries", len(_cpe_lookup))
    except Exception as exc:
        logger.error("Failed to load fingerprints_data.json: %s", exc)
    return _cpe_lookup


@dataclass
class DetectedTechnology:
    """Technology detected by Wappalyzer fingerprinting."""

    name: str
    version: Optional[str] = None
    cpe: Optional[str] = None
    categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "cpe": self.cpe,
            "categories": self.categories,
        }


def _build_cpe(template: str, version: Optional[str]) -> str:
    """Inject detected version into CPE 2.3 template at position [5]."""
    if not version:
        return template
    parts = template.split(":")
    if len(parts) >= 6 and parts[5] == "*":
        parts[5] = version
    return ":".join(parts)


def _resolve_cpe(tech_name: str, version: Optional[str]) -> Optional[str]:
    """
    Resolve CPE template for a detected technology name.
    Tries exact match → alias → case-insensitive fallback.
    """
    cpe_lookup = _get_cpe_lookup()
    # 1. Exact match
    tpl = cpe_lookup.get(tech_name)
    if tpl:
        return _build_cpe(tpl, version)
    # 2. Known alias (lib name ≠ JSON key)
    alias = _NAME_ALIASES.get(tech_name)
    if alias:
        tpl = cpe_lookup.get(alias)
        if tpl:
            return _build_cpe(tpl, version)
    # 3. Case-insensitive scan
    lc = tech_name.lower()
    for fp_name, fp_cpe in cpe_lookup.items():
        if fp_name.lower() == lc:
            return _build_cpe(fp_cpe, version)
    return None


def fingerprint_response(
    url: str,
    html: str,
    headers: dict[str, str],
) -> list[DetectedTechnology]:
    """
    Run Wappalyzer detection on an already-fetched response.
    Does NOT make any HTTP requests.

    Uses Wappalyzer.latest() (1270 bundled tech fingerprints) for
    detection, then cross-references local fingerprints_data.json
    only to obtain CPE templates.

    Returns an empty list on any error (graceful degradation).
    """
    wap = _get_wappalyzer()
    if wap is None:
        return []
    try:
        from Wappalyzer import WebPage  # type: ignore[import]

        webpage = WebPage(url=url, html=html, headers=headers)
        raw: dict = wap.analyze_with_versions_and_categories(webpage)

        results: list[DetectedTechnology] = []
        for tech_name, info in raw.items():
            versions: list[str] = info.get("versions", [])
            version = versions[0] if versions else None
            cpe = _resolve_cpe(tech_name, version)
            results.append(
                DetectedTechnology(
                    name=tech_name,
                    version=version,
                    cpe=cpe,
                    categories=info.get("categories", []),
                )
            )

        logger.info(
            "Wappalyzer [%s]: %d techs (%d versioned, %d with CPE)",
            url,
            len(results),
            sum(1 for t in results if t.version),
            sum(1 for t in results if t.cpe),
        )
        return results

    except Exception as exc:
        logger.warning("Wappalyzer error for %s: %s", url, exc)
        return []
