"""YAML template loader — reads templates from the templates/ directory."""
from __future__ import annotations

import logging
from pathlib import Path

import yaml

from scanner.template_engine.models import (
    ScanTemplate,
    TemplateMatcher,
    TemplateRequest,
)

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


def _parse_matcher(raw: dict) -> TemplateMatcher:
    return TemplateMatcher(
        type=str(raw.get("type", "word")),
        value=str(raw.get("value", "")),
        part=str(raw.get("part", "body")),
        negative=bool(raw.get("negative", False)),
    )


def _parse_request(raw: dict | None) -> TemplateRequest:
    if not raw:
        return TemplateRequest()
    return TemplateRequest(
        method=str(raw.get("method", "GET")).upper(),
        path=str(raw.get("path", "/")),
        headers=dict(raw.get("headers") or {}),
        body=str(raw.get("body", "")),
        inject_in=str(raw.get("inject_in", "query")),
    )


def _parse_template(data: dict) -> ScanTemplate | None:
    """Parse a single YAML document into a ScanTemplate."""
    try:
        tid = str(data.get("id", ""))
        if not tid:
            return None
        return ScanTemplate(
            id=tid,
            name=str(data.get("name", tid)),
            severity=str(data.get("severity", "medium")).lower(),
            vulnerability_type=str(data.get("vulnerability_type", "")),
            owasp=str(data.get("owasp", "")),
            cwe=str(data.get("cwe", "")),
            description=str(data.get("description", "")),
            payloads=[str(p) for p in (data.get("payloads") or [])],
            request=_parse_request(data.get("request")),
            matchers=[_parse_matcher(m) for m in (data.get("matchers") or [])],
            tags=[str(t) for t in (data.get("tags") or [])],
            match_condition=str(data.get("match_condition", "or")),
        )
    except Exception as exc:
        logger.warning("Failed to parse template: %s", exc)
        return None


def load_templates(directory: Path | None = None) -> list[ScanTemplate]:
    """Load all YAML templates from *directory* (default: templates/)."""
    templates_dir = directory or TEMPLATES_DIR
    if not templates_dir.is_dir():
        logger.warning("Templates directory does not exist: %s", templates_dir)
        return []

    templates: list[ScanTemplate] = []
    for yaml_file in sorted(templates_dir.glob("*.yaml")):
        try:
            text = yaml_file.read_text(encoding="utf-8")
            for doc in yaml.safe_load_all(text):
                if not doc or not isinstance(doc, dict):
                    continue
                tpl = _parse_template(doc)
                if tpl:
                    templates.append(tpl)
        except Exception as exc:
            logger.warning("Error reading %s: %s", yaml_file.name, exc)

    logger.info("Loaded %d scan templates from %s", len(templates), templates_dir)
    return templates
