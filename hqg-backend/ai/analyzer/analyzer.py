"""
Main orchestrator: takes raw detection findings and produces enriched
AnalyzedVulnerability objects with OWASP/CWE/CVSS mapping, Vietnamese
explanations, confidence scoring, and false-positive likelihood.

Zero external dependencies, zero network calls. Never raises on bad input.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ai.analyzer.confidence_scorer import calculate_confidence, confidence_label
from ai.analyzer.explanation_engine import generate_explanation
from ai.analyzer.vuln_mapping import lookup

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class AnalyzedVulnerability:
    # --- from finding dict --------------------------------------------------
    finding_id: str
    endpoint: str
    payload: str
    vulnerability_type: str
    confidence: str          # original label from detection engine (High/Medium/Low)
    detection_method: str
    evidence: str
    parameter: str
    http_method: str

    # --- enriched OWASP / CWE / CVSS ----------------------------------------
    owasp_category: str = ""
    cwe_id: str = ""
    cwe_name: str = ""
    cvss_vector: str = ""
    cvss_score: float = 0.0
    severity: str = ""

    # --- AI-generated content (deterministic) --------------------------------
    explanation: str = ""
    impact: str = ""
    fix_recommendation: list[str] = field(default_factory=list)

    # --- scoring -------------------------------------------------------------
    confidence_score: float = 0.0    # 0.0–1.0
    confidence_label_text: str = ""  # Confirmed / Likely / Potential
    false_positive_likelihood: float = 0.0  # 0.0–1.0
    is_false_positive: bool = False
    false_positive_reason: str = ""

    def compute_severity(self) -> None:
        """Set self.severity from self.cvss_score using CVSS v3.1 thresholds."""
        s = self.cvss_score
        if s >= 9.0:
            self.severity = "Critical"
        elif s >= 7.0:
            self.severity = "High"
        elif s >= 4.0:
            self.severity = "Medium"
        elif s > 0:
            self.severity = "Low"
        else:
            self.severity = "None"

    def to_dict(self) -> dict[str, object]:
        return {
            "finding_id": self.finding_id,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "http_method": self.http_method,
            "payload": self.payload,
            "vulnerability_type": self.vulnerability_type,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "cvss_vector": self.cvss_vector,
            "cvss_score": self.cvss_score,
            "severity": self.severity,
            "confidence": self.confidence,
            "confidence_score": round(self.confidence_score, 3),
            "confidence_label": self.confidence_label_text,
            "false_positive_likelihood": round(self.false_positive_likelihood, 3),
            "is_false_positive": self.is_false_positive,
            "false_positive_reason": self.false_positive_reason,
            "detection_method": self.detection_method,
            "evidence": self.evidence,
            "explanation": self.explanation,
            "impact": self.impact,
            "fix_recommendation": self.fix_recommendation,
        }


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def analyze_finding(finding_dict: dict) -> AnalyzedVulnerability | None:
    """
    Enrich a single finding dict with OWASP/CWE/CVSS mapping, explanations,
    confidence scoring and FP likelihood.

    Never raises — returns None on unrecoverable error.
    """
    try:
        vuln_type = str(finding_dict.get("vulnerability_type", "")).strip()

        # 1. OWASP / CWE / CVSS lookup
        mapping = lookup(vuln_type)

        # 2. Explanation, impact, fix
        generated = generate_explanation(finding_dict)

        # 3. Confidence score
        conf_score = calculate_confidence(finding_dict)
        conf_label = confidence_label(conf_score)

        # 4. False-positive likelihood (inverse of confidence)
        if conf_score >= 0.7:
            fp_likelihood = 0.1
        elif conf_score >= 0.4:
            fp_likelihood = 0.3
        else:
            fp_likelihood = 0.6

        av = AnalyzedVulnerability(
            # from finding
            finding_id=str(finding_dict.get("finding_id", "")),
            endpoint=str(finding_dict.get("endpoint", "")),
            payload=str(finding_dict.get("payload", "")),
            vulnerability_type=vuln_type,
            confidence=str(finding_dict.get("confidence", "")),
            detection_method=str(finding_dict.get("detection_method", "")),
            evidence=str(finding_dict.get("evidence", "")),
            parameter=str(finding_dict.get("parameter", "")),
            http_method=str(finding_dict.get("http_method", "GET")),
            # mapping
            owasp_category=mapping["owasp"],
            cwe_id=mapping["cwe_id"],
            cwe_name=mapping["cwe_name"],
            cvss_vector=mapping["cvss_vector"],
            cvss_score=mapping["cvss_score"],
            # generated content
            explanation=generated["explanation"],
            impact=generated["impact"],
            fix_recommendation=generated["fix_recommendation"],
            # scoring
            confidence_score=conf_score,
            confidence_label_text=conf_label,
            false_positive_likelihood=fp_likelihood,
        )

        av.compute_severity()
        return av

    except Exception:
        logger.warning(
            "analyze_finding failed for finding_id=%s vuln_type=%s",
            finding_dict.get("finding_id", "?"),
            finding_dict.get("vulnerability_type", "?"),
            exc_info=True,
        )
        return None


def analyze_findings(findings: list[dict]) -> list[AnalyzedVulnerability]:
    """
    Enrich a list of finding dicts. Silently skips findings that fail.
    Returns results sorted by cvss_score descending (Critical first).
    Logs a summary at INFO level.
    """
    results: list[AnalyzedVulnerability] = []

    for f in findings:
        av = analyze_finding(f)
        if av is not None:
            results.append(av)

    results.sort(key=lambda x: x.cvss_score, reverse=True)

    # Summary log
    by_sev: dict[str, int] = {}
    for av in results:
        by_sev[av.severity] = by_sev.get(av.severity, 0) + 1

    confirmed = sum(1 for av in results if av.confidence_label_text == "Confirmed")
    likely_fp = sum(1 for av in results if av.false_positive_likelihood >= 0.5)

    logger.info(
        "analyze_findings: input=%d analyzed=%d severity=%s confirmed=%d likely_fp=%d",
        len(findings),
        len(results),
        by_sev,
        confirmed,
        likely_fp,
    )

    return results
