from __future__ import annotations

from backend.celery_app import celery_app
from ai.analyzer.ai_client import generate_explanation
from ai.analyzer.models import AnalyzedVulnerability
from ai.analyzer.severity_mapper import (
    map_cwe,
    map_display_name,
    map_owasp,
    map_severity,
)
from ai.analyzer.vulnerability_classifier import classify


def _analyze_single(finding: dict[str, object]) -> AnalyzedVulnerability | None:
    """Run classification, mapping and explanation for one finding."""
    endpoint = str(finding.get("endpoint", ""))
    payload = str(finding.get("payload", ""))
    vuln_type = str(finding.get("vulnerability_type", ""))

    # 1. False-positive filtering & confidence adjustment
    is_fp, adjusted_confidence = classify(finding)
    if is_fp:
        return AnalyzedVulnerability(
            endpoint=endpoint,
            vulnerability=map_display_name(vuln_type),
            vulnerability_type=vuln_type,
            owasp=map_owasp(vuln_type),
            cwe=map_cwe(vuln_type),
            severity=map_severity(vuln_type),
            confidence=adjusted_confidence,
            explanation="Classified as likely false positive.",
            payload=payload,
            detection_method=str(finding.get("detection_method", "")),
            is_false_positive=True,
            false_positive_reason="Classified as likely false positive.",
        )

    # 2. Security-standards mapping
    owasp = map_owasp(vuln_type)
    cwe = map_cwe(vuln_type)
    severity = map_severity(vuln_type)
    display_name = map_display_name(vuln_type)

    # 3. Explanation generation
    explanation = generate_explanation(vuln_type, endpoint, payload)

    return AnalyzedVulnerability(
        endpoint=endpoint,
        vulnerability=display_name,
        vulnerability_type=vuln_type,
        owasp=owasp,
        cwe=cwe,
        severity=severity,
        confidence=adjusted_confidence,
        explanation=explanation,
        payload=payload,
        detection_method=str(finding.get("detection_method", "")),
        is_false_positive=False,
    )


@celery_app.task(name="ai.analyzer.analyze_vulnerabilities")
def analyze_vulnerabilities(
    scan_id: str,
    findings: list[dict[str, object]],
) -> dict[str, object]:
    analyzed: list[dict[str, object]] = []
    false_positive_count = 0

    for raw_finding in findings:
        result = _analyze_single(raw_finding)
        if result is None:
            continue
        if result.is_false_positive:
            false_positive_count += 1
        analyzed.append(result.to_dict())

    return {
        "scan_id": scan_id,
        "total_input": len(findings),
        "total_confirmed": len(analyzed) - false_positive_count,
        "total_false_positives": false_positive_count,
        "findings": analyzed,
    }
