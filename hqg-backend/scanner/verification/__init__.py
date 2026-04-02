"""scanner.verification — trust layer for vulnerability findings.

Converts single-signal detections into multi-step verified reports with
explicit confidence levels (confirmed / high / medium / low) and
traceable verification steps.

Public API::

    from scanner.verification.verifier import verify_findings_async, verify_finding
"""
