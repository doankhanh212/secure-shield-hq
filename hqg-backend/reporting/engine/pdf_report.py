from __future__ import annotations

from pathlib import Path

from reporting.engine.html_report import write_html
from reporting.engine.models import ScanReport


def write_pdf(report: ScanReport, output_dir: Path) -> Path:
    """
    Convert the HTML report to PDF using WeasyPrint.

    WeasyPrint renders the self-contained HTML produced by html_report.write_html()
    and writes a PDF alongside it. The HTML file is kept so it can be inspected.

    Raises:
        RuntimeError: if weasyprint is not installed.
    """
    try:
        from weasyprint import HTML as _WP_HTML  # type: ignore[import-untyped]
    except ImportError as exc:
        raise RuntimeError(
            "weasyprint is required for PDF reports. "
            "Install it with: pip install weasyprint"
        ) from exc

    html_path = write_html(report, output_dir)
    pdf_path = output_dir / f"{report.scan_id}.pdf"
    _WP_HTML(filename=str(html_path)).write_pdf(str(pdf_path))
    return pdf_path
