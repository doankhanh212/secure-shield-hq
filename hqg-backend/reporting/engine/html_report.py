from __future__ import annotations

from pathlib import Path

from reporting.engine.models import ScanReport

_SEVERITY_COLOR: dict[str, str] = {
    "Critical": "#dc2626",
    "High": "#ea580c",
    "Medium": "#d97706",
    "Low": "#16a34a",
}


def write_html(report: ScanReport, output_dir: Path) -> Path:
    """Render *report* as a self-contained HTML file under *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{report.scan_id}.html"
    path.write_text(_render(report), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Private rendering
# ---------------------------------------------------------------------------

def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#6b7280")
    return (
        f'<span class="badge" style="background:{color}">{severity}</span>'
    )


def _ul(items: list[str]) -> str:
    if not items:
        return "<em class='none'>None discovered</em>"
    return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in items) + "</ul>"


def _esc(text: str) -> str:
    """Minimal HTML escaping to prevent XSS in report output."""
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


def _render(r: ScanReport) -> str:
    es = r.executive_summary
    ro = r.risk_overview
    asset = r.asset_summary

    false_positives = es.total_vulnerabilities - es.confirmed_vulnerabilities

    # --- Vulnerability table rows ---
    rows: list[str] = []
    for v in r.vulnerability_details:
        fp_note = " <em class='fp-label'>(False Positive)</em>" if v.is_false_positive else ""
        rows.append(
            f"<tr>"
            f"<td><code>{_esc(v.endpoint)}</code></td>"
            f"<td>{_esc(v.vulnerability)}{fp_note}</td>"
            f"<td><code>{_esc(v.owasp)}</code></td>"
            f"<td><code>{_esc(v.cwe)}</code></td>"
            f"<td>{_severity_badge(v.severity)}</td>"
            f"<td>{_esc(v.confidence)}</td>"
            f"<td>{_esc(v.explanation)}</td>"
            f"<td>{_esc(v.remediation)}</td>"
            f"</tr>"
        )

    vuln_rows = "\n".join(rows) if rows else (
        '<tr><td colspan="8" class="empty">No vulnerabilities found.</td></tr>'
    )

    # --- CVE intelligence table rows ---
    cve_rows_list: list[str] = []
    for c in r.cve_details:
        exploit_icon = "&#x2714;" if c.exploit_available else "&#x2718;"
        cve_rows_list.append(
            f"<tr>"
            f"<td><code>{_esc(c.cve_id)}</code></td>"
            f"<td>{_esc(c.technology)}</td>"
            f"<td>{_esc(c.version)}</td>"
            f"<td>{c.cvss:.1f}</td>"
            f"<td>{_severity_badge(c.severity)}</td>"
            f"<td>{_esc(c.summary[:200])}</td>"
            f"<td style='text-align:center'>{exploit_icon}</td>"
            f"<td>{_esc(c.source)}</td>"
            f"</tr>"
        )
    cve_rows = "\n".join(cve_rows_list) if cve_rows_list else (
        '<tr><td colspan="8" class="empty">No CVEs identified.</td></tr>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report &mdash; {_esc(es.target)}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px; color: #1f2937; background: #f9fafb; padding: 40px 32px;
    }}
    a {{ color: inherit; }}
    h1 {{ font-size: 1.75rem; font-weight: 700; color: #111827; margin-bottom: 4px; }}
    h2 {{
      font-size: 1.05rem; font-weight: 600; color: #374151;
      margin: 32px 0 14px; border-bottom: 2px solid #e5e7eb; padding-bottom: 8px;
      text-transform: uppercase; letter-spacing: .06em;
    }}
    h3 {{ font-size: 0.875rem; font-weight: 600; color: #374151; margin-bottom: 8px; }}
    .meta {{ color: #6b7280; font-size: 0.8125rem; margin-bottom: 28px; }}

    /* Summary cards */
    .summary-grid {{
      display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 4px;
    }}
    .summary-card {{
      background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px 18px;
    }}
    .summary-card .sk {{
      font-size: 0.7rem; color: #9ca3af; text-transform: uppercase;
      letter-spacing: .08em; margin-bottom: 4px;
    }}
    .summary-card .sv {{ font-size: 1rem; font-weight: 600; }}

    /* KPI risk grid */
    .kpi-grid {{
      display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
    }}
    .kpi {{
      background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
      padding: 20px 16px; text-align: center;
    }}
    .kpi .value {{ font-size: 2.25rem; font-weight: 700; }}
    .kpi .label {{
      font-size: 0.7rem; color: #6b7280; margin-top: 4px;
      text-transform: uppercase; letter-spacing: .08em;
    }}
    .critical .value {{ color: #dc2626; }}
    .high     .value {{ color: #ea580c; }}
    .medium   .value {{ color: #d97706; }}
    .low      .value {{ color: #16a34a; }}

    /* Table */
    .table-wrapper {{ overflow-x: auto; }}
    table {{
      width: 100%; border-collapse: collapse;
      background: #fff; border: 1px solid #e5e7eb;
      border-radius: 8px; overflow: hidden;
    }}
    th {{
      background: #f3f4f6; text-align: left; padding: 10px 14px;
      font-size: 0.7rem; text-transform: uppercase;
      letter-spacing: .06em; color: #6b7280; border-bottom: 1px solid #e5e7eb;
      white-space: nowrap;
    }}
    td {{
      padding: 10px 14px; border-bottom: 1px solid #f3f4f6;
      vertical-align: top; font-size: 0.8125rem; max-width: 320px;
      word-break: break-word;
    }}
    tr:last-child td {{ border-bottom: none; }}
    td.empty {{ color: #6b7280; text-align: center; padding: 24px; }}
    code {{
      background: #f3f4f6; padding: 1px 5px;
      border-radius: 4px; font-size: 0.75rem; word-break: break-all;
    }}
    .badge {{
      color: #fff; padding: 2px 8px; border-radius: 4px;
      font-size: 0.7rem; font-weight: 700; white-space: nowrap;
    }}
    .fp-label {{ color: #9ca3af; font-style: italic; font-size: 0.75rem; }}

    /* Asset grid */
    .asset-grid {{
      display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;
    }}
    .asset-card {{
      background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 18px;
    }}
    ul {{ padding-left: 18px; line-height: 1.9; }}
    .none {{ color: #9ca3af; font-style: italic; font-size: 0.8rem; }}
  </style>
</head>
<body>

  <h1>Security Scan Report</h1>
  <p class="meta">
    Generated&nbsp;{_esc(es.generated_at)}
    &nbsp;&bull;&nbsp;
    Scan&nbsp;ID:&nbsp;<code>{_esc(r.scan_id)}</code>
  </p>

  <!-- ── 1. Executive Summary ─────────────────────────────────────── -->
  <h2>1. Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="sk">Target</div>
      <div class="sv">{_esc(es.target) or "<em class='none'>—</em>"}</div>
    </div>
    <div class="summary-card">
      <div class="sk">Scan Mode</div>
      <div class="sv">{_esc(es.scan_mode.title())}</div>
    </div>
    <div class="summary-card">
      <div class="sk">Duration</div>
      <div class="sv">{es.scan_duration_seconds}s</div>
    </div>
    <div class="summary-card">
      <div class="sk">Total Findings</div>
      <div class="sv">{es.total_vulnerabilities}</div>
    </div>
    <div class="summary-card">
      <div class="sk">Confirmed</div>
      <div class="sv">{es.confirmed_vulnerabilities}</div>
    </div>
    <div class="summary-card">
      <div class="sk">False Positives</div>
      <div class="sv">{false_positives}</div>
    </div>
  </div>

  <!-- ── 2. Risk Overview ──────────────────────────────────────────── -->
  <h2>2. Risk Overview</h2>
  <div class="kpi-grid">
    <div class="kpi critical">
      <div class="value">{ro.critical}</div><div class="label">Critical</div>
    </div>
    <div class="kpi high">
      <div class="value">{ro.high}</div><div class="label">High</div>
    </div>
    <div class="kpi medium">
      <div class="value">{ro.medium}</div><div class="label">Medium</div>
    </div>
    <div class="kpi low">
      <div class="value">{ro.low}</div><div class="label">Low</div>
    </div>
  </div>

  <!-- ── 3. Vulnerability Details ─────────────────────────────────── -->
  <h2>3. Vulnerability Details</h2>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>Endpoint</th>
          <th>Vulnerability</th>
          <th>OWASP</th>
          <th>CWE</th>
          <th>Severity</th>
          <th>Confidence</th>
          <th>Explanation</th>
          <th>Remediation</th>
        </tr>
      </thead>
      <tbody>
        {vuln_rows}
      </tbody>
    </table>
  </div>

  <!-- ── 4. CVE Intelligence ───────────────────────────────────────── -->
  <h2>4. CVE Intelligence</h2>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th>CVE ID</th>
          <th>Technology</th>
          <th>Version</th>
          <th>CVSS</th>
          <th>Severity</th>
          <th>Summary</th>
          <th>Exploit</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>
        {cve_rows}
      </tbody>
    </table>
  </div>

  <!-- ── 5. Asset Summary ──────────────────────────────────────────── -->
  <h2>5. Asset Summary</h2>
  <div class="asset-grid">
    <div class="asset-card">
      <h3>Discovered Domains</h3>
      {_ul(asset.domains)}
    </div>
    <div class="asset-card">
      <h3>Subdomains</h3>
      {_ul(asset.subdomains)}
    </div>
    <div class="asset-card">
      <h3>Services</h3>
      {_ul(asset.services)}
    </div>
    <div class="asset-card">
      <h3>Technologies</h3>
      {_ul(asset.technologies)}
    </div>
  </div>

</body>
</html>"""
