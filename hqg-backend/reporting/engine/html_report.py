"""
HQG Security Platform — HTML Report Generator
Tạo báo cáo bảo mật cấp độ intelligence, self-contained, dark theme.

Public API:
    write_html(scan_result: dict, output_path: Path) -> None
"""
from __future__ import annotations

import hashlib
import html as _html
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# XSS safety — dùng cho MỌI user-supplied data
# ---------------------------------------------------------------------------

def _safe(text) -> str:
    """HTML-escape bất kỳ giá trị nào. Never raises."""
    try:
        return _html.escape(str(text), quote=True) if text else ""
    except Exception:
        return ""


def _short_id(v: dict) -> str:
    """Stable 8-char ID derived from endpoint+vuln_type (fallback when finding_id absent)."""
    key = f"{v.get('vulnerability_type', '')}{v.get('endpoint', '')}"
    return hashlib.sha1(key.encode()).hexdigest()[:8]


# ---------------------------------------------------------------------------
# Design constants
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    "Critical": "#ff3e5e",
    "High":     "#ff7b44",
    "Medium":   "#ffb800",
    "Low":      "#00ff9d",
    "Unscored": "#8899aa",
    "None":     "#4a6a90",
}

_SEV_BG = {
    "Critical": "rgba(255,62,94,0.15)",
    "High":     "rgba(255,123,68,0.15)",
    "Medium":   "rgba(255,184,0,0.15)",
    "Low":      "rgba(0,255,157,0.12)",
    "Unscored": "rgba(136,153,170,0.15)",
    "None":     "rgba(74,106,144,0.15)",
}

_EFFORT_MAP: dict[str, str] = {
    "sqli":               "2–4 giờ",
    "time_based_sqli":    "2–4 giờ",
    "xss":                "1–2 giờ",
    "xss_stored":         "2–3 giờ",
    "cmdi":               "4–8 giờ",
    "time_based_cmdi":    "4–8 giờ",
    "ssrf":               "4–6 giờ",
    "lfi":                "2–4 giờ",
    "path_traversal":     "2–4 giờ",
    "info_disclosure":    "30 phút–1 giờ",
    "open_redirect":      "1–2 giờ",
    "cors_misconfiguration": "1–2 giờ",
    "xxe":                "2–4 giờ",
    "crlf_injection":     "1–2 giờ",
}

# ---------------------------------------------------------------------------
# CSS (module-level constant — không phải f-string)
# ---------------------------------------------------------------------------

_CSS = """\
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:14px;scroll-behavior:smooth}
body{
  background:#070b0f;color:#e8f4ff;
  font-family:system-ui,-apple-system,'Segoe UI',sans-serif;
  line-height:1.7;
}
::-webkit-scrollbar{width:5px}
::-webkit-scrollbar-track{background:#070b0f}
::-webkit-scrollbar-thumb{background:#2a4a70;border-radius:3px}

/* Sidebar */
.sidebar{
  width:260px;background:#0d1520;border-right:1px solid #1e3352;
  position:fixed;top:0;bottom:0;left:0;overflow-y:auto;
  padding:20px 0;z-index:100;
}
.sidebar-logo{padding:0 18px 18px;border-bottom:1px solid #1e3352}
.sidebar-title{
  font-size:16px;font-weight:700;letter-spacing:2px;
  color:#e8f4ff;text-transform:uppercase
}
.sidebar-sub{
  font-size:10px;color:#4a6a90;letter-spacing:1.5px;
  text-transform:uppercase;margin-top:3px
}
.toc-section{
  font-size:10px;letter-spacing:2px;color:#4a6a90;
  text-transform:uppercase;padding:14px 18px 4px
}
.toc-link{
  display:block;padding:6px 18px;font-size:12px;
  color:#8aa8cc;text-decoration:none;
  border-left:2px solid transparent;transition:all .15s
}
.toc-link:hover{color:#00d4ff;border-left-color:#00d4ff;background:rgba(0,212,255,.04)}
.toc-critical{color:#ff3e5e}
.toc-high{color:#ff7b44}
.toc-medium{color:#ffb800}
.toc-low{color:#00ff9d}
.toc-info{color:#00d4ff}

/* Main content */
.main{margin-left:260px;padding:44px 52px;max-width:1100px}

/* Hero */
.hero{margin-bottom:44px;padding-bottom:28px;border-bottom:1px solid #1e3352}
.hero-label{
  font-size:11px;letter-spacing:3px;color:#00d4ff;
  text-transform:uppercase;margin-bottom:8px
}
.hero-title{
  font-size:36px;font-weight:800;letter-spacing:.5px;line-height:1.1;
  color:#e8f4ff;margin-bottom:6px
}
.hero-target{color:#00d4ff}
.hero-meta{
  display:flex;gap:24px;flex-wrap:wrap;margin-top:16px
}
.hero-meta-item{font-size:12px;color:#8aa8cc}
.hero-meta-item strong{color:#e8f4ff}

/* Score grid */
.score-grid{
  display:grid;grid-template-columns:repeat(5,1fr);
  gap:12px;margin-bottom:40px
}
.score-card{
  background:#111d2e;border:1px solid #1e3352;
  border-radius:8px;padding:18px 14px;text-align:center
}
.score-val{
  font-size:32px;font-weight:800;line-height:1;
  letter-spacing:-1px
}
.score-lbl{
  font-size:10px;letter-spacing:1.5px;color:#4a6a90;
  margin-top:6px;text-transform:uppercase
}

/* Section */
.section{margin-bottom:52px}
.section-title{
  font-size:20px;font-weight:700;letter-spacing:2px;
  text-transform:uppercase;color:#e8f4ff;
  padding-bottom:10px;border-bottom:1px solid #1e3352;
  margin-bottom:22px
}

/* Finding block */
.finding{
  background:#111d2e;border:1px solid #1e3352;
  border-radius:8px;margin-bottom:16px;overflow:hidden
}
.finding-header{
  display:flex;align-items:center;gap:10px;
  padding:13px 16px;cursor:pointer;user-select:none;
  transition:background .15s
}
.finding-header:hover{background:#162338}
.sev-badge{
  font-size:10px;font-weight:700;letter-spacing:1.5px;
  padding:3px 9px;border-radius:3px;
  text-transform:uppercase;border:1px solid;flex-shrink:0
}
.finding-id{font-size:11px;color:#4a6a90;font-family:'SF Mono','Cascadia Code',Consolas,monospace}
.finding-cwe{
  font-size:11px;color:#8aa8cc;
  font-family:'SF Mono','Cascadia Code',Consolas,monospace
}
.finding-cvss{
  font-size:11px;background:#162338;
  padding:2px 7px;border-radius:3px;color:#8aa8cc
}
.finding-name{font-size:14px;font-weight:600;color:#e8f4ff;flex:1}
.finding-toggle{color:#4a6a90;font-size:16px;margin-left:auto;flex-shrink:0}

.finding-body{padding:16px 18px;border-top:1px solid #1e3352}
.field-label{
  font-size:10px;letter-spacing:2px;color:#4a6a90;
  text-transform:uppercase;margin-top:16px;margin-bottom:5px
}
.field-label:first-child{margin-top:0}
.field-text{font-size:13px;color:#8aa8cc;line-height:1.75}
.code-block{
  background:#040810;border:1px solid #1e3352;border-radius:5px;
  padding:12px 14px;font-family:'SF Mono','Cascadia Code',Consolas,monospace;
  font-size:12px;line-height:1.75;overflow-x:auto;color:#8aa8cc;
  white-space:pre-wrap;word-break:break-all
}
.code-inline{
  background:#162338;padding:2px 6px;border-radius:4px;
  font-family:'SF Mono','Cascadia Code',Consolas,monospace;
  font-size:12px;color:#00d4ff
}
.fix-list{
  list-style:none;margin:6px 0 0
}
.fix-list li{
  padding:5px 0;font-size:13px;color:#8aa8cc;
  display:flex;gap:8px;align-items:flex-start
}
.fix-list li::before{content:'›';color:#00d4ff;flex-shrink:0}
.conf-badge{
  display:inline-block;font-size:11px;padding:2px 9px;
  border-radius:12px;margin-top:10px
}
.conf-confirmed{background:rgba(0,255,157,.12);color:#00ff9d;border:1px solid rgba(0,255,157,.3)}
.conf-likely{background:rgba(0,212,255,.10);color:#00d4ff;border:1px solid rgba(0,212,255,.3)}
.conf-potential{background:rgba(74,106,144,.15);color:#8aa8cc;border:1px solid #2a4a70}

/* Group header */
.group-eps{
  margin-top:8px;padding:8px 12px;
  background:#070b0f;border-radius:5px;
  font-size:12px;color:#4a6a90
}
.group-eps span{
  display:block;padding:2px 0;
  font-family:'SF Mono','Cascadia Code',Consolas,monospace;font-size:11px
}

/* Callout */
.callout{
  border-radius:5px;padding:10px 14px;margin:12px 0;
  font-size:13px;display:flex;gap:8px;align-items:flex-start;
  border-left:3px solid
}
.callout-warn{
  background:rgba(255,184,0,.06);border-color:#ffb800;color:#8aa8cc
}
.callout-info{
  background:rgba(0,212,255,.05);border-color:#00d4ff;color:#8aa8cc
}

/* Table */
.data-table{width:100%;border-collapse:collapse;font-size:13px;margin:10px 0}
.data-table th{
  background:#162338;padding:9px 12px;text-align:left;
  font-size:10px;letter-spacing:1.5px;color:#4a6a90;
  text-transform:uppercase;border-bottom:1px solid #2a4a70;
  white-space:nowrap
}
.data-table td{
  padding:10px 12px;border-bottom:1px solid #1e3352;
  color:#8aa8cc;vertical-align:top
}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:hover td{background:#162338;color:#e8f4ff}
.data-table td.empty{color:#4a6a90;text-align:center;padding:24px}
.kev-pill{
  display:inline-block;background:rgba(255,62,94,.15);
  color:#ff3e5e;border:1px solid rgba(255,62,94,.4);
  font-size:10px;font-weight:700;letter-spacing:1px;
  padding:2px 8px;border-radius:3px;text-transform:uppercase
}

/* Asset section */
.metric-tiles{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
.metric-tile{
  background:#111d2e;border:1px solid #1e3352;border-radius:8px;
  padding:16px;text-align:center
}
.metric-tile-val{font-size:28px;font-weight:800;color:#00d4ff;line-height:1}
.metric-tile-lbl{font-size:10px;color:#4a6a90;letter-spacing:1.5px;text-transform:uppercase;margin-top:5px}
.tech-pills{display:flex;flex-wrap:wrap;gap:7px}
.tech-pill{
  background:#162338;border:1px solid #2a4a70;
  color:#8aa8cc;font-size:12px;padding:3px 10px;border-radius:12px
}

/* Priority badges */
.p0{color:#ff3e5e;font-weight:700}
.p1{color:#ff7b44;font-weight:700}
.p2{color:#ffb800;font-weight:700}
.p3{color:#00ff9d}

/* Attack Surface */
.as-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:22px}
.as-card{
  background:#111d2e;border:1px solid #1e3352;border-radius:8px;padding:16px
}
.as-card-title{
  font-size:10px;letter-spacing:2px;color:#4a6a90;
  text-transform:uppercase;margin-bottom:10px
}
.as-ep-row{
  display:flex;justify-content:space-between;align-items:center;
  padding:6px 0;border-bottom:1px solid #1e335220;font-size:12px
}
.as-ep-url{color:#8aa8cc;font-family:'SF Mono',Consolas,monospace;word-break:break-all}
.as-ep-score{color:#ff7b44;font-weight:700;flex-shrink:0;margin-left:8px}
.as-entry-badge{
  display:inline-block;font-size:10px;font-weight:700;
  padding:2px 8px;border-radius:3px;letter-spacing:1px;
  background:rgba(255,62,94,.12);color:#ff3e5e;border:1px solid rgba(255,62,94,.3)
}

/* Attack Paths */
.ap-scenario{
  background:#111d2e;border:1px solid #1e3352;border-radius:8px;
  margin-bottom:16px;overflow:hidden
}
.ap-header{
  display:flex;align-items:center;gap:10px;
  padding:13px 16px;border-bottom:1px solid #1e3352
}
.ap-risk{
  font-size:10px;font-weight:700;letter-spacing:1px;
  padding:3px 9px;border-radius:3px;text-transform:uppercase
}
.ap-title{font-size:14px;font-weight:600;color:#e8f4ff;flex:1}
.ap-body{padding:16px 18px}
.ap-step{
  display:flex;gap:12px;align-items:flex-start;
  padding:8px 0;border-bottom:1px solid #1e335220
}
.ap-step:last-child{border-bottom:none}
.ap-step-num{
  background:#162338;border:1px solid #2a4a70;
  color:#00d4ff;font-size:11px;font-weight:700;
  width:24px;height:24px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;flex-shrink:0
}
.ap-step-detail{flex:1;font-size:13px;color:#8aa8cc}
.ap-step-vuln{color:#e8f4ff;font-weight:600}
.ap-step-finding{
  font-size:11px;color:#4a6a90;
  font-family:'SF Mono',Consolas,monospace
}

/* Footer */
.footer{
  text-align:center;font-size:11px;color:#4a6a90;
  padding:28px 0;border-top:1px solid #1e3352;margin-top:44px
}

/* Anchor offset for fixed sidebar */
.anchor{display:block;position:relative;top:-24px;visibility:hidden}

/* Asset Intelligence section */
.ai-host-block{
  background:#111d2e;border:1px solid #1e3352;border-radius:8px;
  margin-bottom:16px;overflow:hidden
}
.ai-host-header{
  display:flex;align-items:center;gap:10px;
  padding:14px 18px;cursor:pointer;user-select:none;
  transition:background .15s
}
.ai-host-header:hover{background:#162338}
.ai-host-name{
  font-size:15px;font-weight:700;color:#e8f4ff;flex:1;
  font-family:'SF Mono','Cascadia Code',Consolas,monospace
}
.ai-risk-bar-wrap{width:80px;background:#1e3352;border-radius:3px;height:6px;margin-right:4px;flex-shrink:0}
.ai-risk-bar{height:6px;border-radius:3px}
.ai-risk-score{
  font-size:13px;font-weight:800;font-family:'SF Mono',Consolas,monospace;
  width:36px;text-align:right;flex-shrink:0
}
.ai-host-body{padding:16px 18px;border-top:1px solid #1e3352}
.ai-sub-title{
  font-size:10px;letter-spacing:2px;color:#4a6a90;
  text-transform:uppercase;margin:14px 0 8px
}
.ai-sub-title:first-child{margin-top:0}
.ai-vuln-group{
  background:#0d1520;border:1px solid #1e3352;border-radius:6px;
  margin-bottom:8px;overflow:hidden
}
.ai-vuln-group-header{
  display:flex;align-items:center;gap:8px;
  padding:9px 14px;background:#162338;
  font-size:12px;font-weight:600;color:#e8f4ff
}
.ai-vuln-row{
  display:flex;align-items:center;gap:8px;
  padding:7px 14px;border-top:1px solid #1e335228;
  font-size:12px;color:#8aa8cc
}
.ai-vuln-ep{
  font-family:'SF Mono',Consolas,monospace;font-size:11px;
  color:#4a6a90;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap
}
.ai-vuln-param{
  background:#162338;border:1px solid #2a4a70;border-radius:3px;
  font-family:'SF Mono',Consolas,monospace;font-size:10px;
  color:#00d4ff;padding:1px 6px;flex-shrink:0
}
.conf-badge-raw{
  display:inline-block;font-size:10px;font-weight:700;letter-spacing:1px;
  padding:2px 8px;border-radius:3px;text-transform:uppercase;flex-shrink:0
}
.conf-raw-confirmed{background:rgba(255,62,94,.15);color:#ff3e5e;border:1px solid rgba(255,62,94,.4)}
.conf-raw-high{background:rgba(255,123,68,.15);color:#ff7b44;border:1px solid rgba(255,123,68,.4)}
.conf-raw-medium{background:rgba(255,184,0,.12);color:#ffb800;border:1px solid rgba(255,184,0,.4)}
.conf-raw-low{background:rgba(74,106,144,.15);color:#8aa8cc;border:1px solid #2a4a70}
.ai-summary-pills{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:6px}
"""

_JS = """\
function toggleDetail(id){
  var el=document.getElementById(id);
  if(!el)return;
  el.style.display=(el.style.display==='none'?'block':'none');
  var btn=el.previousElementSibling&&el.previousElementSibling.querySelector('.finding-toggle');
  if(btn)btn.textContent=(el.style.display==='none'?'▶':'▼');
}
document.addEventListener('DOMContentLoaded',function(){
  document.querySelectorAll('a[href^="#"]').forEach(function(a){
    a.addEventListener('click',function(e){
      var t=document.querySelector(this.getAttribute('href'));
      if(t){e.preventDefault();t.scrollIntoView({behavior:'smooth',block:'start'});}
    });
  });
});
"""


# ---------------------------------------------------------------------------
# Helper renderers
# ---------------------------------------------------------------------------

def _sev_badge(severity: str) -> str:
    color = _SEV_COLOR.get(severity, "#4a6a90")
    bg    = _SEV_BG.get(severity, "rgba(74,106,144,.15)")
    s     = _safe(severity) or "N/A"
    return (
        f'<span class="sev-badge" '
        f'style="color:{color};background:{bg};border-color:{color}40">'
        f'{s}</span>'
    )


def _conf_badge(label: str) -> str:
    cls_map = {
        "Confirmed": "conf-confirmed",
        "Likely":    "conf-likely",
        "Potential": "conf-potential",
    }
    cls = cls_map.get(label, "conf-potential")
    label_vn = {"Confirmed": "Đã xác nhận", "Likely": "Có khả năng", "Potential": "Tiềm năng"}.get(label, label)
    return f'<span class="conf-badge {cls}">{_safe(label_vn)}</span>'


def _conf_badge_raw(confidence: str) -> str:
    """Badge for raw asset-intelligence confidence values: confirmed/high/medium/low."""
    key = (confidence or "").lower()
    cls_map = {
        "confirmed": "conf-raw-confirmed",
        "high":      "conf-raw-high",
        "medium":    "conf-raw-medium",
        "low":       "conf-raw-low",
    }
    label_map = {
        "confirmed": "CONFIRMED",
        "high":      "HIGH",
        "medium":    "MEDIUM",
        "low":       "LOW",
    }
    cls   = cls_map.get(key, "conf-raw-low")
    label = label_map.get(key, key.upper() or "?")
    return f'<span class="conf-badge-raw {cls}">{_safe(label)}</span>'


def _risk_level(score: float) -> tuple[str, str]:
    """Return (label, hex_color) for a 0-100 risk score."""
    if score >= 80:
        return "Critical", "#ff3e5e"
    if score >= 60:
        return "High", "#ff7b44"
    if score >= 40:
        return "Medium", "#ffb800"
    return "Low", "#00ff9d"


def _priority_label(cvss: float) -> tuple[str, str]:
    """Return (css_class, label) for remediation roadmap."""
    if cvss >= 9.0:
        return "p0", "P0 — Ngay"
    if cvss >= 7.0:
        return "p1", "P1 — Sprint 1"
    if cvss >= 4.0:
        return "p2", "P2 — Sprint 2"
    return "p3", "P3 — Sprint 3"


def _duration_str(started: str, completed: str) -> str:
    """Parse ISO timestamps and return human duration string."""
    try:
        fmt = "%Y-%m-%dT%H:%M:%S"
        s = datetime.fromisoformat(started.replace("Z", "+00:00"))
        e = datetime.fromisoformat(completed.replace("Z", "+00:00"))
        secs = int((e - s).total_seconds())
        if secs < 60:
            return f"{secs}s"
        if secs < 3600:
            return f"{secs // 60}m {secs % 60}s"
        return f"{secs // 3600}h {(secs % 3600) // 60}m"
    except Exception:
        return "N/A"


def _score_color(score: float) -> str:
    if score >= 70:
        return "#00ff9d"
    if score >= 40:
        return "#ffb800"
    return "#ff3e5e"


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_sidebar(vulns: list[dict]) -> str:
    # Build TOC items for finding groups
    toc_findings: list[str] = []

    # Group by severity for TOC sections
    sev_order = ["Critical", "High", "Medium", "Low", "Unscored"]
    by_sev: dict[str, list[dict]] = defaultdict(list)
    for v in vulns:
        sev = str(v.get("severity", "Low"))
        by_sev[sev].append(v)

    toc_cls = {
        "Critical": "toc-critical",
        "High":     "toc-high",
        "Medium":   "toc-medium",
        "Low":      "toc-low",
        "Unscored": "toc-info",
    }

    for sev in sev_order:
        group = by_sev.get(sev, [])
        if not group:
            continue
        toc_findings.append(
            f'<div class="toc-section">{_safe(sev)} ({len(group)})</div>'
        )
        seen_types: set[str] = set()
        for v in group[:8]:  # cap TOC entries per severity
            vt = str(v.get("vulnerability_type", ""))
            fid = str(v.get("finding_id", ""))[:8] or _short_id(v)
            name = str(v.get("vulnerability_type", "Unknown")).replace("_", " ").title()
            anchor = f"f-{fid}"
            if vt not in seen_types:
                seen_types.add(vt)
            toc_findings.append(
                f'<a class="toc-link {toc_cls.get(sev, "toc-info")}" href="#{_safe(anchor)}">'
                f'{_safe(fid)} · {_safe(name)}</a>'
            )

    return (
        '<nav class="sidebar">'
        '<div class="sidebar-logo">'
        '<div class="sidebar-title">🛡 HQG Security</div>'
        '<div class="sidebar-sub">Security Assessment Report</div>'
        '</div>'
        '<div class="toc-section">Tổng Quan</div>'
        '<a class="toc-link toc-info" href="#overview">Dashboard</a>'
        '<a class="toc-link toc-info" href="#findings">Lỗ Hổng Bảo Mật</a>'
        '<a class="toc-link toc-info" href="#cve">CVE Intelligence</a>'
        '<a class="toc-link toc-info" href="#asset-intelligence">Asset Intelligence</a>'
        '<a class="toc-link toc-info" href="#attack-surface">Bề Mặt Tấn Công</a>'
        '<a class="toc-link toc-info" href="#attack-paths">Kịch Bản Tấn Công</a>'
        '<a class="toc-link toc-info" href="#assets">Tài Sản</a>'
        '<a class="toc-link toc-info" href="#roadmap">Lộ Trình Khắc Phục</a>'
        + "".join(toc_findings) +
        '</nav>'
    )


def _render_hero(scan_result: dict, duration: str) -> str:
    target     = _safe(scan_result.get("target", ""))
    mode       = _safe(scan_result.get("scan_mode", "standard")).title()
    started    = _safe(str(scan_result.get("started_at", ""))[:10])
    version    = _safe(scan_result.get("scanner_version", "1.0.0"))
    asset_sum  = scan_result.get("asset_summary") or {}
    n_ep       = int(asset_sum.get("total_endpoints", 0))
    n_tech     = len(asset_sum.get("technologies") or [])

    return (
        '<div class="hero">'
        '<div class="hero-label">Báo Cáo Phân Tích Bảo Mật</div>'
        f'<div class="hero-title">Phân Tích Bề Mặt Tấn Công<br>'
        f'<span class="hero-target">{target}</span></div>'
        '<div class="hero-meta">'
        f'<div class="hero-meta-item"><strong>Chế độ quét:</strong> {mode}</div>'
        f'<div class="hero-meta-item"><strong>Ngày quét:</strong> {started}</div>'
        f'<div class="hero-meta-item"><strong>Thời lượng:</strong> {_safe(duration)}</div>'
        f'<div class="hero-meta-item"><strong>Phiên bản:</strong> {version}</div>'
        f'<div class="hero-meta-item"><strong>Endpoints:</strong> {n_ep}</div>'
        f'<div class="hero-meta-item"><strong>Công nghệ:</strong> {n_tech}</div>'
        '</div>'
        '</div>'
    )


def _render_score_grid(risk: dict) -> str:
    overall  = float(risk.get("overall_score", 0.0))
    # Support both "critical_count" (legacy) and "critical" (canonical) key names
    critical = int(risk.get("critical_count") or risk.get("critical", 0))
    high     = int(risk.get("high_count")     or risk.get("high",     0))
    medium   = int(risk.get("medium_count")   or risk.get("medium",   0))
    low      = int(risk.get("low_count")      or risk.get("low",      0))
    o_color  = _score_color(overall)

    def _card(val: str, label: str, color: str, extra_border: str = "") -> str:
        border = f"border-color:{extra_border or color}40" if color else ""
        return (
            f'<div class="score-card" style="{border}">'
            f'<div class="score-val" style="color:{color}">{_safe(val)}</div>'
            f'<div class="score-lbl">{_safe(label)}</div>'
            f'</div>'
        )

    return (
        '<a class="anchor" id="overview"></a>'
        '<div class="score-grid">'
        + _card(f"{overall:.1f}/100", "Điểm Rủi Ro", o_color)
        + _card(str(critical), "Critical",  "#ff3e5e")
        + _card(str(high),     "High",      "#ff7b44")
        + _card(str(medium),   "Medium",    "#ffb800")
        + _card(str(low),      "Low",       "#00ff9d")
        + '</div>'
    )


def _render_false_positive_removed(scan_result: dict) -> str:
    removed = int(scan_result.get("false_positive_removed", 0))
    if removed <= 0:
        return ""
    return (
        '<div class="callout callout-info" style="margin-bottom:24px">'
        '<span>ℹ</span>'
        f'<span>{removed} false positives removed from this report.</span>'
        '</div>'
    )


def _render_single_finding(v: dict, detail_id: str, is_open: bool) -> str:
    sev        = str(v.get("severity", "Unscored"))
    fid        = str(v.get("finding_id", ""))[:8] or _short_id(v)
    cwe        = _safe(v.get("cwe_id", ""))
    owasp      = _safe(v.get("owasp_category", ""))
    owasp_src  = _safe(v.get("owasp_source", ""))
    raw_cvss   = v.get("cvss_score")
    cvss       = float(raw_cvss) if raw_cvss is not None else None
    vuln_name  = str(v.get("vulnerability_type", "")).replace("_", " ").title()
    explanation= _safe(v.get("explanation", ""))
    impact     = _safe(v.get("impact", ""))
    evidence   = str(v.get("evidence", ""))[:600]
    payload    = _safe(v.get("payload", ""))
    endpoint   = _safe(v.get("endpoint", ""))
    parameter  = _safe(v.get("parameter", "")) or "—"
    conf_lbl   = str(v.get("confidence_label", v.get("confidence_label_text", "")))
    fp_like    = float(v.get("false_positive_likelihood", 0.0))
    fixes      = v.get("fix_recommendation") or []

    display   = "block" if is_open else "none"
    toggle_ic = "▼" if is_open else "▶"

    # Fix list
    fix_items = "".join(
        f'<li>{_safe(fx)}</li>' for fx in fixes if fx
    ) if fixes else f'<li>Xem hướng dẫn bảo mật cho {_safe(vuln_name)}</li>'

    # FP callout
    fp_callout = ""
    if fp_like > 0.5:
        fp_callout = (
            '<div class="callout callout-warn">'
            '<span>⚠</span>'
            f'<span>Khả năng false positive cao ({fp_like:.0%}). '
            'Nên xác minh thủ công trước khi xử lý.</span>'
            '</div>'
        )

    return (
        f'<div class="finding" id="f-{_safe(fid)}">'
        # Header (clickable toggle)
        f'<div class="finding-header" onclick="toggleDetail(\'{_safe(detail_id)}\')">'
        + _sev_badge(sev) +
        f'<span class="finding-id">{_safe(fid)}</span>'
        f'<span class="finding-cwe">{cwe}</span>'
        f'<span class="finding-cwe">{owasp}'
        + (f' <span style="font-size:9px;opacity:0.6">({owasp_src})</span>' if owasp_src else '') +
        f'</span>'
        + (f'<span class="finding-cvss">CVSS {cvss:.1f}</span>' if cvss is not None and cvss > 0 else '<span class="finding-cvss" style="color:#8899aa">Unscored</span>') +
        f'<span class="finding-name">{_safe(vuln_name)}</span>'
        f'<span class="finding-toggle">{toggle_ic}</span>'
        '</div>'
        # Body (collapsible)
        f'<div class="finding-body" id="{_safe(detail_id)}" style="display:{display}">'
        # Mô tả
        '<div class="field-label">Mô Tả</div>'
        f'<div class="field-text">{explanation}</div>'
        # Tác động
        '<div class="field-label">Tác Động</div>'
        f'<div class="field-text">{impact}</div>'
        # Evidence
        '<div class="field-label">Evidence</div>'
        f'<div class="code-block">{_safe(evidence).replace(chr(10), "<br>") if evidence.strip() else "(không có evidence)"}</div>'
        # Payload
        '<div class="field-label">Payload</div>'
        f'<div class="field-text"><code class="code-inline">{payload if payload else "—"}</code></div>'
        # Endpoint
        '<div class="field-label">Endpoint</div>'
        f'<div class="field-text">{endpoint}</div>'
        # Tham số
        '<div class="field-label">Tham Số</div>'
        f'<div class="field-text"><code class="code-inline">{parameter}</code></div>'
        # Khắc phục
        '<div class="field-label">Khắc Phục</div>'
        f'<ol class="fix-list">{fix_items}</ol>'
        # Confidence + FP
        + _conf_badge(conf_lbl)
        + fp_callout +
        '</div>'
        '</div>'
    )


def _render_findings_section(vulns: list[dict]) -> str:
    if not vulns:
        return (
            '<a class="anchor" id="findings"></a>'
            '<div class="section">'
            '<div class="section-title">Lỗ Hổng Bảo Mật</div>'
            '<div class="callout callout-info">'
            '<span>ℹ</span><span>Không phát hiện lỗ hổng nào trong lần quét này.</span>'
            '</div></div>'
        )

    # Sort by cvss_score desc (None/0 → bottom)
    sorted_vulns = sorted(vulns, key=lambda v: float(v.get("cvss_score") or 0), reverse=True)

    # Group by (vulnerability_type, parameter) for deduplication
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for v in sorted_vulns:
        key = (str(v.get("vulnerability_type", "")), str(v.get("parameter", "")))
        groups[key].append(v)

    parts = [
        '<a class="anchor" id="findings"></a>',
        '<div class="section">',
        '<div class="section-title">Lỗ Hổng Bảo Mật</div>',
    ]

    block_idx = 0
    for key, group_vulns in groups.items():
        primary = group_vulns[0]
        sev     = str(primary.get("severity", "Low"))
        is_open = sev in ("Critical", "High")
        detail_id = f"detail-{block_idx}"
        block_idx += 1

        if len(group_vulns) >= 2:
            # Grouped block: same vuln_type + parameter, multiple endpoints
            fid       = str(primary.get("finding_id", ""))[:8] or _short_id(primary)
            cwe       = _safe(primary.get("cwe_id", ""))
            owasp     = _safe(primary.get("owasp_category", ""))
            owasp_src = _safe(primary.get("owasp_source", ""))
            _raw_cvss = primary.get("cvss_score")
            cvss      = float(_raw_cvss) if _raw_cvss is not None else None
            vuln_name = str(primary.get("vulnerability_type", "")).replace("_", " ").title()
            explanation = _safe(primary.get("explanation", ""))
            impact      = _safe(primary.get("impact", ""))
            payload     = _safe(primary.get("payload", ""))
            parameter   = _safe(primary.get("parameter", "")) or "—"
            conf_lbl    = str(primary.get("confidence_label", primary.get("confidence_label_text", "")))
            fixes       = primary.get("fix_recommendation") or []
            fp_like     = float(primary.get("false_positive_likelihood", 0.0))

            display   = "block" if is_open else "none"
            toggle_ic = "▼" if is_open else "▶"

            fix_items = "".join(f'<li>{_safe(fx)}</li>' for fx in fixes if fx)
            fp_callout = ""
            if fp_like > 0.5:
                fp_callout = (
                    '<div class="callout callout-warn"><span>⚠</span>'
                    f'<span>Khả năng false positive cao ({fp_like:.0%}). Xác minh thủ công.</span></div>'
                )

            ep_list = "".join(
                f'<span>{_safe(str(gv.get("endpoint", "")))}</span>'
                for gv in group_vulns
            )

            parts.append(
                f'<div class="finding" id="f-{_safe(fid)}">'
                f'<div class="finding-header" onclick="toggleDetail(\'{_safe(detail_id)}\')">'
                + _sev_badge(sev) +
                f'<span class="finding-id">{_safe(fid)}</span>'
                f'<span class="finding-cwe">{cwe}</span>'
                f'<span class="finding-cwe">{owasp}'
                + (f' <span style="font-size:9px;opacity:0.6">({owasp_src})</span>' if owasp_src else '') +
                f'</span>'
                + (f'<span class="finding-cvss">CVSS {cvss:.1f}</span>' if cvss is not None and cvss > 0 else '<span class="finding-cvss" style="color:#8899aa">Unscored</span>') +
                f'<span class="finding-name">{_safe(vuln_name)}'
                f' <span style="color:#4a6a90;font-size:12px">({len(group_vulns)} endpoints)</span></span>'
                f'<span class="finding-toggle">{toggle_ic}</span>'
                '</div>'
                f'<div class="finding-body" id="{_safe(detail_id)}" style="display:{display}">'
                '<div class="field-label">Endpoints Bị Ảnh Hưởng</div>'
                f'<div class="group-eps">{ep_list}</div>'
                '<div class="field-label">Mô Tả</div>'
                f'<div class="field-text">{explanation}</div>'
                '<div class="field-label">Tác Động</div>'
                f'<div class="field-text">{impact}</div>'
                '<div class="field-label">Payload Mẫu</div>'
                f'<div class="field-text"><code class="code-inline">{payload if payload else "—"}</code></div>'
                '<div class="field-label">Tham Số</div>'
                f'<div class="field-text"><code class="code-inline">{parameter}</code></div>'
                '<div class="field-label">Khắc Phục</div>'
                f'<ol class="fix-list">{fix_items}</ol>'
                + _conf_badge(conf_lbl)
                + fp_callout +
                '</div></div>'
            )
        else:
            # Single finding block
            parts.append(_render_single_finding(primary, detail_id, is_open))

    parts.append('</div>')
    return "".join(parts)


def _render_cve_section(cve_list: list[dict]) -> str:
    parts = [
        '<a class="anchor" id="cve"></a>',
        '<div class="section">',
        '<div class="section-title">CVE Intelligence</div>',
    ]

    if not cve_list:
        parts.append(
            '<div class="callout callout-info">'
            '<span>ℹ</span>'
            '<span>Không tìm thấy CVE liên quan đến các công nghệ được phát hiện.</span>'
            '</div>'
        )
    else:
        parts.append('<div style="overflow-x:auto"><table class="data-table"><thead><tr>')
        for th in ["CVE ID", "Công Nghệ", "Phiên Bản", "CVSS", "Mức Độ", "KEV", "Ngày Công Bố", "Mô Tả"]:
            parts.append(f'<th>{_safe(th)}</th>')
        parts.append('</tr></thead><tbody>')

        for c in cve_list:
            cve_id  = _safe(c.get("cve_id", ""))
            tech    = _safe(c.get("technology", ""))
            ver     = _safe(c.get("version", "")) or "—"
            cvss    = float(c.get("cvss", 0.0))
            sev     = str(c.get("severity", ""))
            pub     = _safe(str(c.get("published_date", ""))[:10])
            summary = _safe(str(c.get("summary", ""))[:180])
            is_kev  = bool(c.get("is_actively_exploited") or c.get("exploit_available"))
            sev_color = _SEV_COLOR.get(sev, "#4a6a90")

            kev_cell = '<span class="kev-pill">ĐANG BỊ KHAI THÁC</span>' if is_kev else '—'

            parts.append(
                f'<tr>'
                f'<td><code class="code-inline">{cve_id}</code></td>'
                f'<td>{tech}</td>'
                f'<td>{ver}</td>'
                f'<td style="color:{sev_color};font-weight:700">{cvss:.1f}</td>'
                f'<td>{_sev_badge(sev)}</td>'
                f'<td>{kev_cell}</td>'
                f'<td>{pub}</td>'
                f'<td>{summary}</td>'
                f'</tr>'
            )

        parts.append('</tbody></table></div>')

    parts.append('</div>')
    return "".join(parts)


def _render_tech_grid(wap_techs: list[dict]) -> str:
    """Render a Wappalyzer-style technology grid with name, version, CPE, categories."""
    if not wap_techs:
        return '<span style="color:#4a6a90">Không phát hiện</span>'

    cards = []
    for t in wap_techs:
        name     = _safe(t.get("name", ""))
        version  = _safe(t.get("version") or "")
        cpe      = _safe(t.get("cpe") or "")
        cats     = t.get("categories") or []
        cat_str  = _safe(", ".join(str(c) for c in cats[:2]) if cats else "")

        ver_badge = (
            f'<span style="background:#0e3a5c;color:#38bdf8;border-radius:4px;'
            f'padding:1px 6px;font-size:10px;font-family:monospace;font-weight:700">'
            f'{version}</span>'
        ) if version else ""

        cpe_line = (
            f'<div style="font-size:9px;color:#2a4a6a;font-family:monospace;'
            f'margin-top:3px;word-break:break-all">{cpe}</div>'
        ) if cpe else ""

        cards.append(
            f'<div style="background:#0d1e30;border:1px solid #1e3352;border-radius:8px;'
            f'padding:10px 12px;min-width:140px">'
            f'<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
            f'<span style="font-size:13px;font-weight:600;color:#e8f4ff">{name}</span>'
            f'{ver_badge}</div>'
            f'<div style="font-size:10px;color:#4a6a90">{cat_str}</div>'
            f'{cpe_line}'
            f'</div>'
        )

    return (
        '<div style="display:flex;flex-wrap:wrap;gap:8px">'
        + "".join(cards)
        + '</div>'
    )


def _render_asset_section(asset_summary: dict) -> str:
    domains     = asset_summary.get("domains") or []
    subdoms     = asset_summary.get("subdomains") or []
    n_ep        = int(asset_summary.get("total_endpoints", 0))
    wap_techs   = asset_summary.get("wappalyzer_technologies") or []
    plain_techs = asset_summary.get("technologies") or []
    n_techs     = len(wap_techs) if wap_techs else len(plain_techs)

    # Choose best rendering: rich Wappalyzer grid or fallback plain pills
    if wap_techs:
        tech_block = _render_tech_grid(wap_techs)
    elif plain_techs:
        tech_block = (
            '<div class="tech-pills">'
            + "".join(f'<span class="tech-pill">{_safe(t)}</span>' for t in plain_techs)
            + '</div>'
        )
    else:
        tech_block = '<span style="color:#4a6a90">Không phát hiện</span>'

    def _domain_list(items: list) -> str:
        if not items:
            return '<span style="color:#4a6a90;font-size:12px">Không có</span>'
        return "".join(
            f'<div style="font-size:12px;color:#8aa8cc;padding:2px 0;'
            f'font-family:\'SF Mono\',Consolas,monospace">{_safe(str(d))}</div>'
            for d in items[:20]
        )

    return (
        '<a class="anchor" id="assets"></a>'
        '<div class="section">'
        '<div class="section-title">Tài Sản &amp; Công Nghệ</div>'
        '<div class="metric-tiles">'
        f'<div class="metric-tile"><div class="metric-tile-val">{len(domains)}</div>'
        '<div class="metric-tile-lbl">Tên Miền</div></div>'
        f'<div class="metric-tile"><div class="metric-tile-val">{len(subdoms)}</div>'
        '<div class="metric-tile-lbl">Tên Miền Phụ</div></div>'
        f'<div class="metric-tile"><div class="metric-tile-val">{n_ep}</div>'
        '<div class="metric-tile-lbl">Endpoints</div></div>'
        f'<div class="metric-tile"><div class="metric-tile-val">{n_techs}</div>'
        '<div class="metric-tile-lbl">Công Nghệ</div></div>'
        '</div>'
        '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">'
        f'<div style="background:#111d2e;border:1px solid #1e3352;border-radius:8px;padding:16px">'
        '<div style="font-size:11px;letter-spacing:2px;color:#4a6a90;text-transform:uppercase;margin-bottom:10px">Tên Miền</div>'
        + _domain_list(domains) +
        '</div>'
        f'<div style="background:#111d2e;border:1px solid #1e3352;border-radius:8px;padding:16px">'
        '<div style="font-size:11px;letter-spacing:2px;color:#4a6a90;text-transform:uppercase;margin-bottom:10px">Tên Miền Phụ</div>'
        + _domain_list(subdoms) +
        '</div>'
        '</div>'
        '<div style="background:#111d2e;border:1px solid #1e3352;border-radius:8px;padding:16px">'
        '<div style="font-size:11px;letter-spacing:2px;color:#4a6a90;text-transform:uppercase;margin-bottom:12px">'
        'Công Nghệ Phát Hiện'
        + (' <span style="font-size:10px;color:#38bdf8;margin-left:6px">⚡ Wappalyzer</span>' if wap_techs else '')
        + '</div>'
        + tech_block
        + '</div>'
        '</div>'
    )


def _render_asset_intelligence_section(assets: list[dict]) -> str:
    """
    Render a collapsible per-host asset intelligence section.

    Each host block shows:
      - Hostname + risk score bar + risk level badge
      - Confidence summary (highest-severity finding)
      - Technology pills
      - Vulnerabilities grouped by type (with endpoint + confidence per finding)
      - CVE table with KEV badge
    """
    if not assets:
        return ""

    # Sort by priority: KEV > max CVSS > confirmed vuln count
    def _asset_sort_key(a: dict) -> tuple:
        kev = 1 if a.get("has_kev") or any(c.get("is_actively_exploited") for c in (a.get("cves") or [])) else 0
        max_cvss = float(a.get("max_cvss") or max((c.get("cvss", 0) for c in (a.get("cves") or [])), default=0))
        confirmed = int(a.get("confirmed_vuln_count", 0))
        return (kev, max_cvss, confirmed)

    sorted_assets = sorted(assets, key=_asset_sort_key, reverse=True)

    VULN_DISPLAY: dict[str, str] = {
        "sqli":            "SQL Injection",
        "time_based_sqli": "SQL Injection (Time-Based)",
        "sqli_error":      "SQL Injection (Error-Based)",
        "xss":             "Cross-Site Scripting",
        "xss_reflected":   "XSS (Reflected)",
        "xss_stored":      "XSS (Stored)",
        "cmdi":            "Command Injection",
        "lfi":             "Local File Inclusion",
        "path_traversal":  "Path Traversal",
        "ssrf":            "Server-Side Request Forgery",
        "open_redirect":   "Open Redirect",
        "info_disclosure": "Information Disclosure",
    }

    CONF_ORDER = ["confirmed", "high", "medium", "low"]

    def _top_confidence(vulns: list[dict]) -> str:
        best = "low"
        for v in vulns:
            c = (v.get("confidence") or "low").lower()
            if CONF_ORDER.index(c) < CONF_ORDER.index(best):
                best = c
        return best

    parts = [
        '<a class="anchor" id="asset-intelligence"></a>',
        '<div class="section">',
        '<div class="section-title">Asset Intelligence</div>',
        '<div class="callout callout-info" style="margin-bottom:20px">'
        '<span>🎯</span>'
        '<span>Phân tích rủi ro theo từng host — ưu tiên: KEV → CVSS → lỗ hổng đã xác nhận. '
        'Click vào host để xem chi tiết.</span>'
        '</div>',
    ]

    for idx, asset in enumerate(sorted_assets):
        host       = _safe(asset.get("host", "unknown"))
        vulns      = asset.get("vulnerabilities") or []
        techs      = asset.get("technologies") or []
        cves       = asset.get("cves") or []
        endpoints  = asset.get("endpoints") or []
        block_id   = f"ai-block-{idx}"
        top_conf   = _top_confidence(vulns)
        has_kev    = asset.get("has_kev") or any(c.get("is_actively_exploited") for c in cves)
        max_cvss   = asset.get("max_cvss")
        if max_cvss is None and cves:
            max_cvss = max((float(c.get("cvss", 0)) for c in cves), default=None)

        # Derive priority label from real signals
        if has_kev:
            _plabel, _pcolor = "KEV", "#ff3e5e"
        elif max_cvss is not None and max_cvss >= 9.0:
            _plabel, _pcolor = "Critical", "#ff3e5e"
        elif max_cvss is not None and max_cvss >= 7.0:
            _plabel, _pcolor = "High", "#ff7b44"
        elif vulns:
            _plabel, _pcolor = "Medium", "#ffb800"
        else:
            _plabel, _pcolor = "Low", "#00ff9d"

        # ── Header ────────────────────────────────────────────────────────
        parts.append(
            f'<div class="ai-host-block">'
            f'<div class="ai-host-header" onclick="toggleDetail(\'{block_id}\')">'
            # Priority badge
            f'<span class="sev-badge" style="color:{_pcolor};background:{_pcolor}22;'
            f'border-color:{_pcolor}55">{_safe(_plabel)}</span>'
            # Hostname
            f'<span class="ai-host-name">{host}</span>'
            # Top confidence (only when vulns exist)
        )
        if vulns:
            parts.append(_conf_badge_raw(top_conf))
        # Stats pills
        parts.append(
            '<div class="ai-summary-pills">'
        )
        if vulns:
            parts.append(
                f'<span style="font-size:11px;color:#8aa8cc">'
                f'🐛 {len(vulns)} vuln{"s" if len(vulns) != 1 else ""}</span>'
            )
        if cves:
            kev_count = sum(1 for c in cves if c.get("is_actively_exploited"))
            kev_txt = f" ({kev_count} KEV)" if kev_count else ""
            parts.append(
                f'<span style="font-size:11px;color:#8aa8cc">'
                f'🔴 {len(cves)} CVE{"s" if len(cves) != 1 else ""}{kev_txt}</span>'
            )
        parts.append('</div>')
        # Max CVSS display (replaces fake risk bar)
        if max_cvss is not None:
            bar_pct = min(100, max(0, max_cvss * 10))
            parts.append(
                f'<div class="ai-risk-bar-wrap">'
                f'<div class="ai-risk-bar" style="width:{bar_pct:.0f}%;background:{_pcolor}"></div>'
                f'</div>'
                f'<span class="ai-risk-score" style="color:{_pcolor}">CVSS {max_cvss:.1f}</span>'
            )
        if has_kev:
            parts.append(
                '<span style="font-size:10px;font-weight:700;color:#ff3e5e;background:rgba(255,62,94,0.15);'
                'border:1px solid rgba(255,62,94,0.3);border-radius:4px;padding:2px 6px;margin-left:4px">'
                'KEV</span>'
            )
        parts.append(
            f'<span class="finding-toggle">▶</span>'
            f'</div>'  # /ai-host-header
        )

        # ── Collapsible body ──────────────────────────────────────────────
        parts.append(f'<div class="ai-host-body" id="{block_id}" style="display:none">')

        # Technologies
        if techs:
            parts.append('<div class="ai-sub-title">Công Nghệ</div>')
            parts.append('<div class="tech-pills">')
            for tech in techs:
                name    = _safe(tech.get("name", ""))
                version = _safe(tech.get("version") or "")
                ver_str = f" <span style='font-size:10px;color:#38bdf8'>{version}</span>" if version else ""
                parts.append(f'<span class="tech-pill">{name}{ver_str}</span>')
            parts.append('</div>')

        # Vulnerabilities grouped by type
        if vulns:
            parts.append(
                f'<div class="ai-sub-title">Lỗ Hổng ({len(vulns)})</div>'
            )
            # Group by type
            groups: dict[str, list[dict]] = defaultdict(list)
            for v in vulns:
                key = VULN_DISPLAY.get(str(v.get("type", "")), str(v.get("type", "")).replace("_", " ").title())
                groups[key].append(v)

            # Sort groups: confirmed findings first, then by count
            def _group_sort_key(item: tuple[str, list[dict]]) -> tuple[int, int]:
                _, gvulns = item
                confirmed = sum(1 for gv in gvulns if (gv.get("confidence") or "").lower() == "confirmed")
                return (-confirmed, -len(gvulns))

            for type_name, group_vulns in sorted(groups.items(), key=_group_sort_key):
                # Highest severity in this group
                sev_order = ["critical", "high", "medium", "low"]
                group_sev = min(
                    group_vulns,
                    key=lambda gv: sev_order.index((gv.get("severity") or "low").lower())
                    if (gv.get("severity") or "low").lower() in sev_order else 3
                ).get("severity", "Low")
                g_color = _SEV_COLOR.get(str(group_sev).capitalize(), "#4a6a90")
                confirmed_count = sum(1 for gv in group_vulns if (gv.get("confidence") or "").lower() == "confirmed")

                parts.append(
                    f'<div class="ai-vuln-group">'
                    f'<div class="ai-vuln-group-header">'
                    + _sev_badge(str(group_sev).capitalize()) +
                    f'<span style="flex:1">{_safe(type_name)}</span>'
                    f'<span style="color:#4a6a90;font-size:11px">'
                    f'{len(group_vulns)} finding{"s" if len(group_vulns) != 1 else ""}</span>'
                )
                if confirmed_count > 0:
                    parts.append(
                        f'<span class="conf-badge-raw conf-raw-confirmed">'
                        f'{confirmed_count} confirmed</span>'
                    )
                parts.append('</div>')  # /ai-vuln-group-header

                # Sort findings: confirmed first
                sorted_vulns = sorted(
                    group_vulns,
                    key=lambda gv: CONF_ORDER.index((gv.get("confidence") or "low").lower())
                    if (gv.get("confidence") or "low").lower() in CONF_ORDER else 3
                )
                for v in sorted_vulns:
                    ep    = _safe(v.get("endpoint", ""))
                    param = _safe(v.get("parameter", ""))
                    conf  = (v.get("confidence") or "low").lower()
                    parts.append(
                        f'<div class="ai-vuln-row">'
                        + _conf_badge_raw(conf) +
                        f'<span class="ai-vuln-ep">{ep}</span>'
                    )
                    if param:
                        parts.append(f'<span class="ai-vuln-param">{param}</span>')
                    parts.append('</div>')

                parts.append('</div>')  # /ai-vuln-group
        else:
            parts.append(
                '<div style="color:#4a6a90;font-size:12px;padding:8px 0">'
                'Không phát hiện lỗ hổng.</div>'
            )

        # CVE table
        if cves:
            sorted_cves = sorted(cves, key=lambda c: float(c.get("cvss", 0)), reverse=True)
            kev_count   = sum(1 for c in cves if c.get("is_actively_exploited"))
            parts.append(
                f'<div class="ai-sub-title">CVE Intelligence'
                f' ({len(cves)}'
                + (f' · <span style="color:#ff3e5e">{kev_count} KEV</span>' if kev_count else '') +
                ')</div>'
                '<div style="overflow-x:auto">'
                '<table class="data-table"><thead><tr>'
                '<th>CVE ID</th><th>CVSS</th><th>Mức Độ</th>'
                '<th>KEV</th><th>Công Nghệ</th><th>Mô Tả</th>'
                '</tr></thead><tbody>'
            )
            for c in sorted_cves:
                cve_id  = _safe(c.get("id", ""))
                cvss    = float(c.get("cvss", 0))
                sev     = str(c.get("severity", "Medium")).capitalize()
                is_kev  = bool(c.get("is_actively_exploited"))
                tech    = _safe(c.get("technology", ""))
                summary = _safe(str(c.get("summary", ""))[:160])
                sev_color = _SEV_COLOR.get(sev, "#4a6a90")
                kev_cell = '<span class="kev-pill">ĐANG BỊ KHAI THÁC</span>' if is_kev else '—'
                parts.append(
                    f'<tr>'
                    f'<td><code class="code-inline">{cve_id}</code></td>'
                    f'<td style="color:{sev_color};font-weight:700">{cvss:.1f}</td>'
                    f'<td>{_sev_badge(sev)}</td>'
                    f'<td>{kev_cell}</td>'
                    f'<td>{tech}</td>'
                    f'<td>{summary}</td>'
                    f'</tr>'
                )
            parts.append('</tbody></table></div>')

        # Endpoints (collapsed, only if > 0)
        if endpoints:
            parts.append(
                f'<div class="ai-sub-title">Endpoints ({len(endpoints)})</div>'
                '<div class="group-eps">'
            )
            for ep in endpoints[:20]:
                parts.append(f'<span>{_safe(ep)}</span>')
            if len(endpoints) > 20:
                parts.append(f'<span style="color:#4a6a90">… +{len(endpoints) - 20} more</span>')
            parts.append('</div>')

        parts.append('</div>')  # /ai-host-body
        parts.append('</div>')  # /ai-host-block

    parts.append('</div>')  # /section
    return "".join(parts)


def _render_attack_surface_section(attack_surface: dict) -> str:
    if not attack_surface:
        return ""

    summary = attack_surface.get("summary", {})
    total_assets = int(summary.get("total_assets", 0))
    total_ep = int(summary.get("total_endpoints", 0))
    total_params = int(summary.get("total_parameters", 0))
    total_vulns = int(summary.get("total_vulnerabilities", 0))
    riskiest = summary.get("riskiest_endpoints") or []
    entry_points = summary.get("entry_points") or []

    parts = [
        '<a class="anchor" id="attack-surface"></a>',
        '<div class="section">',
        '<div class="section-title">Bản Đồ Bề Mặt Tấn Công</div>',
        '<div class="metric-tiles">',
        f'<div class="metric-tile"><div class="metric-tile-val">{total_assets}</div>'
        '<div class="metric-tile-lbl">Tài Sản</div></div>',
        f'<div class="metric-tile"><div class="metric-tile-val">{total_ep}</div>'
        '<div class="metric-tile-lbl">Endpoints</div></div>',
        f'<div class="metric-tile"><div class="metric-tile-val">{total_params}</div>'
        '<div class="metric-tile-lbl">Tham Số</div></div>',
        f'<div class="metric-tile"><div class="metric-tile-val">{total_vulns}</div>'
        '<div class="metric-tile-lbl">Lỗ Hổng</div></div>',
        '</div>',
    ]

    # Riskiest endpoints table
    if riskiest:
        parts.append(
            '<div class="as-grid">'
            '<div class="as-card">'
            '<div class="as-card-title">Endpoints Rủi Ro Cao Nhất</div>'
        )
        for ep in riskiest[:10]:
            url = _safe(ep.get("url", ""))
            score = float(ep.get("risk_score", 0.0))
            vuln_count = int(ep.get("vuln_count", 0))
            parts.append(
                f'<div class="as-ep-row">'
                f'<span class="as-ep-url">{url}</span>'
                f'<span class="as-ep-score">{score:.1f} ({vuln_count} vulns)</span>'
                f'</div>'
            )
        parts.append('</div>')

        # Entry points
        parts.append(
            '<div class="as-card">'
            '<div class="as-card-title">Điểm Xâm Nhập</div>'
        )
        if entry_points:
            for ep in entry_points[:10]:
                ep_type = _safe(str(ep.get("type", "")).replace("_", " ").title())
                ep_id = _safe(ep.get("id", ""))
                parts.append(
                    f'<div class="as-ep-row">'
                    f'<span class="as-ep-url">{ep_type}</span>'
                    f'<span class="as-entry-badge">{ep_id}</span>'
                    f'</div>'
                )
        else:
            parts.append(
                '<div style="color:#4a6a90;font-size:12px;padding:8px 0">'
                'Không phát hiện điểm xâm nhập trực tiếp</div>'
            )
        parts.append('</div></div>')

    parts.append('</div>')
    return "".join(parts)


def _render_attack_paths_section(attack_paths: list[dict]) -> str:
    if not attack_paths:
        return ""

    _risk_colors = {
        "Critical": ("#ff3e5e", "rgba(255,62,94,.15)"),
        "High": ("#ff7b44", "rgba(255,123,68,.15)"),
        "Medium": ("#ffb800", "rgba(255,184,0,.15)"),
        "Low": ("#00ff9d", "rgba(0,255,157,.12)"),
    }

    parts = [
        '<a class="anchor" id="attack-paths"></a>',
        '<div class="section">',
        '<div class="section-title">Kịch Bản Tấn Công</div>',
    ]

    for path in attack_paths[:10]:
        name = _safe(path.get("name", ""))
        risk = str(path.get("likelihood", "Medium"))
        impact = _safe(path.get("total_impact", ""))
        steps = path.get("steps", [])
        color, bg = _risk_colors.get(risk, ("#4a6a90", "rgba(74,106,144,.15)"))

        parts.append(
            f'<div class="ap-scenario">'
            f'<div class="ap-header">'
            f'<span class="ap-risk" style="color:{color};background:{bg};border:1px solid {color}40">{_safe(risk)}</span>'
            f'<span class="ap-title">{name}</span>'
            f'</div>'
            f'<div class="ap-body">'
        )

        if impact:
            parts.append(
                f'<div style="font-size:12px;color:#8aa8cc;margin-bottom:12px;'
                f'padding:8px 12px;background:#070b0f;border-radius:5px">'
                f'<strong style="color:#e8f4ff">Tác động:</strong> {impact}</div>'
            )

        for i, step in enumerate(steps, 1):
            action = _safe(step.get("action", ""))
            vuln_type = _safe(str(step.get("vuln_type", "")).replace("_", " ").title())
            finding_id = _safe(step.get("finding_id", ""))
            endpoint = _safe(step.get("endpoint", ""))

            parts.append(
                f'<div class="ap-step">'
                f'<div class="ap-step-num">{i}</div>'
                f'<div class="ap-step-detail">'
                f'<span class="ap-step-vuln">{vuln_type}</span> — {action}'
            )
            if finding_id:
                parts.append(f' <span class="ap-step-finding">[{finding_id}]</span>')
            if endpoint:
                parts.append(f'<br><span style="font-size:11px;color:#4a6a90">{endpoint}</span>')
            parts.append('</div></div>')

        parts.append('</div></div>')

    parts.append('</div>')
    return "".join(parts)


def _render_roadmap_section(vulns: list[dict]) -> str:
    if not vulns:
        return ""

    # Deduplicate by vulnerability_type, keep highest cvss representative
    seen: dict[str, dict] = {}
    for v in vulns:
        vt   = str(v.get("vulnerability_type", ""))
        cvss = float(v.get("cvss_score") or 0)
        if vt not in seen or cvss > float(seen[vt].get("cvss_score") or 0):
            seen[vt] = v

    rows_data = sorted(seen.values(), key=lambda v: float(v.get("cvss_score") or 0), reverse=True)

    rows: list[str] = []
    for v in rows_data:
        vt     = str(v.get("vulnerability_type", ""))
        cvss   = float(v.get("cvss_score") or 0)
        sev    = str(v.get("severity", "Unscored"))
        fid    = str(v.get("finding_id", ""))[:8] or _short_id(v)
        name   = vt.replace("_", " ").title()
        fixes  = v.get("fix_recommendation") or []
        if fixes:
            _fix_text = str(fixes[0])
            if len(_fix_text) > 100:
                _truncated = _fix_text[:100].rsplit(" ", 1)[0] + "…"
            else:
                _truncated = _fix_text
            action = _safe(_truncated)
        else:
            action = "Xem khuyến nghị bảo mật"
        effort = _safe(_EFFORT_MAP.get(vt, "2–4 giờ"))
        p_cls, p_lbl = _priority_label(cvss)

        rows.append(
            f'<tr>'
            f'<td class="{p_cls}">{_safe(p_lbl)}</td>'
            f'<td><code class="code-inline">{_safe(fid)}</code></td>'
            f'<td>{_safe(name)}</td>'
            f'<td>{action}</td>'
            f'<td>{effort}</td>'
            f'<td>{_sev_badge(sev)}</td>'
            f'</tr>'
        )

    return (
        '<a class="anchor" id="roadmap"></a>'
        '<div class="section">'
        '<div class="section-title">Lộ Trình Khắc Phục</div>'
        '<div style="overflow-x:auto"><table class="data-table"><thead><tr>'
        '<th>Ưu Tiên</th><th>ID</th><th>Lỗ Hổng</th>'
        '<th>Hành Động</th><th>Nỗ Lực</th><th>Mức Độ</th>'
        '</tr></thead><tbody>'
        + "".join(rows) +
        '</tbody></table></div>'
        '</div>'
    )


# ---------------------------------------------------------------------------
# Main renderer
# ---------------------------------------------------------------------------

def _render(scan_result: dict) -> str:
    target    = _safe(scan_result.get("target", "Unknown"))
    scan_id   = _safe(scan_result.get("scan_id", ""))
    started   = str(scan_result.get("started_at", ""))
    completed = str(scan_result.get("completed_at", ""))
    duration  = _duration_str(started, completed)

    risk     = scan_result.get("risk_overview") or {}
    asset    = scan_result.get("asset_summary") or {}
    vulns    = scan_result.get("analyzed_vulnerabilities") or []
    cve_list = scan_result.get("cve_intelligence") or []
    attack_surface     = scan_result.get("attack_surface") or {}
    attack_paths       = scan_result.get("attack_paths") or []
    asset_intelligence = scan_result.get("asset_intelligence") or []

    generated_at = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    parts: list[str] = []

    # ── HEAD ──────────────────────────────────────────────────────────────
    parts.append(
        f'<!DOCTYPE html>\n<html lang="vi">\n<head>\n'
        f'<meta charset="UTF-8">\n'
        f'<meta name="viewport" content="width=device-width,initial-scale=1.0">\n'
        f'<title>Báo Cáo Bảo Mật — {target}</title>\n'
        f'<style>\n{_CSS}\n</style>\n'
        f'</head>\n<body>\n'
    )

    # ── SIDEBAR ───────────────────────────────────────────────────────────
    parts.append(_render_sidebar(vulns))

    # ── MAIN ──────────────────────────────────────────────────────────────
    parts.append('<main class="main">')

    # Hero
    parts.append(_render_hero(scan_result, duration))

    # Score grid
    parts.append(_render_score_grid(risk))
    parts.append(_render_false_positive_removed(scan_result))

    # Findings
    parts.append(_render_findings_section(vulns))

    # CVE Intelligence
    parts.append(_render_cve_section(cve_list))

    # Asset Intelligence (per-host breakdown)
    parts.append(_render_asset_intelligence_section(asset_intelligence))

    # Attack Surface Map (deep mode)
    parts.append(_render_attack_surface_section(attack_surface))

    # Attack Path Scenarios (deep mode)
    parts.append(_render_attack_paths_section(attack_paths))

    # Asset Summary
    parts.append(_render_asset_section(asset))

    # Remediation Roadmap
    parts.append(_render_roadmap_section(vulns))

    # Footer
    parts.append(
        f'<div class="footer">'
        f'HQG Security Platform &nbsp;·&nbsp; '
        f'Scan ID: <code style="font-size:11px;color:#4a6a90">{scan_id}</code>'
        f' &nbsp;·&nbsp; Được tạo lúc {_safe(generated_at)}'
        f'</div>'
    )

    parts.append('</main>')

    # ── INLINE JS ─────────────────────────────────────────────────────────
    parts.append(f'<script>\n{_JS}\n</script>\n</body>\n</html>')

    return "".join(parts)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_html(scan_result: dict, output_path: Path) -> None:
    """
    Render *scan_result* as a self-contained dark-theme HTML security report.

    Args:
        scan_result: Dict từ scan pipeline (xem module docstring cho schema).
        output_path: Path của file .html sẽ được ghi.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html_content = _render(scan_result)
    output_path.write_text(html_content, encoding="utf-8")
