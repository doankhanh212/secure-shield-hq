# HQG Web Security Platform — Tài Liệu Kỹ Thuật

## 1. Tổng Quan Kiến Trúc

### 1.1 Tech Stack

| Layer     | Technology                                    |
|-----------|-----------------------------------------------|
| Backend   | FastAPI + Celery + Redis                      |
| Frontend  | React 18 + TailwindCSS + Radix UI + TanStack Query |
| Storage   | Redis (primary store)                         |
| Container | Docker Compose (5 services)                   |
| Scanner   | Custom Python detection engine (async, httpx)  |
| Build     | Vite + SWC + TypeScript                        |

### 1.2 System Architecture

```
┌──────────────┐      ┌──────────────┐      ┌───────────────┐
│  React SPA   │─────▶│  FastAPI API  │─────▶│ Celery Worker │
│  :5173       │◀─ws──│  :8000       │◀─────│  (fork pool)  │
└──────────────┘      └──────┬───────┘      └──────┬────────┘
                             │                      │
                             ▼                      ▼
                      ┌──────────────┐       ┌─────────────┐
                      │    Redis     │       │   Scanner   │
                      │  :6379      │       │  Pipeline   │
                      │  (queue +   │       │  (10 stages)│
                      │   store)    │       └─────────────┘
                      └──────────────┘
```

### 1.3 Deployment

Docker Compose services:

| Service   | Image                      | Port | Mô tả                       |
|-----------|----------------------------|------|------------------------------|
| api       | custom (Dockerfile)        | 8000 | FastAPI application server   |
| worker    | custom (Dockerfile)        | —    | Celery worker (scan tasks)   |
| redis     | redis:7-alpine             | 6379 | Message queue + data store   |
| dvwa      | ghcr.io/digininja/dvwa     | 8080 | Vulnerable test target       |
| dvwa-db   | mariadb:10                 | —    | MySQL for DVWA               |

Celery queues: `queue_default`, `queue_scan_manager`, `queue_discovery`, `queue_crawler`,
`queue_payload`, `queue_detection`, `queue_cve_intelligence`, `queue_template`,
`queue_ai`, `queue_reporting`, `queue_scheduler`.

---

## 2. Pipeline Quét Bảo Mật

### 2.1 Pipeline Overview

```
Target URL
  │
  ├─ 1. Asset Discovery      (subdomain, DNS, tech fingerprint)
  ├─ 2. Web Crawling          (endpoints, forms, parameters)
  ├─ 3. Template Scan         (misconfig, exposed files)
  ├─ 4. Payload Injection     (SQLi, XSS, CmdI, SSRF, LFI payloads)
  ├─ 5. Detection Engine      (error_pattern, reflection, timing, diff)
  ├─ 6. AI Analysis           (OWASP/CWE/CVSS mapping + explanation)
  ├─ 7. CVE Intelligence      (NVD + CISA KEV cross-reference)
  ├─ 8. Attack Surface Graph  [Deep only]
  ├─ 9. Attack Path Analysis  [Deep only]
  └─ 10. Reporting            (HTML self-contained report)
```

Stages 8–9 chỉ chạy trong chế độ Deep Intelligence.

### 2.2 Chi Tiết Từng Stage

**Stage 1 — Asset Discovery** (`scanner/asset_discovery/`)
- Input: target URL
- Output: domain, subdomains, IPs, services, technologies, DNS records
- Logic: crt.sh subdomain enum → DNS resolve → HTTP probe → tech fingerprint
- Key files: `tasks.py`, `subdomain_enum.py`, `dns_resolver.py`, `tech_fingerprint.py`

**Stage 2 — Web Crawling** (`scanner/crawler/`)
- Input: crawl targets (domain + subdomains) + config (max_pages, max_depth)
- Output: endpoints, forms, parameters, API endpoints
- Logic: BFS crawl → HTML parse → JS parse → form extract → URL normalize
- Key files: `crawler.py`, `html_parser.py`, `js_parser.py`, `form_parser.py`

**Stage 3 — Template Scan** (`scanner/template_engine/`)
- Input: endpoints
- Output: template-matched findings (misconfig, info disclosure, exposed files)
- Logic: YAML template matching với regex/status_code/header checks
- Key files: `executor.py`, `loader.py`, `matchers.py`

**Stage 4 — Payload Injection** (`scanner/payload_engine/`)
- Input: endpoints + parameters + forms
- Output: injection results (response body, code, time, headers)
- Payload types: SQLi, XSS, CmdI, SSRF, LFI, Path Traversal, Open Redirect
- Key files: `tasks.py`, `injector.py`, `payload_loader.py`, `request_builder.py`

**Stage 5 — Detection Engine** (`scanner/detection_engine/`)
- Input: injection results + baseline responses
- Output: `VulnerabilityFinding` objects
- Methods: `error_pattern`, `reflection`, `time_based`, `diff`, `baseline_comparison`
- Key files: `response_analyzer.py`, `error_patterns.py`, `diff_analyzer.py`, `time_analyzer.py`, `tasks.py`

**Stage 6 — AI Analyzer** (`ai/analyzer/`)
- Input: raw findings
- Output: `AnalyzedVulnerability` objects (enriched với OWASP/CWE/CVSS)
- Method: Rule-based (deterministic, zero cost, không cần LLM)
- Key files: `analyzer.py`, `vuln_mapping.py`, `explanation_engine.py`, `confidence_scorer.py`

**Stage 7 — CVE Intelligence** (`scanner/cve_intelligence/`)
- Input: technologies detected
- Output: CVE records từ NVD + CISA KEV cross-reference
- Logic: tech parse → NVD 2.0 API → KEV catalog → enrich findings
- Key files: `nvd_client.py`, `kev_client.py`, `tech_parser.py`

**Stage 8 — Attack Surface Graph** (`scanner/attack_surface/graph.py`) [Deep only]
- Input: all findings + endpoints + discovery
- Output: `AttackSurfaceGraph` (Asset → Endpoint → Parameter → Vuln)
- Logic: Build graph → calculate risk scores → identify entry points

**Stage 9 — Attack Path Analysis** (`scanner/attack_surface/attack_paths.py`) [Deep only]
- Input: AttackSurfaceGraph + findings
- Output: Attack path scenarios (multi-step chains)
- Logic: 6 chain templates × pattern matching → linked steps

**Stage 10 — Reporting** (`reporting/engine/`)
- Input: all scan results
- Output: HTML report (self-contained, dark theme, offline-capable)
- Key files: `html_report.py`, `report_builder.py`, `tasks.py`
- Formats: HTML, JSON, CSV, PDF

---

## 3. Ba Chế Độ Quét

### 3.1 Quét Nhanh (Quick Scan)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~2–5 phút                                  |
| Payload injection       | Không                                      |
| Stages                  | asset_discovery → crawling → template_scan → detection |
| Crawler                 | max 20 pages, depth 2                      |
| Detection               | error_pattern only                         |
| Output                  | Security checks summary (an toàn / cần kiểm tra / có rủi ro) |

Config: `scanner/scan_manager/scan_profiles.py` → `"quick"`

### 3.2 Quét Tiêu Chuẩn (Standard Scan)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~15–40 phút                                |
| Payload injection       | Safe mode, 10 payloads/param               |
| Stages                  | 7 stages (đến CVE Intelligence)            |
| Crawler                 | max 200 pages, depth 5                     |
| Detection               | error_pattern + reflection + timing + diff |
| AI Analysis             | OWASP/CWE/CVSS + explanation + fix         |
| CVE Intelligence        | NVD + CISA KEV                             |
| Output                  | Intelligence HTML report                    |

Config: `scan_profiles.py` → `"standard"`

### 3.3 Phân Tích Sâu (Deep Intelligence)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~1–3 giờ                                   |
| Payload injection       | Aggressive mode, 25 payloads/param + fuzzing |
| Stages                  | 9 stages (+ Attack Surface + Attack Path)  |
| Crawler                 | max 500 pages, depth 8, JS parsing, hidden param discovery |
| Detection               | All methods + boolean_blind                |
| Attack Surface          | Graph: Asset → Endpoint → Parameter → Vuln |
| Attack Path             | 6 chain templates, multi-step scenarios    |
| Output                  | Intelligence report + Attack Surface Map + Attack Scenarios |

Config: `scan_profiles.py` → `"deep"`

---

## 4. Detection Engine — Chi Tiết Kỹ Thuật

### 4.1 Phương Pháp Detection

**SQL Injection** — `match_sql_errors()` + baseline comparison
- Pattern matching trên database error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Baseline diff: chỉ alert khi error KHÔNG có trong baseline response

**XSS** — `_check_xss_reflection()` + HTML context analysis
- Exact match, URL decode, HTML unescape
- Partial marker detection: `<script`, `onerror=`, `alert(`, `<svg`, `<img`, `<iframe`
- Context analysis: `html_text` → High, `html_attribute` → High, `css` → Low, `html_comment` → skip
- Baseline comparison: skip nếu payload content đã có sẵn

**Command Injection** — Tiered detection
- Tier 1 (Confirmed): `match_cmdi_confirmed()` — OS output patterns (`uid=`, `root:`, `Windows`)
- Tier 2 (Possible): `match_cmdi_possible()` — weaker indicators
- Response code filter: skip 404/403/405

**SSRF** — `match_ssrf_patterns()` + payload validation
- Chỉ accept nếu payload là internal URL (`is_ssrf_payload()`)
- Baseline comparison

**LFI/Path Traversal** — `match_lfi_patterns()`
- Pattern: `/etc/passwd`, `[boot loader]`, `.ini` content
- Baseline comparison

**Info Disclosure** — `match_info_disclosure()`
- Negative patterns: CSRF token, `_token`, `authenticity_token` → excluded
- Response code 500+ → auto-trigger

### 4.2 False Positive Mitigation

1. **Baseline comparison** — differential analysis với benign request
2. **HTML context analysis** — XSS trong `html_comment` = not exploitable → skip
3. **Tiered CmdI patterns** — confirmed vs possible tách riêng
4. **SSRF payload validation** — chỉ internal URLs
5. **Info Disclosure negative patterns** — CSRF token exclusion
6. **Response code filtering** — skip 404/403/405 cho injection types
7. **Post-detection filter** — `_filter_low_quality_findings()` trong pipeline
8. **Template filter** — `_template_filter.py` filter template findings
9. **Cross-validation** — boost confidence khi multiple methods agree

### 4.3 Confidence Scoring

| Range       | Label      | Ý nghĩa                          |
|-------------|------------|-----------------------------------|
| > 0.7       | Confirmed  | Evidence rõ ràng, verified         |
| 0.4 – 0.7  | Likely     | Dấu hiệu mạnh, nên verify        |
| < 0.4       | Potential  | Cần xác minh thủ công              |

False positive likelihood: Confirmed → 10%, Likely → 30%, Potential → 60%.

---

## 5. AI Analyzer — Rule-Based Intelligence

### 5.1 OWASP/CWE/CVSS Mapping Table

| Vuln Type          | OWASP           | CWE     | CVSS Score |
|--------------------|-----------------|---------|------------|
| sqli               | A03:2021        | CWE-89  | 9.8        |
| time_based_sqli    | A03:2021        | CWE-89  | 7.5        |
| xss                | A03:2021        | CWE-79  | 6.1        |
| xss_stored         | A03:2021        | CWE-79  | 5.4        |
| cmdi               | A03:2021        | CWE-78  | 9.8        |
| time_based_cmdi    | A03:2021        | CWE-78  | 7.5        |
| ssrf               | A10:2021        | CWE-918 | 8.6        |
| lfi                | A01:2021        | CWE-22  | 7.5        |
| path_traversal     | A01:2021        | CWE-22  | 7.5        |
| info_disclosure    | A05:2021        | CWE-200 | 5.3        |
| open_redirect      | A01:2021        | CWE-601 | 6.1        |
| cors_misconfig     | A05:2021        | CWE-942 | 6.5        |
| xxe                | A05:2021        | CWE-611 | 7.5        |
| crlf_injection     | A03:2021        | CWE-93  | 4.7        |

Source: `ai/analyzer/vuln_mapping.py`

### 5.2 Explanation Engine

- Explanation templates: tiếng Việt, 3–4 câu, contextual (endpoint + parameter)
- Impact templates: 2 câu business/technical impact
- Fix templates: 3 recommendations cụ thể per vuln type
- Source: `ai/analyzer/explanation_engine.py`

### 5.3 Upgrade Path

- **Hiện tại**: Rule-based (zero cost, deterministic, < 1ms per finding)
- **Tương lai (planned)**: Ollama + local LLM cho contextual explanation
- LLM chỉ làm: contextual explanation + false positive assessment
- LLM KHÔNG làm: OWASP/CWE/CVSS mapping (giữ rule-based cho consistency)

---

## 6. CVE Intelligence

### 6.1 Data Sources

| Source   | API                                         | Mô tả                          |
|----------|---------------------------------------------|---------------------------------|
| NVD      | `services.nvd.nist.gov/rest/json/cves/2.0` | National Vulnerability Database |
| CISA KEV | `www.cisa.gov/sites/.../known_exploited...`  | Known Exploited Vulnerabilities |

### 6.2 Pipeline

```
tech_fingerprint.py → tech_parser.py → nvd_client.py → kev_client.py
                                            ↓
                                     Enrich findings
                                     (related_cve_ids,
                                      is_actively_exploited)
```

- Rate limiting: `asyncio.Semaphore(2)`, 0.7s between NVD requests
- Without API key: 5 req/30s; with key: 50 req/30s
- Caching: Redis (TTL 24h per technology lookup)
- Graceful degradation: NVD down → skip, pipeline continues

---

## 7. Attack Surface Graph (Deep Mode)

### 7.1 Data Model

```
AssetNode (domain, IP, technologies, risk_score)
    └── EndpointNode (url, method, parameters, finding_ids, risk_score)
            └── ParameterNode (name, type, injectable, finding_ids)
                    └── VulnNode (vuln_type, severity, cvss, cwe, is_entry_point)
```

### 7.2 Risk Propagation

- Vuln risk = CVSS score
- Endpoint risk = sum(vuln CVSS scores)
- Asset risk = sum(endpoint risk scores)

### 7.3 Entry Point Detection

Entry point vuln types: `xss`, `xss_stored`, `xss_reflected`, `sqli`, `time_based_sqli`,
`cmdi`, `time_based_cmdi`, `ssrf`, `open_redirect`, `lfi`, `path_traversal`.

Source: `scanner/attack_surface/graph.py`

---

## 8. Attack Path Analysis (Deep Mode)

### 8.1 Chain Templates (6)

| # | Template                          | Required Vulns | Steps |
|---|-----------------------------------|----------------|-------|
| 1 | XSS → Session Hijacking           | xss            | 3     |
| 2 | SQLi → Database Extraction        | sqli           | 4     |
| 3 | CmdI → Server Takeover            | cmdi           | 4     |
| 4 | SSRF → Cloud Resource Access      | ssrf           | 3     |
| 5 | LFI → Credential Theft            | lfi            | 3     |
| 6 | XSS + SQLi → Escalation Chain     | xss, sqli      | 3     |

### 8.2 Matching Logic

- Required vuln types phải có trong findings (với variation matching)
- Steps linked to actual finding IDs và endpoints
- Priority: max CVSS ≥ 9.0 → P0, ≥ 7.0 → P1, else → P2

Source: `scanner/attack_surface/attack_paths.py`

---

## 9. HTML Report

### 9.1 Design

- Dark theme, self-contained (no external CDN/fonts), offline-capable
- Fixed sidebar TOC + scrollable main content
- Pure inline CSS + vanilla JS (no framework dependencies)
- File size: ~20–40KB per report

### 9.2 Sections

1. **Hero** — target, scan mode, duration, endpoint/tech counts
2. **Score Grid** — 5 cards: overall score + Critical/High/Medium/Low counts
3. **Findings** — grouped by (vuln_type, parameter), expandable, confidence badges
4. **CVE Intelligence** — table: CVE ID, technology, CVSS, KEV status
5. **Attack Surface Map** — riskiest endpoints + entry points [Deep only]
6. **Attack Path Scenarios** — multi-step chains with timeline [Deep only]
7. **Asset Summary** — domains, subdomains, technologies
8. **Remediation Roadmap** — priority table (P0/P1/P2/P3)

### 9.3 XSS Safety

Tất cả user-supplied data qua `_safe()` → `html.escape(str(text), quote=True)`.

Source: `reporting/engine/html_report.py`

---

## 10. Tiêu Chuẩn Áp Dụng

- **OWASP Top 10 2021** — vulnerability classification
- **CWE** (Common Weakness Enumeration) — root cause mapping
- **CVE** (Common Vulnerabilities and Exposures) — known vulnerability reference
- **CVSS v3.1** (Common Vulnerability Scoring System) — severity scoring
- **CISA KEV** — actively exploited vulnerability tracking
- **NVD 2.0 API** — vulnerability database queries

---

## 11. API Reference

### Authentication

| Method | Path              | Summary                    | Auth |
|--------|-------------------|----------------------------|------|
| POST   | `/api/v1/auth/login` | Login, returns JWT token | No   |
| GET    | `/api/v1/auth/me`    | Current user info        | Yes  |

### Scans

| Method | Path                     | Summary                          |
|--------|--------------------------|----------------------------------|
| POST   | `/api/v1/scans`          | Start scan `{target, mode}`      |
| GET    | `/api/v1/scans`          | List all scans                   |
| GET    | `/api/v1/scans/{id}`     | Scan status + progress           |
| DELETE | `/api/v1/scans/{id}`     | Cancel scan                      |
| WS     | `/api/v1/ws/scans/{id}`  | Real-time scan progress          |

Modes: `quick`, `standard`, `deep`, `full`

### Domains

| Method | Path                           | Summary                        |
|--------|--------------------------------|--------------------------------|
| GET    | `/api/v1/assets`               | List all domains               |
| POST   | `/api/v1/assets`               | Add domain `{url}`             |
| DELETE | `/api/v1/assets/{id}`          | Delete domain                  |
| GET    | `/api/v1/assets/{scan_id}/discovery` | Discovery results cho scan |

Domains tự động register khi quét target mới.

### Vulnerabilities

| Method | Path                           | Summary                        |
|--------|--------------------------------|--------------------------------|
| GET    | `/api/v1/vulnerabilities`      | List (filter: scan_id, severity, endpoint) |
| GET    | `/api/v1/vulnerabilities/{id}` | Detail + remediation           |
| PATCH  | `/api/v1/vulnerabilities/{id}` | Update status/FP/note          |

### Reports

| Method | Path                                          | Summary              |
|--------|-----------------------------------------------|-----------------------|
| GET    | `/api/v1/reports/{scan_id}`                   | Report metadata       |
| GET    | `/api/v1/reports/{scan_id}/download?format=X` | Download (json/csv/html/pdf) |

### Dashboard

| Method | Path                          | Summary                   |
|--------|-------------------------------|---------------------------|
| GET    | `/api/v1/dashboard/stats`     | Overview statistics       |
| GET    | `/api/v1/dashboard/posture`   | Security posture trend    |
| GET    | `/api/v1/dashboard/top-risks` | Top 5 riskiest assets     |

### Settings

| Method | Path                 | Summary                    |
|--------|----------------------|----------------------------|
| GET    | `/api/v1/settings`   | Get platform settings      |
| PUT    | `/api/v1/settings`   | Update settings (incl NVD key) |

### System

| Method | Path      | Summary      |
|--------|-----------|--------------|
| GET    | `/health` | Health check |

---

## 12. Cấu Trúc Thư Mục

```
hqg-backend/
├── ai/analyzer/
│   ├── analyzer.py              # Orchestrator: analyze_finding()
│   ├── vuln_mapping.py          # OWASP/CWE/CVSS lookup table
│   ├── explanation_engine.py    # Vietnamese explanation templates
│   ├── confidence_scorer.py     # 0.0-1.0 confidence calculation
│   └── models.py                # AnalyzedVulnerability dataclass
├── backend/
│   ├── main.py                  # FastAPI app creation
│   ├── celery_app.py            # Celery configuration
│   ├── config/config.py         # Pydantic Settings (env-based)
│   ├── core/
│   │   ├── auth.py              # JWT authentication
│   │   ├── redis.py             # Async Redis client
│   │   ├── search.py            # Elasticsearch client
│   │   └── user_store.py        # Admin user seeding
│   └── api/routes/
│       ├── auth.py              # POST /login, GET /me
│       ├── scans.py             # CRUD /scans
│       ├── dashboard.py         # GET /dashboard/*
│       ├── assets.py            # CRUD /assets (domains)
│       ├── vulnerabilities.py   # GET/PATCH /vulnerabilities
│       ├── reports.py           # GET /reports/download
│       ├── settings.py          # GET/PUT /settings
│       └── ws.py                # WebSocket /ws/scans/{id}
├── scanner/
│   ├── asset_discovery/
│   │   ├── tasks.py             # _discover_assets_async()
│   │   ├── subdomain_enum.py    # crt.sh enumeration
│   │   ├── dns_resolver.py      # A/AAAA/CNAME resolution
│   │   ├── service_detector.py  # HTTP/HTTPS probing
│   │   └── tech_fingerprint.py  # Server/framework detection
│   ├── crawler/
│   │   ├── crawler.py           # crawl_target_async()
│   │   ├── html_parser.py       # Link/form extraction
│   │   ├── js_parser.py         # JS endpoint/param extraction
│   │   └── form_parser.py       # Form field parsing
│   ├── template_engine/
│   │   ├── executor.py          # Template matching engine
│   │   ├── loader.py            # YAML template loader
│   │   └── matchers.py          # Regex/status/header matchers
│   ├── payload_engine/
│   │   ├── tasks.py             # _inject_payloads_async()
│   │   ├── injector.py          # Async injection executor
│   │   ├── payload_loader.py    # Payload file loader
│   │   ├── payload_mutator.py   # Payload mutation (deep mode)
│   │   └── request_builder.py   # HTTP request construction
│   ├── detection_engine/
│   │   ├── tasks.py             # _detect_async()
│   │   ├── response_analyzer.py # analyze_response() — core detection
│   │   ├── error_patterns.py    # SQL/CmdI/LFI error patterns
│   │   ├── diff_analyzer.py     # Response diff analysis
│   │   ├── time_analyzer.py     # Time-based detection
│   │   └── models.py            # VulnerabilityFinding dataclass
│   ├── cve_intelligence/
│   │   ├── nvd_client.py        # NVD 2.0 API client
│   │   ├── kev_client.py        # CISA KEV catalog client
│   │   └── tech_parser.py       # Technology string parser
│   ├── attack_surface/
│   │   ├── graph.py             # AttackSurfaceGraph + builder
│   │   └── attack_paths.py      # 6 chain templates + analyzer
│   └── scan_manager/
│       ├── pipeline.py          # run_pipeline() — 10-stage orchestrator
│       ├── tasks.py             # Celery start_scan task
│       ├── scan_modes.py        # ScanModeConfig (quick/standard/deep/full)
│       ├── scan_profiles.py     # Per-stage configuration dicts
│       ├── scan_service.py      # Redis CRUD for scan state
│       ├── security_checks.py   # Quick mode security checks
│       └── _template_filter.py  # Template finding quality filter
├── reporting/engine/
│   ├── html_report.py           # Self-contained HTML generator
│   ├── report_builder.py        # ScanReport assembler
│   ├── tasks.py                 # Celery report generation task
│   ├── json_report.py           # JSON export
│   ├── csv_report.py            # CSV export
│   └── pdf_report.py            # PDF export (WeasyPrint)
└── docker-compose.yml           # 5 services: api, worker, redis, dvwa, dvwa-db
```

Frontend:
```
src/
├── pages/
│   ├── Index.tsx                # Dashboard
│   ├── AssetManagement.tsx      # Quản lý Tên miền
│   ├── SecurityScans.tsx        # Quét Bảo mật
│   ├── Vulnerabilities.tsx      # Lỗ hổng
│   ├── Reports.tsx              # Báo cáo
│   ├── Settings.tsx             # Cài đặt
│   └── Login.tsx                # Đăng nhập
├── components/layout/
│   ├── DashboardLayout.tsx      # Main layout wrapper
│   └── AppSidebar.tsx           # Navigation sidebar
├── services/api.ts              # API client (fetch-based)
├── hooks/
│   ├── use-language.ts          # i18n hook (vi/en)
│   └── use-toast.ts             # Toast notifications
└── lib/i18n.ts                  # Translation strings
```
