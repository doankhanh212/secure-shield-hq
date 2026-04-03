# HQG Web Security Platform — Tài Liệu Kỹ Thuật

> **Phiên bản:** 1.1 — Cập nhật sau đợt tối ưu hoá production (2026-04-03)

---

## 1. Tổng Quan Kiến Trúc

### 1.1 Tech Stack

| Layer     | Technology                                           |
|-----------|------------------------------------------------------|
| Backend   | FastAPI 0.115 + Celery 5.4 + Redis 7                 |
| Frontend  | React 18 + TailwindCSS + Radix UI + TanStack Query   |
| Storage   | Redis (primary store — scans, findings, users, settings) |
| Container | Docker Compose (4 services production)               |
| Scanner   | Custom Python detection engine (async, httpx)         |
| Build     | Vite + SWC + TypeScript                              |
| Auth      | JWT HS256, 8h expiry, bcrypt passwords               |

### 1.2 System Architecture

```
Internet
   │
   ├── :3000 ──► frontend (nginx)
   │                  │
   │            /api/* proxy ──► backend:8000
   │
   └── :8000 ──► backend (FastAPI) [direct API access]
                      │
            ┌─────────┼──────────┐
            │         │          │
         redis      worker    scheduler
        (broker)   (Celery)   (optional)
```

### 1.3 Deployment — Docker Compose (Production)

4 services production tại repo root `docker-compose.yml`:

| Service   | Image                   | Port | Mô tả                        |
|-----------|-------------------------|------|-------------------------------|
| redis     | redis:7-alpine          | —    | Message queue + data store (expose internal only) |
| backend   | custom (hqg-backend/Dockerfile) | 8000 | FastAPI API server (2 workers) |
| worker    | custom (hqg-backend/Dockerfile) | —    | Celery worker (4 concurrency, tất cả queues) |
| frontend  | Dockerfile.frontend (nginx) | 3000 | React SPA + API reverse proxy |

> **Lưu ý:** `hqg-backend/docker-compose.yml` là file cũ dùng cho dev local (có thêm DVWA). File production là `docker-compose.yml` ở root.

Celery queues:
```
queue_default, queue_scan_manager, queue_discovery, queue_crawler,
queue_payload, queue_detection, queue_cve_intelligence, queue_template,
queue_ai, queue_reporting, queue_scheduler
```

### 1.4 Nginx (Frontend Container)

File `nginx.conf` phục vụ:
- Static React SPA tại `/`
- Proxy `/api/*` → `backend:8000` (Docker internal DNS)
- Proxy WebSocket `/api/v1/ws/*` với `Upgrade` header
- SPA fallback: mọi route trả về `index.html`
- Cache static assets: 1 năm (`immutable`)

---

## 2. Pipeline Quét Bảo Mật

### 2.1 Pipeline Overview

```
Target URL
  │
  ├─ 1.  Asset Discovery       (subdomain, DNS, tech fingerprint)
  ├─ 2.  Web Crawling           (endpoints, forms, parameters)
  ├─ 3.  Template Scan          (misconfig, exposed files, security headers)
  ├─ 4.  Payload Injection      (SQLi, XSS, CmdI, SSRF, LFI payloads)
  ├─ 5.  Detection Engine       (error_pattern, reflection, timing, diff)
  ├─ 6.  Verification Layer     (multi-step false-positive reduction)
  ├─ 7.  Knowledge-Base Enrich  (description, impact, remediation từ templates)
  ├─ 8.  AI Analysis            (OWASP/CWE/CVSS mapping + explanation)
  ├─ 9.  CVE Intelligence       (NVD + CISA KEV cross-reference)
  ├─ 10. Attack Surface Graph   [Deep only]
  ├─ 11. Attack Path Analysis   [Deep only]
  ├─ 12. Asset Intelligence     (per-host grouping, risk score)
  └─ 13. Reporting              (HTML self-contained report)
```

Stages 10–11 chỉ chạy trong chế độ Deep Intelligence.

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

**Stage 6 — Verification Layer** (`scanner/verification/`)
- Input: raw findings dicts
- Output: findings với `confidence` (updated), `verification_steps`, `verified: bool`
- Logic: per-type multi-step HTTP probes (SQLi boolean, XSS reflection, CmdI output, SSRF divergence)
- Runs concurrently via `asyncio.gather`; non-fatal (failure giữ nguyên findings gốc)
- Key files: `verifier.py`, `strategies.py`

**Stage 7 — Knowledge-Base Enrichment** (`scanner/knowledge_base/`)
- Input: verified findings (có thể thiếu `explanation`, `impact`, `remediation`)
- Output: findings đảm bảo luôn có đủ 4 trường hiển thị UI
- Logic: lookup `VULN_TEMPLATES` dict theo `vulnerability_type`; chỉ điền các trường còn trống (không ghi đè AI output)
- Fallback: generic template cho mọi vuln type chưa có trong dict
- Key file: `vuln_templates.py` — 11 templates (sqli, time_based_sqli, xss, xss_reflected, xss_stored, cmdi, time_based_cmdi, ssrf, lfi, path_traversal, info_disclosure, open_redirect) + generic fallback

**Stage 8 — AI Analyzer** (`ai/analyzer/`)
- Input: raw findings
- Output: `AnalyzedVulnerability` objects (enriched với OWASP/CWE/CVSS)
- Method: Rule-based (deterministic, zero cost, không cần LLM, < 1ms per finding)
- Key files: `analyzer.py`, `vuln_mapping.py`, `explanation_engine.py`, `confidence_scorer.py`
- Chạy sau Knowledge-Base; output AI ghi đè template nếu có

**Stage 9 — CVE Intelligence** (`scanner/cve_intelligence/`)
- Input: technologies detected
- Output: CVE records từ NVD + CISA KEV cross-reference
- Logic: tech parse → NVD 2.0 API → KEV catalog → enrich findings với `is_actively_exploited`
- Key files: `nvd_client.py`, `kev_client.py`, `tech_parser.py`

**Stage 10 — Attack Surface Graph** (`scanner/attack_surface/graph.py`) [Deep only]
- Input: all findings + endpoints + discovery
- Output: `AttackSurfaceGraph` (Asset → Endpoint → Parameter → Vuln)

**Stage 11 — Attack Path Analysis** (`scanner/attack_surface/attack_paths.py`) [Deep only]
- Input: AttackSurfaceGraph + findings
- Output: Attack path scenarios (6 chain templates, multi-step)

**Stage 12 — Asset Intelligence** (`scanner/asset_intelligence/`)
- Input: all findings + CVE records + discovered endpoints
- Output: per-host `Asset` objects với `risk_score`, `technologies`, `vulnerabilities`, `cves`
- Key files: `asset_manager.py`, `asset_enricher.py`, `fingerprint_service.py`, `host_grouper.py`, `risk_aggregator.py`, `models.py`
- Stored in Redis key `scan:{id}:asset_intelligence`

**Stage 13 — Reporting** (`reporting/engine/`)
- Input: all scan results
- Output: HTML report (self-contained, dark theme, offline-capable) + JSON/CSV/PDF
- Key files: `html_report.py`, `report_builder.py`, `tasks.py`

---

## 3. Ba Chế Độ Quét

### 3.1 Quét Nhanh (Quick Scan)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~2–5 phút                                  |
| Payload injection       | Không                                      |
| Stages                  | Discovery → Crawl → Template → Detection   |
| Crawler                 | max 20 pages, depth 2                      |
| Detection               | error_pattern only                         |
| Output                  | Security checks summary                    |

### 3.2 Quét Tiêu Chuẩn (Standard Scan)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~15–40 phút                                |
| Payload injection       | Safe mode, 10 payloads/param               |
| Stages                  | 9 stages (đến CVE Intelligence + Asset Intelligence) |
| Crawler                 | max 200 pages, depth 5                     |
| Detection               | error_pattern + reflection + timing + diff |
| AI Analysis             | OWASP/CWE/CVSS + explanation + fix         |
| CVE Intelligence        | NVD + CISA KEV                             |
| Output                  | Intelligence HTML report                    |

### 3.3 Phân Tích Sâu (Deep Intelligence)

| Thuộc tính              | Giá trị                                    |
|-------------------------|--------------------------------------------|
| Thời gian               | ~1–3 giờ                                   |
| Payload injection       | Aggressive mode, 25 payloads/param + fuzzing |
| Stages                  | 11 stages (+ Attack Surface + Attack Path) |
| Crawler                 | max 500 pages, depth 8, JS + hidden params |
| Detection               | All methods + boolean_blind                |
| Output                  | Full report + Attack Surface + Attack Paths |

Config: `scanner/scan_manager/scan_profiles.py`

---

## 4. Detection Engine

### 4.1 Phương Pháp Detection

**SQL Injection** — `match_sql_errors()` + baseline comparison
- Pattern matching DB error messages (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
- Baseline diff: chỉ alert khi error KHÔNG có trong baseline

**XSS** — `_check_xss_reflection()` + HTML context analysis
- Exact match, URL decode, HTML unescape; partial marker detection
- Context: `html_text`/`html_attribute` → High, `css` → Low, `html_comment` → skip

**Command Injection** — Tiered detection
- Tier 1 (Confirmed): OS output patterns (`uid=`, `root:`, `Windows`)
- Tier 2 (Possible): weaker indicators; skip 404/403/405

**SSRF** — `match_ssrf_patterns()` + internal URL validation

**LFI/Path Traversal** — `match_lfi_patterns()` (`/etc/passwd`, `[boot loader]`)

**Info Disclosure** — `match_info_disclosure()` — excludes CSRF tokens

### 4.2 False Positive Mitigation (9 lớp)

1. Baseline comparison (differential)
2. HTML context analysis (XSS)
3. Tiered CmdI patterns
4. SSRF payload validation (internal URLs only)
5. Info Disclosure negative patterns
6. Response code filtering (skip 404/403/405)
7. `_filter_low_quality_findings()` post-detection
8. Template filter (`_template_filter.py`)
9. Verification Layer (Stage 6) — multi-step HTTP probes

### 4.3 Confidence Scoring

| Range      | Label     | Ý nghĩa                          |
|------------|-----------|-----------------------------------|
| confirmed  | Confirmed | Verified bởi Verification Layer   |
| high       | High      | Evidence rõ ràng từ Detection      |
| medium     | Medium    | Dấu hiệu trung bình                |
| low        | Low       | Cần xác minh thủ công              |

---

## 5. Knowledge-Base Enrichment

### 5.1 Mục Đích

Đảm bảo **mọi finding** đều có đủ 4 trường hiển thị trong UI, dù AI Analyzer bị tắt (Quick/Standard mode):

| Trường        | Nguồn ưu tiên         | Fallback          |
|---------------|-----------------------|-------------------|
| `explanation` | AI Analyzer           | Knowledge-base template |
| `impact`      | AI Analyzer           | Knowledge-base template |
| `remediation` | AI Analyzer           | Knowledge-base template |
| `payload`     | Detection Engine      | `""` (hiển thị "Not available — detected via...") |
| `evidence`    | Detection Engine      | `""` |

### 5.2 Templates Có Sẵn

`scanner/knowledge_base/vuln_templates.py`:

```
sqli, time_based_sqli, xss, xss_reflected, xss_stored,
cmdi, time_based_cmdi, ssrf, lfi, path_traversal,
info_disclosure, open_redirect, _GENERIC_FALLBACK
```

---

## 6. Asset Intelligence Layer

### 6.1 Data Model

```python
Asset:
  host: str
  endpoints: list[str]
  technologies: list[Technology]   # name, version, confidence, cpe
  vulnerabilities: list[Vulnerability]  # type, severity, confidence, payload, evidence,
                                        # explanation, impact, remediation, cwe_id, cvss_score,
                                        # owasp_category, verification_steps
  cves: list[CVE]                  # id, cvss, severity, technology, summary, is_actively_exploited
  risk_score: float                # 0–100
```

### 6.2 Risk Score

| Score  | Level    | Màu    |
|--------|----------|--------|
| ≥ 80   | Critical | Đỏ     |
| ≥ 60   | High     | Cam    |
| ≥ 40   | Medium   | Vàng   |
| < 40   | Low      | Xanh lá |

### 6.3 API Endpoint

```
GET /api/v1/scans/{scan_id}/asset-intelligence
→ { scan_id, target, assets[], total_assets, critical_assets, high_risk_assets, total_cves }
```

Redis key: `scan:{id}:asset_intelligence` (TTL 7 ngày)

---

## 7. AI Analyzer — Rule-Based Intelligence

### 7.1 OWASP/CWE/CVSS Mapping

| Vuln Type          | OWASP       | CWE     | CVSS |
|--------------------|-------------|---------|------|
| sqli               | A03:2021    | CWE-89  | 9.8  |
| time_based_sqli    | A03:2021    | CWE-89  | 7.5  |
| xss                | A03:2021    | CWE-79  | 6.1  |
| xss_stored         | A03:2021    | CWE-79  | 5.4  |
| cmdi               | A03:2021    | CWE-78  | 9.8  |
| time_based_cmdi    | A03:2021    | CWE-78  | 7.5  |
| ssrf               | A10:2021    | CWE-918 | 8.6  |
| lfi                | A01:2021    | CWE-22  | 7.5  |
| path_traversal     | A01:2021    | CWE-22  | 7.5  |
| info_disclosure    | A05:2021    | CWE-200 | 5.3  |
| open_redirect      | A01:2021    | CWE-601 | 6.1  |
| cors_misconfig     | A05:2021    | CWE-942 | 6.5  |
| xxe                | A05:2021    | CWE-611 | 7.5  |
| crlf_injection     | A03:2021    | CWE-93  | 4.7  |

### 7.2 Upgrade Path

- **Hiện tại**: Rule-based (zero cost, deterministic, < 1ms per finding)
- **Tương lai**: Ollama + local LLM cho contextual explanation
- LLM KHÔNG làm OWASP/CWE/CVSS mapping (giữ rule-based cho consistency)

---

## 8. CVE Intelligence

### 8.1 Data Sources

| Source   | URL                                              | Mô tả                          |
|----------|--------------------------------------------------|--------------------------------|
| NVD      | `services.nvd.nist.gov/rest/json/cves/2.0`       | National Vulnerability Database |
| CISA KEV | `www.cisa.gov/…/known_exploited_vulnerabilities` | Known Exploited Vulnerabilities |

### 8.2 Rate Limiting

- Không có API key: 5 req/30s
- Có `NVD_API_KEY`: 50 req/30s
- Internal: `asyncio.Semaphore(2)`, 0.7s between requests
- Cache Redis TTL 24h per technology lookup

### 8.3 KEV Badge

Findings có `is_actively_exploited: true` hiển thị badge **KEV** màu đỏ trong:
- Asset Intelligence drawer (CVE table)
- HTML report (CVE section)

---

## 9. Bảo Mật & Authentication

### 9.1 JWT

| Thuộc tính     | Giá trị                          |
|----------------|----------------------------------|
| Algorithm      | HS256                            |
| Expiry         | 8 giờ                            |
| Secret         | `SECRET_KEY` env var (bắt buộc)  |
| Payload        | `{ sub, role, exp, iat }`        |
| Storage        | `localStorage` (frontend)        |

Nếu `SECRET_KEY` không set → sinh random mỗi restart (tokens mất hiệu lực khi restart).

### 9.2 Endpoints Authentication

Tất cả endpoints **bắt buộc JWT** trừ:
- `POST /api/v1/auth/login` (public)
- `GET /health` (public)

WebSocket `/api/v1/ws/scans/{id}?token=<jwt>` — validate via query param.

### 9.3 Rate Limiting (Login)

20 requests/phút/IP trên endpoint `/auth/login`. Vượt quá → HTTP 429.

### 9.4 Security Headers

Tất cả responses trả về:
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
Strict-Transport-Security: max-age=31536000; includeSubDomains  [production only]
```

### 9.5 User Management

| Endpoint                              | Method | Auth         | Mô tả                    |
|---------------------------------------|--------|--------------|--------------------------|
| `/api/v1/auth/login`                  | POST   | Public       | Đăng nhập                |
| `/api/v1/auth/me`                     | GET    | Any user     | Thông tin user hiện tại  |
| `/api/v1/auth/change-password`        | POST   | Any user     | Đổi mật khẩu             |
| `/api/v1/auth/users`                  | POST   | Admin only   | Tạo user mới             |

Roles: `admin`, `analyst`, `viewer`

### 9.6 Admin User Seeding

Chỉ chạy khi **không có user nào** trong Redis (first startup):
- Username: `HQG_ADMIN_USERNAME` env (default: `admin`)
- Password: `HQG_ADMIN_PASSWORD` env; nếu không set → sinh random và log 1 lần

---

## 10. HTML Report

### 10.1 Design

- Dark theme, self-contained (no external CDN), offline-capable
- Fixed sidebar TOC + scrollable main content
- Pure inline CSS + vanilla JS

### 10.2 Sections

1. **Hero** — target, scan mode, duration, endpoint/tech counts
2. **Score Grid** — Overall score + Critical/High/Medium/Low counts
3. **Findings** — grouped by (vuln_type, parameter), expandable, confidence badges
4. **CVE Intelligence** — CVE ID, technology, CVSS, KEV badge
5. **Asset Intelligence** — per-host risk score, tech pills, vuln groups, CVE table [Standard/Deep]
6. **Attack Surface Map** — riskiest endpoints + entry points [Deep only]
7. **Attack Path Scenarios** — multi-step chains [Deep only]
8. **Asset Summary** — domains, subdomains, technologies
9. **Remediation Roadmap** — priority table P0/P1/P2/P3

### 10.3 XSS Safety

Tất cả user-supplied data qua `_safe()` → `html.escape(str(text), quote=True)`.

---

## 11. API Reference

### Authentication (không cần token)

| Method | Path                      | Mô tả                  |
|--------|---------------------------|------------------------|
| POST   | `/api/v1/auth/login`      | Đăng nhập → JWT token  |
| GET    | `/health`                 | Health check           |

### Authentication (cần token)

| Method | Path                                | Mô tả                    |
|--------|-------------------------------------|--------------------------|
| GET    | `/api/v1/auth/me`                   | User info                |
| POST   | `/api/v1/auth/change-password`      | Đổi mật khẩu             |
| POST   | `/api/v1/auth/users`                | Tạo user (admin only)    |

### Scans

| Method | Path                                  | Mô tả                           |
|--------|---------------------------------------|----------------------------------|
| POST   | `/api/v1/scans`                       | Bắt đầu scan `{target, mode}`   |
| GET    | `/api/v1/scans`                       | Danh sách scans                  |
| GET    | `/api/v1/scans/{id}`                  | Trạng thái + tiến độ             |
| DELETE | `/api/v1/scans/{id}`                  | Huỷ scan                         |
| GET    | `/api/v1/scans/{id}/asset-intelligence` | Asset Intelligence per-host    |
| WS     | `/api/v1/ws/scans/{id}?token=<jwt>`   | Real-time progress               |

Modes: `quick`, `standard`, `deep`, `full`

### Domains / Assets

| Method | Path                                  | Mô tả                        |
|--------|---------------------------------------|------------------------------|
| GET    | `/api/v1/assets`                      | Danh sách domains            |
| POST   | `/api/v1/assets`                      | Thêm domain `{url}`          |
| DELETE | `/api/v1/assets/{id}`                 | Xoá domain                   |
| GET    | `/api/v1/assets/{scan_id}/discovery`  | Discovery results của scan   |
| GET    | `/api/v1/assets/{domain_id}/report`   | Download report theo domain  |

### Vulnerabilities

| Method | Path                             | Mô tả                                          |
|--------|----------------------------------|------------------------------------------------|
| GET    | `/api/v1/vulnerabilities`        | List (filter: scan_id, severity, domain, endpoint) |
| GET    | `/api/v1/vulnerabilities/{id}`   | Chi tiết + remediation                         |
| PATCH  | `/api/v1/vulnerabilities/{id}`   | Cập nhật status / false-positive / note        |

### Findings

| Method | Path                                     | Mô tả                        |
|--------|------------------------------------------|------------------------------|
| PUT    | `/api/v1/findings/{id}/false-positive`   | Toggle false-positive state  |

### Reports

| Method | Path                                            | Mô tả                              |
|--------|-------------------------------------------------|------------------------------------|
| GET    | `/api/v1/reports/{scan_id}`                     | Metadata report                    |
| GET    | `/api/v1/reports/{scan_id}/download?format=X`   | Download (json / csv / html / pdf) |

### Dashboard

| Method | Path                            | Mô tả                      |
|--------|---------------------------------|----------------------------|
| GET    | `/api/v1/dashboard/stats`       | Overview (cache 30s)       |
| GET    | `/api/v1/dashboard/posture`     | Security posture trend     |
| GET    | `/api/v1/dashboard/top-risks`   | Top 5 riskiest assets      |

### Settings

| Method | Path                               | Mô tả                              |
|--------|------------------------------------|------------------------------------|
| GET    | `/api/v1/settings`                 | Platform settings                  |
| PUT    | `/api/v1/settings`                 | Cập nhật settings (incl NVD key)   |
| POST   | `/api/v1/settings/verify-nvd-key`  | Kiểm tra NVD API key               |

---

## 12. Environment Variables

| Biến                    | Bắt buộc | Mặc định                        | Mô tả                              |
|-------------------------|----------|---------------------------------|------------------------------------|
| `SECRET_KEY`            | **Có**   | *(ephemeral random)*            | JWT signing key                    |
| `HQG_ADMIN_USERNAME`    | Không    | `admin`                         | Username admin lần đầu             |
| `HQG_ADMIN_PASSWORD`    | **Có**   | *(random, logged once)*         | Password admin lần đầu             |
| `ALLOWED_ORIGINS`       | **Có**   | `http://localhost:3000`         | CORS — URL frontend truy cập       |
| `REDIS_URL`             | Không    | `redis://redis:6379/0`          | Broker URL                         |
| `REDIS_RESULT_BACKEND`  | Không    | `redis://redis:6379/1`          | Celery result backend              |
| `APP_DEBUG`             | Không    | `false`                         | Debug mode (ẩn /docs nếu false)    |
| `NVD_API_KEY`           | Không    | `""`                            | NVD API key (tăng rate limit)      |
| `ELASTICSEARCH_URL`     | Không    | `""`                            | Elasticsearch (tắt nếu để trống)   |
| `POSTGRES_DSN`          | Không    | `""`                            | PostgreSQL (tắt nếu để trống)      |

---

## 13. Frontend

### 13.1 Pages

| Route               | File                      | Mô tả                         |
|---------------------|---------------------------|-------------------------------|
| `/login`            | `Login.tsx`               | Đăng nhập                     |
| `/`                 | `Index.tsx`               | Dashboard (stats, posture, risks) |
| `/assets`           | `AssetManagement.tsx`     | Quản lý tên miền               |
| `/scans`            | `SecurityScans.tsx`       | Quét bảo mật + live WS        |
| `/vulnerabilities`  | `Vulnerabilities.tsx`     | Danh sách lỗ hổng              |
| `/asset-intelligence` | `AssetIntelligence.tsx` | Per-host intelligence view     |
| `/reports`          | `Reports.tsx`             | Tải báo cáo                    |
| `/settings`         | `Settings.tsx`            | Cài đặt platform               |

### 13.2 Authentication Flow (Frontend)

1. `isAuthenticated()` — decode JWT, kiểm tra `exp`, tự clear nếu hết hạn
2. `ProtectedRoute` — redirect về `/login` nếu chưa auth
3. `request()` helper — tự đính `Authorization: Bearer` vào mọi request
4. HTTP 401 → clear storage + redirect `/login`
5. HTTP 429 → hiện thông báo "Quá nhiều yêu cầu"
6. WebSocket truyền token qua query param `?token=<jwt>`
7. WS close code `4401` → tự logout

### 13.3 Key Components

| Component                    | Mô tả                                            |
|------------------------------|--------------------------------------------------|
| `AppSidebar.tsx`             | Navigation sidebar, active route highlight        |
| `asset-intelligence/AssetDetailDrawer.tsx` | Slide-in panel với 6 sections vulnerability detail |
| `asset-intelligence/ConfidenceBadge.tsx`   | Badge confirmed/high/medium/low           |
| `asset-intelligence/RiskBar.tsx`           | Progress bar risk score 0–100             |
| `asset-intelligence/AssetIntelligencePanel.tsx` | Filterable host list + global summary  |
| `scans/`                     | Scan creation + live progress via WebSocket       |
| `dashboard/`                 | Stats cards, posture chart, top risks             |

---

## 14. Cấu Trúc Thư Mục

```
secure-shield-hq/
├── docker-compose.yml           # Production: 4 services (redis, backend, worker, frontend)
├── Dockerfile.frontend          # Multi-stage: Node 18 build → nginx:alpine serve
├── nginx.conf                   # SPA routing + /api/* proxy + WebSocket proxy
├── .env                         # Active config (không commit)
├── .env.example                 # Template config (commit)
├── DEPLOY.md                    # Hướng dẫn deploy VPS
│
├── hqg-backend/
│   ├── Dockerfile               # Python 3.11-slim + WeasyPrint deps
│   ├── pyproject.toml           # Dependencies (uv/pip install .)
│   ├── fingerprints_data.json   # Tech fingerprint database (3.7MB)
│   │
│   ├── backend/
│   │   ├── main.py              # FastAPI app + security headers + rate limiting middleware
│   │   ├── celery_app.py        # Celery config + 10 queues
│   │   ├── config/config.py     # Pydantic Settings (env-based)
│   │   ├── core/
│   │   │   ├── auth.py          # JWT (HS256, 8h, SECRET_KEY env)
│   │   │   ├── redis.py         # Async Redis client
│   │   │   ├── search.py        # Elasticsearch client (optional)
│   │   │   └── user_store.py    # User CRUD + seed từ HQG_ADMIN_* env
│   │   └── api/routes/
│   │       ├── auth.py          # login, me, change-password, create-user
│   │       ├── scans.py         # CRUD /scans + asset-intelligence
│   │       ├── dashboard.py     # stats (30s cache), posture, top-risks
│   │       ├── assets.py        # CRUD domains + discovery + domain-report
│   │       ├── vulnerabilities.py # list/detail/patch + FP filter
│   │       ├── findings.py      # toggle false-positive
│   │       ├── reports.py       # metadata + download (html/json/csv/pdf)
│   │       ├── settings.py      # get/update + verify-nvd-key
│   │       └── ws.py            # WebSocket /ws/scans/{id}?token=<jwt>
│   │
│   ├── scanner/
│   │   ├── asset_discovery/     # subdomain_enum, dns_resolver, tech_fingerprint
│   │   ├── crawler/             # BFS crawler, html/js/form parsers
│   │   ├── template_engine/     # YAML template executor
│   │   ├── payload_engine/      # Async injector, payload loader/mutator
│   │   ├── detection_engine/    # VulnerabilityFinding, response/diff/time analyzers
│   │   ├── verification/        # Multi-step false-positive reduction
│   │   ├── knowledge_base/      # vuln_templates.py — 12 templates + generic fallback
│   │   ├── cve_intelligence/    # NVD client, KEV client, tech parser
│   │   ├── attack_surface/      # graph.py, attack_paths.py (6 chain templates)
│   │   ├── asset_intelligence/  # models, enricher, manager, risk_aggregator
│   │   ├── tech_fingerprint/    # Wappalyzer-compatible fingerprinting
│   │   └── scan_manager/        # pipeline.py (13 stages), tasks.py, scan_service.py
│   │
│   ├── ai/analyzer/             # Rule-based OWASP/CWE/CVSS + explanation engine
│   └── reporting/engine/        # html_report.py, json/csv/pdf exporters
│
└── src/                         # React frontend
    ├── pages/                   # 9 pages (Login + 8 protected)
    ├── components/
    │   ├── asset-intelligence/  # AssetDetailDrawer, ConfidenceBadge, RiskBar, Panel
    │   ├── dashboard/           # Stats cards, charts
    │   ├── scans/               # Scan form, progress
    │   └── layout/              # DashboardLayout, AppSidebar
    ├── services/api.ts          # Fetch client: JWT auth, 401/429 handling, WS factory
    ├── hooks/use-language.ts    # i18n (vi/en)
    └── lib/i18n.ts              # Translation strings
```

---

## 15. Tiêu Chuẩn Áp Dụng

- **OWASP Top 10 2021** — vulnerability classification
- **CWE** (Common Weakness Enumeration) — root cause mapping
- **CVE** (Common Vulnerabilities and Exposures) — known vulnerability reference
- **CVSS v3.1** — severity scoring
- **CISA KEV** — actively exploited vulnerability tracking
- **NVD 2.0 API** — vulnerability database queries
