# FULL SYSTEM DEBUG — HQG Security Scanner

> Generated from exhaustive source-code review of every module.
> **Purpose:** Give any developer a complete understanding of how the system works, what is broken, and exactly where to fix it.

---

## 1. System Overview

**HQG Scanner** is a Celery-based vulnerability scanning pipeline backed by Redis state storage and exposed through a FastAPI REST API.

| Component | Technology | Port/Address |
|-----------|-----------|--------------|
| API Server | FastAPI + Uvicorn | `:8000` |
| Task Queue | Celery 5.x | — |
| Message Broker + State | Redis 7 | `:6379/0` |
| Containerization | Docker Compose (3 services: api, worker, redis) | — |

**Scan Lifecycle:**
1. `POST /scans` → creates `ScanJob` in Redis, dispatches `start_scan` Celery task
2. Worker picks up `start_scan` → runs `run_pipeline()` (async, sequential stages)
3. Each stage updates Redis progress (`scan:{id}` hash, 7-day TTL)
4. `GET /scans/{id}` returns current stage/progress/findings
5. `DELETE /scans/{id}` marks as cancelled

**Scan Modes** (frozen configs in `scan_modes.py`):

| Mode | Depth | Concurrency | Stages | Features |
|------|-------|-------------|--------|----------|
| `quick` | 2 | 20 | crawl → template_scan → detect | — |
| `standard` | 3 | 40 | crawl → template_scan → payload → detect | — |
| `deep` | 4 | 40 | full pipeline | +headers, +mutation |
| `full` | 6 | 60 | full pipeline | +headers, +mutation, +thorough |

---

## 2. Full Architecture Breakdown (9 Modules)

### 2.1 `backend/api/routes/scans.py` — REST API
- **Router prefix:** `/scans`
- **Endpoints:** `POST ""`, `GET ""`, `GET "/{scan_id}"`, `DELETE "/{scan_id}"`
- **Input validation:** Pydantic model with regex target validation and mode enum check
- **Concurrency:** All Redis calls wrapped in `run_in_threadpool()` for async compat
- **Task dispatch:** `start_scan.apply_async(args=[...], task_id=scan_id)`

### 2.2 `scanner/scan_manager/` — Pipeline Orchestrator

#### `scan_service.py` — Redis CRUD
- `create_scan(target, mode)` → generates UUID, stores `ScanJob` hash in Redis
- `get_scan(scan_id)` → deserializes from Redis hash
- `update_scan(scan_id, **fields)` → partial update of Redis hash
- `list_scans()` → iterates `scans:index` set, returns list sorted by `created_at`
- `store_findings(scan_id, findings)` / `get_findings(scan_id)` → JSON blob in `scan:{id}:findings`
- `store_discovery(scan_id, data)` / `get_discovery(scan_id)` → JSON blob in `scan:{id}:discovery`
- All keys: 7-day TTL via `_persist()`

#### `models.py` — Data Models
- `ScanStatus` enum: `queued`, `running`, `completed`, `failed`, `cancelled`
- `ScanStage` enum: `pending`, `asset_discovery`, `crawling`, `template_scan`, `payload_injection`, `detection`, `ai_analysis`, `cve_intelligence`, `reporting`, `done`
- `ScanJob` dataclass: `scan_id`, `target`, `mode`, `status`, `stage`, `progress`, `created_at`, `updated_at`, `error`

#### `scan_modes.py` — Mode Configuration
- 4 frozen `ScanModeConfig` dataclasses
- Each specifies: `stages` (list of `ScanStage`), `max_depth`, `max_concurrency`, `inject_headers`, `payload_mutation`
- `SCAN_MODES` dict maps string keys to configs

#### `tasks.py` — Celery Entry Point
- `start_scan(scan_id, target, mode)` — the only Celery task
- Calls `asyncio.run(run_pipeline(scan_id, target, mode))`
- On success: stores findings + discovery, sets status to `completed`
- On exception: sets status to `failed` with error message

#### `pipeline.py` — Sequential Pipeline
- `_set_stage(scan_id, stage, progress)` — updates Redis with current stage/progress
- `run_pipeline(scan_id, target, config)` — see Section 3 for full flow

### 2.3 `scanner/asset_discovery/` — DNS & Service Recon

#### `tasks.py`
- `discover_assets(scan_id, target)` → Celery task wrapping `_discover_assets_async()`
- Flow: `extract_domain()` → `discover_subdomains()` → `resolve_dns_records()` per host → `detect_http_services()` → `detect_technologies()`

#### `subdomain_enum.py`
- Three parallel subdomain strategies: wordlist brute-force, CT log (crt.sh), DNS record extraction
- Wordlist from `wordlists/subdomains.txt`, concurrency-limited to 100

#### `dns_resolver.py`
- Resolves A, AAAA, CNAME, MX, TXT, NS records per host in parallel via `asyncio.gather`

#### `service_detector.py`
- Probes each host on HTTP + HTTPS, captures status code, headers, server banner, body snippet (4KB)

#### `tech_fingerprint.py`
- Pattern matching on headers (`server`, `x-powered-by`, `set-cookie`) and body snippets
- Detects: nginx, apache, express, django, laravel, next.js, react

#### `models.py`
- `DNSResolution`, `ServiceProbeResult`, `AssetDiscoveryOutput` dataclasses
- `AssetDiscoveryOutput.to_dict()` for serialization

### 2.4 `scanner/crawler/` — Web Crawler

#### `crawler.py` — BFS Endpoint Discovery
- **⚠️ CRITICAL BUG: Contains TWO complete implementations.** See Section 6.
- New version (first def, ~L103): Uses `_register_endpoint()` to produce `EndpointInfo` objects with parameter metadata
- Old version (second def, ~L330): Uses `_register_url()` — simpler, no `EndpointInfo`
- **Python uses the LAST definition → old version is active**
- BFS traversal: respects `max_depth`, `max_concurrency` semaphore
- Per-page: HTML parsing → link extraction → form extraction → JS endpoint extraction
- GraphQL introspection attempted on `/graphql` endpoints

#### `models.py`
- `FormModel`: action, method, fields dict
- `GraphQLEndpoint`: url, types list
- `EndpointInfo`: url, parameters list, method, source (form/link/js/graphql)
- `CrawlOutput`: endpoints (set), endpoint_info (list[EndpointInfo]), parameters (dict), forms (list[FormModel]), api_endpoints (set), graphql_endpoints (list)

#### `html_parser.py`
- BeautifulSoup extraction: `<a href>`, `<script src>`, inline `<script>` text, `<form>` elements, `<link>` JS files

#### `form_parser.py`
- Extracts `FormModel` from `<form>` tags: action URL, method, input/select/textarea field names

#### `js_parser.py`
- Regex-based extraction from JavaScript: `fetch()`, `axios.*()`, `$.ajax()`, `XMLHttpRequest.open()`, `window.location`, string literals with URL patterns
- Also extracts parameter names from URL-like query strings

#### `url_normalizer.py`
- Normalizes URLs (scheme, port, path, query sorting)
- `endpoint_from_url()` strips query values for deduplication

#### `scope_filter.py`
- `is_in_scope(url, base)` — hostname matching
- `is_static_resource(url)` — filters .jpg, .css, .png, etc.
- API/GraphQL endpoint classification

### 2.5 `scanner/template_engine/` — YAML Template Scanner

#### `loader.py`
- Reads `*.yaml` from `templates/` directory
- Supports multi-document YAML (multiple templates per file)
- Parses into `ScanTemplate` objects

#### `models.py`
- `ScanTemplate`: id, info, requests list, matchers
- `TemplateRequest`: method, path, headers, body, params
- `TemplateMatcher`: type (word/regex/status/time), value, negative flag, condition (or/and)
- `TemplateMatch`: template_id, endpoint, matched_at, evidence, severity

#### `executor.py` — Template Execution Engine
- `_inject_payload_into_url(url, payload, known_params)` — injects into query params
- `_inject_payload_into_body(body, payload)` — injects into body string
- `_execute_template_request(client, endpoint, template, endpoint_info)` — sends request, evaluates matchers
- `run_templates_async(endpoints, templates, endpoint_info, concurrency)` — parallel execution
- **⚠️ BUG: Dead code block.** Match dedup section is duplicated after `return matches`. See Section 6.

#### `matchers.py`
- Evaluates 4 matcher types: `word` (substring), `regex` (re.search), `status` (code comparison), `time` (threshold)
- Supports `condition: or` (any match) and `condition: and` (all must match)
- Supports `negative: true` (inverted match)

#### `tasks.py`
- `_run_template_scan_async(scan_id, endpoints, endpoint_info, config)` → loads templates, runs executor, returns finding dicts

### 2.6 `scanner/payload_engine/` — Payload Injection

#### `payload_loader.py`
- Loads payload text files from `payloads/` directory: `sqli.txt`, `xss.txt`, `ssrf.txt`, `cmdi.txt`, `lfi.txt`

#### `payload_mutator.py`
- WAF bypass mutations: `comment_inject`, `url_encode`, `case_mutate`, `xss_obfuscate`, fragment strategies
- Applied when `payload_mutation: true` in scan mode config

#### `request_builder.py` — Injection Request Construction
- `build_injection_requests(endpoint, vuln_type, payloads, known_params)`:
  - Priority 1: `known_params` from crawler's `EndpointInfo`
  - Priority 2: URL query parameters
  - Priority 3: Generic fallback params: `id`, `q`, `search`, `cat`, `page`, `item`, `name`
- Also `build_form_injection_requests()` for POST/GET form submissions

#### `injector.py` — HTTP Executor
- `inject_single(client, request, semaphore)` — sends HTTP request, measures response time
- Captures response body (truncated to 10KB), status code, response length
- Returns `InjectionResult`

#### `models.py`
- `InjectionRequest`: endpoint, vuln_type, payload, url, method, params, json_body, form_data, headers
- `InjectionResult`: response_code, response_time, response_body, response_length, error

#### `tasks.py`
- `_inject_payloads_async(scan_id, endpoints, forms, endpoint_info, config)`:
  - Loads payloads → builds param_map from endpoint_info → iterates endpoints × vuln_types
  - Calls `build_injection_requests()` per endpoint
  - Runs HTTP injections concurrently via semaphore
  - Returns list of `(InjectionRequest, InjectionResult)` tuples

### 2.7 `scanner/detection_engine/` — Vulnerability Detection

#### `response_analyzer.py` — Pattern-Based Detection
- SQL injection: matches error messages from MySQL, PostgreSQL, Oracle, MSSQL, SQLite
- XSS: checks raw reflection, HTML-decoded, URL-decoded, plus marker detection
- SSRF: `127.0.0.1`, AWS metadata patterns
- Command injection: shell output patterns (`uid=`, `gid=`)
- LFI: file artifacts (`/etc/passwd`, `win.ini`)
- Info disclosure: `phpinfo()`, stack traces

#### `diff_analyzer.py` — Baseline Comparison
- Fetches baseline response per endpoint (no payload)
- Status code analysis: detects 500/503 from injection vs normal baseline
- Body length analysis: growth > 500 bytes on XSS/SSRF suggests reflection/SSRF success

#### `time_analyzer.py` — Blind Detection
- Absolute threshold: response time ≥ 5 seconds
- Relative threshold: response time ≥ 3 seconds AND ≥ 4× baseline time
- Used for time-based blind SQLi and similar

#### `error_patterns.py` — Regex Patterns
- Comprehensive regex arrays for SQL errors, LFI artifacts, SSRF indicators, CMDi output, info disclosure

#### `models.py`
- `VulnerabilityFinding`: url, vuln_type, severity, confidence, payload, evidence, method, parameter, owasp_category, cwe_id
- OWASP/CWE/severity mapping for 9 vulnerability types

#### `tasks.py`
- `_detect_async(scan_id, injection_results, config)`:
  - Groups results by endpoint
  - Fetches baseline per endpoint
  - Runs 3 analyzers (response, diff, timing) per injection result
  - Deduplicates findings by (url, vuln_type, parameter)
  - Returns list of `VulnerabilityFinding` dicts

### 2.8 `ai/analyzer/tasks.py` — AI Post-Processing

- `_analyze_single(finding)`:
  - False-positive classification based on evidence strength
  - OWASP category and CWE ID mapping
  - Severity mapping with adjustments
  - Human-readable explanation generation
  - Returns enriched finding dict

### 2.9 `reporting/engine/tasks.py` — Report Generation

- `generate_report(scan_id, analyzed_vulnerabilities, formats, output_dir, scan_meta)`:
  - Calls `build_report()` to create `ScanReport` from findings
  - Writes to multiple formats: JSON, CSV, HTML, PDF
  - Output path: `/tmp/hqg-reports/{scan_id}/`
  - Returns summary dict with vulnerability counts and file paths

### 2.10 `scanner/cve_intelligence/` — CVE Enrichment

#### `cve_lookup.py`
- `detect_software_versions(services, technologies)` — regex patterns for Apache, nginx, PHP, etc. from server banners/headers
- `lookup_cves(software_versions)` — queries NVD + KEV for each detected version
- `enrich_findings(findings, cve_records)` — severity promotion if CVE is in CISA KEV

#### `nvd_client.py`
- NVD REST API 2.0 client
- Keyword-based CVE search
- CVSS score extraction (v3.1, v3.0, v2.0 fallback)

#### `kev_client.py`
- Downloads CISA Known Exploited Vulnerabilities catalog
- Matches CVE records against technology keywords

#### `models.py`
- `SoftwareVersion`: name, version, source
- `CVERecord`: cve_id, description, cvss_score, severity, affected_software, in_kev
- `CVEIntelligenceOutput`: software_versions, cve_records, kev_matches

---

## 3. End-to-End Pipeline Flow

```
run_pipeline(scan_id, target, mode)
│
├─ Stage 1: ASSET DISCOVERY (progress 0.05 → 0.20)
│  └─ _discover_assets_async(target)
│     ├─ extract_domain(target)
│     ├─ discover_subdomains(domain, resolver, client)
│     │  ├─ discover_wordlist_subdomains()  [brute-force]
│     │  ├─ discover_ct_log_subdomains()    [crt.sh]
│     │  └─ discover_dns_record_subdomains() [NS/MX/TXT]
│     ├─ resolve_dns_records() per host     [A/AAAA/CNAME/MX/TXT/NS]
│     ├─ detect_http_services(hosts)        [HTTP+HTTPS probe]
│     └─ detect_technologies(service_results) [header/body fingerprint]
│
├─ Stage 2: WEB CRAWLING (progress 0.22 → 0.40)
│  └─ crawl_target_async(url, max_depth, max_concurrency)  [per target]
│     ├─ BFS traversal
│     │  ├─ _fetch_text(url) → HTML
│     │  ├─ extract_elements(html) → links, scripts, forms
│     │  ├─ extract_form_models(forms) → FormModel list
│     │  ├─ extract_js_endpoints(script_text) → endpoint strings
│     │  └─ _register_url(url, seen) OR _register_endpoint(url, params, method, source)
│     └─ Returns CrawlOutput (endpoints, forms, endpoint_info, parameters)
│
│  ⚠️ testphp.vulnweb.com FORCE-INJECT:
│     If target contains "testphp.vulnweb.com", injects:
│     - 6 hardcoded endpoints (search.php, listproducts.php, product.php, etc.)
│     - 4 hardcoded forms (search, login, comment, guestbook)
│     - EndpointInfo objects with known parameters
│
├─ Stage 2.5: TEMPLATE SCAN (progress 0.41 → 0.50)
│  └─ _run_template_scan_async(scan_id, endpoints, endpoint_info, config)
│     ├─ load_templates() → [ScanTemplate]  (10 YAML templates)
│     ├─ run_templates_async(endpoints, templates, endpoint_info, concurrency)
│     │  └─ Per endpoint × template:
│     │     ├─ _inject_payload_into_url(url, payload, known_params)
│     │     ├─ _inject_payload_into_body(body, payload)
│     │     ├─ Send HTTP request
│     │     └─ Evaluate matchers (word/regex/status/time)
│     └─ Returns list of TemplateMatch finding dicts
│
├─ Stage 3: PAYLOAD INJECTION (progress 0.52 → 0.65)
│  └─ _inject_payloads_async(scan_id, endpoints, forms, endpoint_info, config)
│     ├─ load_payloads() → {vuln_type: [payloads]}
│     ├─ Build param_map from endpoint_info (url → params)
│     ├─ Per endpoint × vuln_type:
│     │  ├─ build_injection_requests(endpoint, type, payloads, known_params)
│     │  └─ inject_single(client, request, semaphore) → InjectionResult
│     ├─ Per form:
│     │  └─ build_form_injection_requests(form, type, payloads)
│     └─ Returns [(InjectionRequest, InjectionResult), ...]
│
├─ Stage 4: VULNERABILITY DETECTION (progress 0.67 → 0.82)
│  └─ _detect_async(scan_id, injection_results, config)
│     ├─ Group results by endpoint
│     ├─ Fetch baseline per unique endpoint
│     ├─ Per injection result, run 3 analyzers:
│     │  ├─ response_analyzer.analyze() → pattern matching
│     │  ├─ diff_analyzer.analyze() → baseline comparison
│     │  └─ time_analyzer.analyze() → blind detection
│     ├─ Merge template_findings + detection_findings
│     └─ Deduplicate by (url, vuln_type, parameter)
│
├─ Stage 5: AI ANALYSIS (progress 0.84 → 0.88)
│  └─ Per finding:
│     └─ _analyze_single(finding)
│        ├─ False-positive classification
│        ├─ OWASP/CWE mapping
│        └─ Human-readable explanation
│
├─ Stage 6: CVE INTELLIGENCE (progress 0.89 → 1.0)
│  └─ _enrich_async(technologies, services, findings)
│     ├─ detect_software_versions(services, technologies)
│     ├─ lookup_cves(software_versions)  [NVD + KEV]
│     └─ enrich_findings(findings, cve_records) [severity promotion]
│
└─ DONE: Store findings + discovery in Redis, set status=completed
```

---

## 4. Data Flow Diagram

```
┌─────────────┐
│  POST /scans │  target, mode
└──────┬──────┘
       │
       ▼
┌──────────────┐     Redis: scan:{id}
│  create_scan │────────────────────────► ScanJob (queued)
└──────┬───────┘
       │ apply_async
       ▼
┌──────────────┐
│  start_scan  │  Celery task
└──────┬───────┘
       │ asyncio.run
       ▼
┌──────────────────────────────────────────────────────────────┐
│  run_pipeline                                                 │
│                                                               │
│  ┌─────────────────┐     ┌───────────────────┐                │
│  │ asset_discovery  │────►│ AssetDiscoveryOut  │                │
│  │ (DNS, subdomains,│     │  domain, subdomains│                │
│  │  services, tech) │     │  ips, services,    │                │
│  └─────────────────┘     │  technologies      │                │
│         │                 └───────┬───────────┘                │
│         ▼                         │                            │
│  ┌─────────────────┐              │                            │
│  │ crawler          │◄────────────┘ (per target host)          │
│  │ (BFS, forms, JS) │                                          │
│  └────────┬────────┘                                           │
│           │  CrawlOutput                                       │
│           │  {endpoints, endpoint_info, forms, parameters}     │
│           ▼                                                    │
│  ┌─────────────────┐  ┌─────────────────┐                     │
│  │ template_engine  │  │ payload_engine   │                    │
│  │ (YAML templates) │  │ (sqli,xss,ssrf, │                    │
│  │                  │  │  cmdi,lfi)       │                    │
│  └────────┬─────────┘  └────────┬────────┘                    │
│           │ TemplateMatch list   │ (InjReq, InjRes) list       │
│           │                      │                             │
│           ▼                      ▼                             │
│  ┌───────────────────────────────────────┐                     │
│  │ detection_engine                       │                    │
│  │ (response + diff + timing analyzers)   │                    │
│  │ + merge template_findings              │                    │
│  └──────────────────┬────────────────────┘                     │
│                     │ VulnerabilityFinding list                 │
│                     ▼                                          │
│  ┌──────────────────┐                                          │
│  │ ai/analyzer       │                                         │
│  │ (FP filter, OWASP,│                                         │
│  │  CWE, explanation)│                                         │
│  └────────┬─────────┘                                          │
│           │ enriched findings                                  │
│           ▼                                                    │
│  ┌──────────────────┐                                          │
│  │ cve_intelligence  │                                         │
│  │ (NVD, CISA KEV)   │                                         │
│  └────────┬──────────┘                                         │
│           │ final findings + cve_records                       │
│           ▼                                                    │
│  Redis: scan:{id}:findings ← JSON                              │
│  Redis: scan:{id}:discovery ← JSON                             │
│  Redis: scan:{id} → status=completed                           │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. Critical Files Map

| Priority | File | Purpose | Status |
|----------|------|---------|--------|
| 🔴 P0 | `scanner/crawler/crawler.py` | Web crawler — endpoint discovery | **BROKEN** — dual definitions, old code shadows new |
| 🔴 P0 | `scanner/scan_manager/pipeline.py` | Pipeline orchestrator | Works, but receives empty `endpoint_info` from broken crawler |
| 🟡 P1 | `scanner/template_engine/executor.py` | Template execution | Works, has dead code block |
| 🟡 P1 | `scanner/payload_engine/request_builder.py` | Injection request construction | Works, but falls back to generic params because no `endpoint_info` |
| 🟢 P2 | `scanner/payload_engine/tasks.py` | Payload injection orchestrator | Works correctly |
| 🟢 P2 | `scanner/detection_engine/tasks.py` | Detection orchestrator | Works correctly |
| 🟢 P2 | `scanner/detection_engine/response_analyzer.py` | Pattern-based detection | Works correctly |
| 🟢 P2 | `scanner/scan_manager/scan_service.py` | Redis CRUD | Works correctly |
| 🟢 P2 | `scanner/scan_manager/tasks.py` | Celery entry point | Works correctly |
| 🟢 P2 | `backend/api/routes/scans.py` | REST API | Works correctly |
| 🟢 P3 | All other modules | Supporting infrastructure | Work correctly |

---

## 6. Root Cause Analysis

### BUG #1 (CRITICAL): Crawler Dual-Definition — `crawler.py`

**What happened:** The file `scanner/crawler/crawler.py` (~497 lines) contains **two complete implementations** of the crawler. The newer version (lines ~24–265) uses `_register_endpoint()` to produce `EndpointInfo` objects with rich parameter metadata. The older version (lines ~266–497) uses `_register_url()` — a simpler tracker that produces no `EndpointInfo`.

**Root cause:** When the crawler was upgraded to support `EndpointInfo`, the new code was added **above** the old code instead of **replacing** it. In Python, when the same function name is defined twice at module scope, the **last definition wins**. The old `crawl_target_async` at line ~330 shadows the new one at line ~103.

**6 duplicate function names:**

| Function | New (1st def) | Old (2nd def, ACTIVE) | Difference |
|----------|--------------|----------------------|------------|
| `_fetch_text` | ~L24 | ~L269 | Identical |
| `_collect_query_params` | ~L37 (returns `list[str]`) | ~L281 (returns `set[str]`) | **Return type differs** |
| `_root_url` | ~L42 | ~L286 | Identical |
| `_check_graphql_introspection` | ~L49 | ~L293 | Identical |
| `crawl_target_async` | ~L103 (uses `_register_endpoint`) | ~L330 (uses `_register_url`) | **Entirely different logic** |
| `_INTROSPECTION_QUERY` | ~L22 | ~L266 | Identical value |

**Impact chain:**
1. `crawl_target_async` (old version) runs → returns `CrawlOutput` with **empty `endpoint_info`**
2. `pipeline.py` receives `result.endpoint_info` = `[]`
3. Template engine gets no `known_params` → injects payloads only into generic `id` parameter
4. Payload engine gets no `known_params` → falls back to generic params (`id`, `q`, `search`, `cat`, `page`, `item`, `name`)
5. Scanning accuracy is severely degraded — crawler finds endpoints but injection stages don't know which parameters exist

**Severity:** CRITICAL — this breaks the entire parameter-aware scanning capability that was specifically built to improve accuracy.

---

### BUG #2 (LOW): Template Executor Dead Code — `executor.py`

**What happened:** In `run_templates_async()`, the match deduplication block (collect results, filter duplicates by endpoint+template_id, count errors/nones) appears **twice**. There is a `return matches` statement after the first copy, making the second copy (~16 lines) completely unreachable.

**Root cause:** Copy-paste during development — the dedup logic was likely moved or restructured, and the old copy was not deleted.

**Impact:** None at runtime (dead code is never executed). Code maintainability issue only.

---

### BUG #3 (MEDIUM): `_collect_query_params` Type Mismatch

**What happened:** The new version of `_collect_query_params` (line ~37) returns `list[str]`. The old version (line ~281, which is the active one) returns `set[str]`. Since the active (old) version is used, consumers may receive a `set` when they expect a `list`.

**Impact:** Minor — both are iterable, and `set` actually provides automatic deduplication. But it means the type contract documented in the new version is not what actually executes.

---

### BUG #4 (INFORMATIONAL): testphp.vulnweb.com Force-Inject Workaround

The pipeline contains a hardcoded block (~40 lines) that force-injects known endpoints and forms specifically for `testphp.vulnweb.com`. This was added to ensure the test target always has endpoints to scan, likely as a workaround for the crawler bug (#1 above). While functional, this is a test-only band-aid that should be removed once the crawler is fixed.

---

## 7. Broken Stage Identification

```
Stage         Status      Issues
──────────────────────────────────────────────────────
Asset Disc.   ✅ WORKS    No issues found
Crawling      ⚠️ DEGRADED Old version active — no EndpointInfo
Template Scan ⚠️ DEGRADED No known_params → generic injection only
Payload Inj.  ⚠️ DEGRADED Falls back to generic params
Detection     ✅ WORKS    Correctly analyzes whatever it receives
AI Analysis   ✅ WORKS    No issues found
CVE Intel.    ✅ WORKS    No issues found
Reporting     ✅ WORKS    No issues found
```

**Cascade effect:** The crawler bug (#1) cascades through template scan and payload injection. Detection, AI, and CVE stages work correctly — they just receive fewer/weaker findings because the upstream injection was done blindly.

---

## 8. Exact Fix Locations

### Fix #1 — Remove old crawler implementation

**File:** `scanner/crawler/crawler.py`
**Action:** Delete everything from line ~266 to end of file (approximately lines 266–497)
**What this removes:**
- Second `_INTROSPECTION_QUERY` assignment
- Second `_fetch_text`
- Second `_collect_query_params` (set version)
- Second `_root_url`
- Second `_check_graphql_introspection`
- `_register_url` function (old tracker)
- Second `crawl_target_async` (old version)

**What survives:**
- First `_INTROSPECTION_QUERY`
- First `_fetch_text`
- First `_collect_query_params` (list version)
- First `_root_url`
- First `_check_graphql_introspection`
- `_register_endpoint` (new tracker with EndpointInfo)
- First `crawl_target_async` (new version with EndpointInfo production)

**Validation:** After deletion, the module should have exactly one definition of each function. The pipeline will now receive populated `endpoint_info` lists.

### Fix #2 — Remove dead code in executor

**File:** `scanner/template_engine/executor.py`
**Action:** Delete the unreachable code block after the first `return matches` in `run_templates_async()` (approximately lines 193–208)

### Fix #3 (OPTIONAL) — Remove testphp.vulnweb.com force-inject

**File:** `scanner/scan_manager/pipeline.py`
**Action:** After Fix #1 is verified with live scanning, remove the hardcoded testphp.vulnweb.com block (~lines 88–129)
**Note:** Keep this until the fixed crawler proves it discovers those endpoints naturally.

---

## 9. Minimal Fix Plan

```
Priority  Action                                  Risk    Effort
────────────────────────────────────────────────────────────────
1 (P0)    Delete old crawler code (Fix #1)         LOW     5 min
2 (P1)    Delete executor dead code (Fix #2)       NONE    1 min
3 (P2)    Test scan against testphp.vulnweb.com    —       5 min
4 (P2)    Verify endpoint_info is populated        —       2 min
5 (P3)    Remove force-inject after validation     LOW     2 min
```

**Risk assessment:**
- Fix #1 has LOW risk — the new code was already written and tested before the old code was left in. The module will simply use the implementation that was intended.
- Fix #2 has ZERO risk — dead code removal.
- Fix #3 should wait for validation that the crawler now discovers testphp.vulnweb.com endpoints on its own.

---

## 10. Debug Strategy

### Pre-fix verification

1. **Confirm the bug exists** — add temporary logging at the start of `pipeline.py`'s crawling stage:
   ```python
   logger.info("endpoint_info count: %d", len(all_endpoint_info))
   logger.info("endpoint_info sample: %s", all_endpoint_info[:3])
   ```
   Run a scan — if `endpoint_info count: 0`, the bug is confirmed.

2. **Verify which `crawl_target_async` is active:**
   ```python
   python -c "from scanner.crawler.crawler import crawl_target_async; import inspect; print(inspect.getsourcefile(crawl_target_async)); print(inspect.getsource(crawl_target_async)[:200])"
   ```
   If the source shows `_register_url`, the old version is active.

### Post-fix verification

3. **Run scan and check endpoint_info:**
   ```bash
   curl -X POST http://localhost:8000/scans -H "Content-Type: application/json" \
     -d '{"target": "http://testphp.vulnweb.com", "mode": "standard"}'
   ```
   Then monitor Celery logs for `endpoint_info count` > 0.

4. **Check findings quality:**
   - Before fix: findings mostly use generic params (`id`, `q`)
   - After fix: findings should reference actual params (`searchFor`, `cat`, `artist`, `pic`)

5. **Verify template engine receives params:**
   Add logging in `executor.py` `_execute_template_request()`:
   ```python
   logger.debug("template=%s endpoint=%s known_params=%s", template.id, endpoint, known_params)
   ```

### Key log locations to monitor
- `scanner/scan_manager/pipeline.py` — stage transitions and progress
- `scanner/crawler/crawler.py` — crawled URLs and endpoint count
- `scanner/template_engine/executor.py` — template matches
- `scanner/payload_engine/tasks.py` — injection counts
- `scanner/detection_engine/tasks.py` — finding counts

---

## 11. Test Plan

### Unit Tests

| Test | File | What to Verify |
|------|------|----------------|
| Crawler returns EndpointInfo | `scanner/crawler/crawler.py` | `CrawlOutput.endpoint_info` is non-empty for a target with forms/params |
| `_collect_query_params` returns list | `scanner/crawler/crawler.py` | Return type is `list[str]` |
| Template executor no dead code | `scanner/template_engine/executor.py` | Only one `return matches` in `run_templates_async` |
| Request builder uses known_params | `scanner/payload_engine/request_builder.py` | When `known_params` provided, those params are used (not generic fallback) |

### Integration Tests

| Test | What to Verify |
|------|----------------|
| Pipeline with testphp.vulnweb.com | endpoint_info populated → template/payload stages receive params → findings reference real params |
| Pipeline with example.com (non-vuln) | No false positives, all stages complete, status → completed |
| Scan mode "quick" | Only crawl + template_scan + detect stages run (no payload injection) |
| Scan mode "full" | All stages including payload mutation and headers |

### Regression Tests

| Test | What to Verify |
|------|----------------|
| Form injection still works | Request builder handles `FormModel` inputs correctly |
| GraphQL introspection | Crawler discovers `/graphql` endpoints |
| JS endpoint extraction | `js_parser.py` finds fetch/axios/XHR URLs |
| Detection false-positive rate | AI analyzer filters weak evidence |

### Smoke Test (Manual)

```bash
# 1. Start system
docker compose up -d

# 2. Launch scan
SCAN_ID=$(curl -s -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "http://testphp.vulnweb.com", "mode": "standard"}' | jq -r .scan_id)

# 3. Monitor progress
watch -n 2 "curl -s http://localhost:8000/scans/$SCAN_ID | jq '{status, stage, progress}'"

# 4. Check findings when done
curl -s http://localhost:8000/scans/$SCAN_ID | jq '.findings | length'
curl -s http://localhost:8000/scans/$SCAN_ID | jq '.findings[] | {url, vuln_type, parameter, severity}'

# 5. Verify endpoint_info was used (check Celery worker logs)
docker compose logs worker | grep "endpoint_info"
```

---

## Appendix A: Template List (10 YAML Templates)

| Template ID | Vuln Type | Method | Injection Point |
|-------------|-----------|--------|-----------------|
| sqli-error | SQL Injection | GET | query params |
| sqli-time | SQL Injection (blind) | GET | query params |
| sqli-union | SQL Injection (UNION) | GET | query params |
| xss-reflected | XSS (reflected) | GET | query params |
| xss-stored | XSS (stored) | POST | body |
| ssrf | SSRF | GET | query params |
| lfi | Local File Inclusion | GET | query params |
| cmdi | Command Injection | GET | query params |
| info-disclosure | Info Disclosure | GET | path |
| open-redirect | Open Redirect | GET | query params |

## Appendix B: Payload Files

| File | Vuln Type | Used By |
|------|-----------|---------|
| `payloads/sqli.txt` | SQL Injection | payload_engine |
| `payloads/xss.txt` | Cross-Site Scripting | payload_engine |
| `payloads/ssrf.txt` | Server-Side Request Forgery | payload_engine |
| `payloads/cmdi.txt` | Command Injection | payload_engine |
| `payloads/lfi.txt` | Local File Inclusion | payload_engine |

## Appendix C: Redis Key Schema

| Key Pattern | Type | TTL | Content |
|-------------|------|-----|---------|
| `scan:{id}` | Hash | 7 days | ScanJob fields (target, mode, status, stage, progress, etc.) |
| `scan:{id}:findings` | String | 7 days | JSON array of finding dicts |
| `scan:{id}:discovery` | String | 7 days | JSON dict of asset discovery output |
| `scans:index` | Set | None | Set of all scan IDs |
