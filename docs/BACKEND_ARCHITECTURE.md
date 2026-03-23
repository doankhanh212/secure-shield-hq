# HQG Web Security Platform — Backend Architecture

> **Version:** 1.0  
> **Author:** Security Architecture Team  
> **Stack:** Python · FastAPI · Celery · Redis · PostgreSQL · Elasticsearch

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Module Responsibilities](#2-module-responsibilities)
3. [Data Flow](#3-data-flow)
4. [Service Boundaries](#4-service-boundaries)
5. [Database Schema (Core Tables)](#5-database-schema-core-tables)
6. [Distributed Worker Architecture](#6-distributed-worker-architecture)
7. [Recommended Folder Structure](#7-recommended-folder-structure)
8. [API Surface](#8-api-surface)
9. [Security Considerations](#9-security-considerations)
10. [Deployment Topology](#10-deployment-topology)

---

## 1. Architecture Overview

The HQG platform follows a **task-pipeline architecture** where a scan request flows through discrete processing stages, each executed as independent Celery tasks on distributed workers. The system is decomposed into **four deployment services** communicating through Redis task queues, with PostgreSQL as the system of record and Elasticsearch for full-text vulnerability search.

```
┌──────────────────────────────────────────────────────────────────┐
│                       EXTERNAL LAYER                             │
│   React Dashboard  ·  CLI / SDK  ·  Webhook Consumers           │
└──────────────────────┬───────────────────────────────────────────┘
                       │ HTTPS / WSS
┌──────────────────────▼───────────────────────────────────────────┐
│                    API GATEWAY (FastAPI)                          │
│   Authentication · Authorization · Rate Limiting · Routing       │
└──────┬──────────┬──────────┬──────────┬─────────────────────────┘
       │          │          │          │
┌──────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼─────┐
│   Scan   │ │ Asset  │ │Scheduler│ │Reporting│
│ Manager  │ │Discovery│ │ Engine │ │ Engine  │
└──────┬───┘ └───┬────┘ └───┬────┘ └────┬────┘
       │         │          │            │
┌──────▼─────────▼──────────▼────────────▼────────────────────────┐
│                     REDIS (Celery Broker)                         │
│   Task Queues · Result Backend · Distributed Locks · Cache       │
└──────┬──────────┬──────────┬──────────┬─────────────────────────┘
       │          │          │          │
┌──────▼───┐ ┌───▼────┐ ┌───▼────┐ ┌───▼─────────┐
│  Web     │ │Payload │ │Template│ │ Vulnerability│
│ Crawler  │ │Injection│ │ Scan  │ │  Detection   │
└──────────┘ └────────┘ └────────┘ └──────┬───────┘
                                          │
                              ┌────────────▼──────────────┐
                              │   AI Vulnerability        │
                              │   Analyzer (LLM)          │
                              └────────────┬──────────────┘
                                           │
                              ┌─────────────▼─────────────┐
                              │   Risk Scoring Engine      │
                              └────────────────────────────┘
```

### Design Principles

| Principle | Implementation |
|---|---|
| **Separation of Concerns** | Each engine is an independent Python module with its own Celery task definitions |
| **Horizontal Scalability** | Scanning workers are stateless; scale by adding Celery worker instances |
| **Pipeline Composability** | Scan stages are chained via Celery workflows (`chain`, `chord`, `group`) |
| **Fault Tolerance** | Celery retry policies, Redis-based distributed locks, dead-letter queues |
| **Observability** | Structured logging (structlog), OpenTelemetry traces, Prometheus metrics |

---

## 2. Module Responsibilities

### 2.1 API Gateway

| Attribute | Detail |
|---|---|
| **Framework** | FastAPI with Uvicorn (ASGI) |
| **Port** | `8000` |
| **Auth** | JWT (access + refresh tokens), API key for service-to-service |
| **Rate Limiting** | Token bucket via Redis (`slowapi`) |

**Responsibilities:**
- Request authentication & authorization (RBAC: `admin`, `analyst`, `viewer`)
- Input validation with Pydantic v2 models
- API versioning (`/api/v1/...`)
- WebSocket endpoint for real-time scan progress streaming
- Request/response logging and correlation ID propagation
- OpenAPI schema generation

### 2.2 Scan Manager

**Responsibilities:**
- Orchestrates the full scan lifecycle: `QUEUED → RUNNING → COMPLETED | FAILED | CANCELLED`
- Creates scan records in PostgreSQL
- Composes Celery workflows (DAGs) based on scan configuration
- Manages scan concurrency limits per tenant
- Handles scan pause, resume, and cancellation via Celery `revoke()`
- Emits scan state-change events to the WebSocket channel

**Scan Configuration Model:**
```python
class ScanConfig:
    target: str                    # Root URL or domain
    scan_type: ScanType            # FULL | QUICK | PASSIVE | CUSTOM
    modules: list[str]             # Which engines to enable
    max_depth: int                 # Crawl depth
    max_concurrent_requests: int   # Throttle
    authentication: AuthConfig | None
    schedule: CronExpression | None
```

### 2.3 Asset Discovery Engine

**Celery Queue:** `queue_discovery`

**Responsibilities:**
- DNS enumeration (A, AAAA, CNAME, MX, TXT, NS records)
- Subdomain discovery (wordlist brute-force, certificate transparency logs, passive DNS)
- Port scanning (top 1000 TCP ports via async socket or integration with Masscan/Nmap)
- Technology fingerprinting (HTTP headers, response patterns, Wappalyzer-style rules)
- TLS/SSL certificate analysis
- Web server identification
- Stores discovered assets in `assets` table with status `DISCOVERED`

**Output:** List of `Asset` records (subdomains, IPs, open ports, tech stack)

### 2.4 Web Crawler Engine

**Celery Queue:** `queue_crawler`

**Responsibilities:**
- Headless browser crawling (Playwright) for JavaScript-rendered pages
- Traditional HTTP crawling (httpx/aiohttp) for static pages
- URL extraction, normalization, and deduplication
- Form detection and parameter extraction
- API endpoint discovery (from JavaScript source, sitemap.xml, robots.txt)
- Respects `robots.txt` configurable override
- Depth and breadth limits per scan configuration
- Session/cookie management for authenticated crawling

**Output:** `CrawlResult` → URLs, endpoints, parameters, forms, API routes

### 2.5 Payload Injection Engine

**Celery Queue:** `queue_attack`

**Responsibilities:**
- Generates and injects payloads for OWASP Top 10 vulnerability classes:
  - **A03:2021 Injection** — SQL injection (error-based, blind, time-based), NoSQL injection, LDAP injection, OS command injection
  - **A07:2021 XSS** — Reflected, stored, DOM-based cross-site scripting
  - **A10:2021 SSRF** — Server-side request forgery via URL parameters
  - **A01:2021 Broken Access Control** — IDOR, path traversal, privilege escalation probes
  - **A02:2021 Cryptographic Failures** — Insecure transport, weak cipher detection
- Payload encoding and evasion techniques (URL encoding, double encoding, unicode, null bytes)
- Response analysis for injection confirmation (error signatures, timing differences, out-of-band callbacks)
- Rate limiting to avoid target disruption
- **Safe mode:** Non-destructive payloads only (no write operations)

**Output:** `RawFinding` objects with evidence (request, response, payload, confidence)

### 2.6 Vulnerability Detection Engine

**Celery Queue:** `queue_detection`

**Responsibilities:**
- Correlates and deduplicates raw findings from Payload Injection + Template Scan engines
- Confirms true positives, eliminates false positives via secondary verification
- Maps findings to:
  - **CVE** identifiers (via NVD API / local mirror)
  - **CWE** weakness categories
  - **OWASP Top 10** categories (2021 edition)
- Assigns preliminary CVSS v3.1 base scores
- Stores confirmed vulnerabilities in PostgreSQL
- Indexes vulnerability documents in Elasticsearch for search
- Manages vulnerability states: `OPEN → CONFIRMED → MITIGATED → RESOLVED → FALSE_POSITIVE`

### 2.7 Template Scan Engine

**Celery Queue:** `queue_attack`

**Responsibilities:**
- Executes signature-based scans using YAML vulnerability templates (Nuclei-compatible format)
- Template categories: CVE exploits, misconfigurations, default credentials, exposed panels, info disclosure
- Template hot-reload from filesystem or Git repository
- Custom template authoring support
- Version-specific checks (e.g., Apache 2.4.49 path traversal CVE-2021-41773)
- Template result normalization into the standard `RawFinding` format

**Template Schema:**
```yaml
id: CVE-2021-44228
info:
  name: Apache Log4j RCE
  severity: critical
  cwe: CWE-502
  cvss: 10.0
  tags: [rce, log4j, jndi]
requests:
  - method: GET
    path: "/"
    headers:
      X-Api-Version: "${jndi:ldap://{{interactsh-url}}}"
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["dns", "http"]
```

### 2.8 AI Vulnerability Analyzer

**Celery Queue:** `queue_ai`

**Responsibilities:**
- Accepts confirmed vulnerabilities from the detection engine
- Uses LLM (self-hosted or API-based: OpenAI, Anthropic, local Llama) to:
  - Generate human-readable vulnerability explanations
  - Produce context-aware remediation recommendations
  - Classify business impact (data breach, service disruption, compliance violation)
  - Identify attack chains (combining multiple low-severity findings into critical paths)
  - Generate proof-of-concept descriptions for pentest reports
- Prompt engineering with structured output (JSON mode)
- Token budget management and caching to control LLM costs
- Fallback to rule-based analysis if LLM is unavailable

### 2.9 Risk Scoring Engine

**Celery Queue:** `queue_analysis`

**Responsibilities:**
- Computes composite risk scores per vulnerability, per asset, and per scan
- Score components:
  - **CVSS v3.1 base score** (from VDE)
  - **Environmental modifiers** (asset criticality, network exposure, data sensitivity)
  - **Temporal modifiers** (exploit maturity, patch availability from CVE data)
  - **Business context** (asset tags, compliance requirements)
  - **AI enrichment weight** (from AI Analyzer)
- Aggregates asset-level risk: weighted sum of vulnerability scores
- Computes organization-level security posture score (0–100)
- Trend tracking: stores historical scores for posture-over-time charts

**Scoring Formula:**
```
asset_risk = Σ (vuln_cvss × exploit_maturity × asset_criticality × exposure_factor)
posture_score = 100 - normalize(Σ asset_risk / total_assets)
```

### 2.10 Reporting Engine

**Celery Queue:** `queue_report`

**Responsibilities:**
- Generates reports in multiple formats: PDF, HTML, JSON, CSV, SARIF
- Report types:
  - Executive Summary (risk posture, trends, top findings)
  - Technical Detail (full vulnerability list with evidence)
  - Compliance (OWASP Top 10, PCI-DSS, SOC 2 mapping)
  - Delta Report (changes between two scans)
- PDF generation via WeasyPrint or ReportLab with branded templates
- Report storage in object storage (S3-compatible / local filesystem)
- Webhook notification on report completion
- Report access control (download links with expiry tokens)

### 2.11 Scheduler Engine

**Responsibilities:**
- Manages recurring scan schedules via Celery Beat with database-backed schedule store
- CRON expression support for scan frequency
- Scan window enforcement (e.g., only scan during off-peak hours)
- Auto-discovery schedules (periodic asset re-discovery)
- Schedule CRUD via API
- Timezone-aware scheduling
- Conflict detection (prevent overlapping scans on same target)

---

## 3. Data Flow

### 3.1 Primary Scan Pipeline

```
User Request
    │
    ▼
[API Gateway] ──validate──▶ [Scan Manager] ──create scan──▶ [PostgreSQL]
                                   │
                                   ▼
                            [Redis Queue]
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼               ▼
            [Asset Discovery]     ...             ...
                    │
                    ▼
            [Web Crawler]
                    │
            ┌───────┴───────┐
            ▼               ▼
    [Payload Injection] [Template Scan]     ← parallel execution
            │               │
            └───────┬───────┘
                    ▼
        [Vulnerability Detection]
                    │
                    ├──▶ [PostgreSQL]  (confirmed vulns)
                    ├──▶ [Elasticsearch]  (index for search)
                    ▼
          [AI Analyzer]
                    │
                    ▼
          [Risk Scoring]
                    │
                    ├──▶ [PostgreSQL]  (scores)
                    ▼
          [Reporting Engine]
                    │
                    ├──▶ [Object Storage]  (PDF/HTML)
                    └──▶ [Webhook]  (notification)
```

### 3.2 Celery Workflow Composition

```python
from celery import chain, chord, group

scan_workflow = chain(
    discover_assets.s(scan_id),
    crawl_targets.s(),
    chord(
        group(
            inject_payloads.s(),
            run_templates.s(),
        ),
        detect_vulnerabilities.s(),
    ),
    analyze_with_ai.s(),
    compute_risk_scores.s(),
    generate_report.s(),
)
```

### 3.3 Real-Time Progress

```
Celery Worker ──task_state_change──▶ Redis PubSub ──▶ API Gateway ──WebSocket──▶ Frontend
```

Each task publishes progress updates to a Redis PubSub channel (`scan:{scan_id}:progress`). The API Gateway subscribes and forwards to connected WebSocket clients.

---

## 4. Service Boundaries

The system deploys as **4 independently scalable services** plus shared infrastructure:

### Service Deployment Matrix

| Service | Process | Scales By | Stateless | Docker Image |
|---|---|---|---|---|
| **API + Core** | Uvicorn + Celery Beat | Replicas behind load balancer | Yes | `hqg-api` |
| **Discovery Workers** | Celery worker (`-Q queue_discovery,queue_crawler`) | Adding worker containers | Yes | `hqg-worker-discovery` |
| **Attack Workers** | Celery worker (`-Q queue_attack,queue_detection`) | Adding worker containers | Yes | `hqg-worker-attack` |
| **AI Workers** | Celery worker (`-Q queue_ai,queue_analysis,queue_report`) | Adding worker containers | Yes | `hqg-worker-ai` |

### Service Communication

| From | To | Mechanism |
|---|---|---|
| API Gateway → Workers | Redis (Celery task dispatch) | Async |
| Workers → Workers | Redis (Celery chain/chord) | Async |
| Workers → PostgreSQL | SQLAlchemy (async) | Direct |
| Workers → Elasticsearch | elasticsearch-py (async) | Direct |
| API → Frontend | WebSocket + REST | Sync/Stream |
| Scheduler → Scan Manager | Internal function call (same process) | Sync |

### Queue Isolation

```
Redis
├── queue_discovery     → Discovery workers only
├── queue_crawler       → Discovery workers only
├── queue_attack        → Attack workers only
├── queue_detection     → Attack workers only
├── queue_ai            → AI workers only
├── queue_analysis      → AI workers only
├── queue_report        → AI workers only
└── celery              → Default (heartbeat, control)
```

Isolating queues ensures that long-running AI tasks don't block time-sensitive crawling operations, and heavy payload injection doesn't starve vulnerability detection.

---

## 5. Database Schema (Core Tables)

```sql
-- Organizations / Tenants
CREATE TABLE organizations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    plan            VARCHAR(50) DEFAULT 'free',
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Users
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    email           VARCHAR(255) UNIQUE NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,
    role            VARCHAR(50) NOT NULL DEFAULT 'analyst',  -- admin, analyst, viewer
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Discovered Assets
CREATE TABLE assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    hostname        VARCHAR(512),
    ip_address      INET,
    port            INTEGER,
    protocol        VARCHAR(10),
    tech_stack      JSONB DEFAULT '[]',
    status          VARCHAR(50) DEFAULT 'discovered',  -- discovered, active, inactive
    risk_score      FLOAT DEFAULT 0.0,
    first_seen      TIMESTAMPTZ DEFAULT now(),
    last_seen       TIMESTAMPTZ DEFAULT now()
);

-- Scans
CREATE TABLE scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    created_by      UUID REFERENCES users(id),
    target          VARCHAR(2048) NOT NULL,
    scan_type       VARCHAR(50) NOT NULL,  -- full, quick, passive, custom
    config          JSONB NOT NULL DEFAULT '{}',
    status          VARCHAR(50) DEFAULT 'queued',  -- queued, running, completed, failed, cancelled
    progress        FLOAT DEFAULT 0.0,
    celery_task_id  VARCHAR(255),
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Crawled URLs
CREATE TABLE crawled_urls (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id),
    asset_id        UUID REFERENCES assets(id),
    url             TEXT NOT NULL,
    method          VARCHAR(10) DEFAULT 'GET',
    parameters      JSONB DEFAULT '{}',
    status_code     INTEGER,
    content_type    VARCHAR(255),
    depth           INTEGER DEFAULT 0,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Vulnerabilities
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id),
    asset_id        UUID REFERENCES assets(id),
    url             TEXT,
    parameter       VARCHAR(512),
    vuln_type       VARCHAR(255) NOT NULL,   -- sqli, xss, ssrf, etc.
    severity        VARCHAR(20) NOT NULL,     -- critical, high, medium, low, info
    cvss_score      FLOAT,
    cve_id          VARCHAR(50),
    cwe_id          VARCHAR(50),
    owasp_category  VARCHAR(100),
    evidence        JSONB NOT NULL DEFAULT '{}',  -- request, response, payload
    ai_analysis     JSONB DEFAULT '{}',           -- explanation, remediation, impact
    status          VARCHAR(50) DEFAULT 'open',   -- open, confirmed, mitigated, resolved, false_positive
    risk_score      FLOAT DEFAULT 0.0,
    created_at      TIMESTAMPTZ DEFAULT now(),
    updated_at      TIMESTAMPTZ DEFAULT now()
);

-- Scan Templates
CREATE TABLE scan_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    category        VARCHAR(100),
    severity        VARCHAR(20),
    template_data   JSONB NOT NULL,
    version         INTEGER DEFAULT 1,
    enabled         BOOLEAN DEFAULT true,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Scheduled Scans
CREATE TABLE scheduled_scans (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    target          VARCHAR(2048) NOT NULL,
    scan_config     JSONB NOT NULL DEFAULT '{}',
    cron_expression VARCHAR(100) NOT NULL,
    timezone        VARCHAR(50) DEFAULT 'UTC',
    is_active       BOOLEAN DEFAULT true,
    last_run_at     TIMESTAMPTZ,
    next_run_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Reports
CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID REFERENCES scans(id),
    org_id          UUID REFERENCES organizations(id),
    report_type     VARCHAR(50) NOT NULL,  -- executive, technical, compliance, delta
    format          VARCHAR(20) NOT NULL,  -- pdf, html, json, csv, sarif
    file_path       VARCHAR(1024),
    file_size       BIGINT,
    created_at      TIMESTAMPTZ DEFAULT now()
);

-- Risk Score History (for trend charts)
CREATE TABLE risk_score_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID REFERENCES organizations(id),
    asset_id        UUID REFERENCES assets(id),
    scan_id         UUID REFERENCES scans(id),
    posture_score   FLOAT NOT NULL,
    asset_risk      FLOAT NOT NULL,
    recorded_at     TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX idx_assets_org ON assets(org_id);
CREATE INDEX idx_scans_org_status ON scans(org_id, status);
CREATE INDEX idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_crawled_scan ON crawled_urls(scan_id);
CREATE INDEX idx_risk_history_org ON risk_score_history(org_id, recorded_at);
```

---

## 6. Distributed Worker Architecture

### Worker Scaling Model

```
                    ┌─────────────────────────────┐
                    │        Redis Broker          │
                    │   (queues + result backend)  │
                    └──────┬──────┬──────┬─────────┘
                           │      │      │
              ┌────────────┤      │      ├────────────┐
              │            │      │      │            │
    ┌─────────▼──┐  ┌──────▼──┐  │  ┌───▼──────┐  ┌──▼─────────┐
    │ Discovery  │  │Discovery│  │  │ Attack   │  │ Attack     │
    │ Worker 1   │  │Worker 2 │  │  │ Worker 1 │  │ Worker 2   │
    │ (host-A)   │  │(host-A) │  │  │ (host-B) │  │ (host-B)   │
    └────────────┘  └─────────┘  │  └──────────┘  └────────────┘
                                 │
                        ┌────────▼────────┐
                        │  AI Worker 1    │
                        │  (GPU host-C)   │
                        └─────────────────┘
```

### Celery Worker Configuration

```python
# celery_app.py
from celery import Celery

app = Celery("hqg")

app.conf.update(
    broker_url="redis://redis:6379/0",
    result_backend="redis://redis:6379/1",
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    task_acks_late=True,              # Re-deliver if worker crashes
    worker_prefetch_multiplier=1,     # Fair scheduling
    task_reject_on_worker_lost=True,
    task_default_retry_delay=60,
    task_max_retries=3,
    worker_max_tasks_per_child=100,   # Prevent memory leaks
    task_routes={
        "engines.discovery.*": {"queue": "queue_discovery"},
        "engines.crawler.*":   {"queue": "queue_crawler"},
        "engines.injection.*": {"queue": "queue_attack"},
        "engines.templates.*": {"queue": "queue_attack"},
        "engines.detection.*": {"queue": "queue_detection"},
        "engines.ai.*":        {"queue": "queue_ai"},
        "engines.scoring.*":   {"queue": "queue_analysis"},
        "engines.reporting.*": {"queue": "queue_report"},
    },
)
```

### Worker Launch Commands

```bash
# Discovery workers (scale horizontally)
celery -A hqg.celery_app worker -Q queue_discovery,queue_crawler \
  -c 8 --hostname=discovery@%h -l info

# Attack workers (scale horizontally)
celery -A hqg.celery_app worker -Q queue_attack,queue_detection \
  -c 4 --hostname=attack@%h -l info

# AI + Report workers
celery -A hqg.celery_app worker -Q queue_ai,queue_analysis,queue_report \
  -c 2 --hostname=ai@%h -l info

# Scheduler (single instance)
celery -A hqg.celery_app beat --scheduler celery_sqlalchemy_scheduler.schedulers:DatabaseScheduler
```

---

## 7. Recommended Folder Structure

```
hqg-backend/
│
├── docker/
│   ├── Dockerfile.api
│   ├── Dockerfile.worker
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   └── nginx/
│       └── nginx.conf
│
├── alembic/                          # Database migrations
│   ├── alembic.ini
│   ├── env.py
│   └── versions/
│       └── 001_initial_schema.py
│
├── hqg/                              # Main Python package
│   ├── __init__.py
│   ├── celery_app.py                 # Celery application factory
│   ├── config.py                     # Settings via pydantic-settings
│   │
│   ├── api/                          # API Gateway
│   │   ├── __init__.py
│   │   ├── app.py                    # FastAPI app factory
│   │   ├── dependencies.py           # Dependency injection (db, auth, etc.)
│   │   ├── middleware/
│   │   │   ├── __init__.py
│   │   │   ├── auth.py               # JWT validation middleware
│   │   │   ├── rate_limit.py         # Redis-backed rate limiter
│   │   │   ├── cors.py
│   │   │   └── logging.py            # Request/response logging + correlation ID
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── scans.py              # POST/GET/DELETE /api/v1/scans
│   │   │   ├── assets.py             # CRUD /api/v1/assets
│   │   │   ├── vulnerabilities.py    # GET /api/v1/vulnerabilities
│   │   │   ├── reports.py            # GET /api/v1/reports
│   │   │   ├── schedules.py          # CRUD /api/v1/schedules
│   │   │   ├── auth.py               # POST /api/v1/auth/login, /refresh
│   │   │   ├── dashboard.py          # GET /api/v1/dashboard/stats
│   │   │   └── ws.py                 # WebSocket /api/v1/ws/scans/{id}
│   │   └── schemas/                  # Pydantic request/response models
│   │       ├── __init__.py
│   │       ├── scan.py
│   │       ├── asset.py
│   │       ├── vulnerability.py
│   │       ├── report.py
│   │       └── auth.py
│   │
│   ├── core/                         # Shared core logic
│   │   ├── __init__.py
│   │   ├── security.py               # Password hashing, JWT encode/decode
│   │   ├── permissions.py            # RBAC logic
│   │   └── exceptions.py             # Custom exception classes
│   │
│   ├── db/                           # Database layer
│   │   ├── __init__.py
│   │   ├── session.py                # Async SQLAlchemy session factory
│   │   ├── base.py                   # Declarative base
│   │   └── models/
│   │       ├── __init__.py
│   │       ├── organization.py
│   │       ├── user.py
│   │       ├── asset.py
│   │       ├── scan.py
│   │       ├── vulnerability.py
│   │       ├── crawled_url.py
│   │       ├── scan_template.py
│   │       ├── scheduled_scan.py
│   │       ├── report.py
│   │       └── risk_score_history.py
│   │
│   ├── engines/                      # Scan engine modules (Celery tasks)
│   │   ├── __init__.py
│   │   │
│   │   ├── scan_manager/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py       # Celery workflow composition
│   │   │   ├── state_machine.py      # Scan lifecycle FSM
│   │   │   └── tasks.py
│   │   │
│   │   ├── discovery/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py              # Celery tasks
│   │   │   ├── dns_enum.py           # DNS enumeration logic
│   │   │   ├── subdomain.py          # Subdomain brute-force
│   │   │   ├── port_scanner.py       # Async port scanning
│   │   │   ├── tech_fingerprint.py   # Technology detection
│   │   │   └── tls_analyzer.py       # TLS/SSL analysis
│   │   │
│   │   ├── crawler/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── browser_crawler.py    # Playwright-based headless crawl
│   │   │   ├── http_crawler.py       # httpx-based fast crawl
│   │   │   ├── url_extractor.py      # Link & endpoint extraction
│   │   │   ├── form_parser.py        # HTML form analysis
│   │   │   └── sitemap_parser.py     # sitemap.xml / robots.txt
│   │   │
│   │   ├── injection/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── base.py               # Abstract payload injector
│   │   │   ├── sqli.py               # SQL injection payloads
│   │   │   ├── xss.py                # XSS payloads
│   │   │   ├── ssrf.py               # SSRF payloads
│   │   │   ├── cmdi.py               # Command injection payloads
│   │   │   ├── path_traversal.py     # Path traversal payloads
│   │   │   ├── encoder.py            # Payload encoding/evasion
│   │   │   └── payloads/             # Payload wordlists
│   │   │       ├── sqli.txt
│   │   │       ├── xss.txt
│   │   │       ├── ssrf.txt
│   │   │       └── cmdi.txt
│   │   │
│   │   ├── templates/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── engine.py             # Template execution engine
│   │   │   ├── parser.py             # YAML template parser
│   │   │   ├── matcher.py            # Response matching logic
│   │   │   └── library/              # Built-in templates
│   │   │       ├── cves/
│   │   │       ├── misconfigs/
│   │   │       ├── exposures/
│   │   │       └── default-creds/
│   │   │
│   │   ├── detection/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── correlator.py         # Finding correlation + dedup
│   │   │   ├── verifier.py           # Secondary verification
│   │   │   ├── cve_mapper.py         # CVE lookup and mapping
│   │   │   ├── cwe_mapper.py         # CWE classification
│   │   │   └── owasp_mapper.py       # OWASP Top 10 mapping
│   │   │
│   │   ├── ai_analyzer/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── llm_client.py         # LLM provider abstraction
│   │   │   ├── prompts.py            # Prompt templates
│   │   │   ├── chain_analyzer.py     # Attack chain detection
│   │   │   └── fallback.py           # Rule-based fallback
│   │   │
│   │   ├── scoring/
│   │   │   ├── __init__.py
│   │   │   ├── tasks.py
│   │   │   ├── cvss.py               # CVSS v3.1 calculator
│   │   │   ├── risk_model.py         # Composite risk scoring
│   │   │   └── posture.py            # Organization posture calculation
│   │   │
│   │   └── reporting/
│   │       ├── __init__.py
│   │       ├── tasks.py
│   │       ├── pdf_generator.py      # WeasyPrint PDF
│   │       ├── html_generator.py     # Jinja2 HTML
│   │       ├── sarif_generator.py    # SARIF format (for IDE integration)
│   │       ├── csv_generator.py
│   │       └── templates/            # Report Jinja2 templates
│   │           ├── executive.html
│   │           ├── technical.html
│   │           └── compliance.html
│   │
│   ├── scheduler/
│   │   ├── __init__.py
│   │   ├── cron_manager.py           # CRON schedule management
│   │   └── beat_schedule.py          # Celery Beat integration
│   │
│   ├── search/                       # Elasticsearch integration
│   │   ├── __init__.py
│   │   ├── client.py                 # ES client wrapper
│   │   ├── indices.py                # Index mappings
│   │   └── queries.py                # Search query builders
│   │
│   └── integrations/                 # External integrations
│       ├── __init__.py
│       ├── nvd.py                    # NVD API client (CVE data)
│       ├── cti.py                    # Certificate Transparency
│       ├── webhook.py                # Outbound webhook dispatcher
│       └── storage.py                # S3-compatible object storage
│
├── tests/
│   ├── conftest.py                   # Shared fixtures
│   ├── factories.py                  # Test data factories
│   ├── unit/
│   │   ├── test_discovery.py
│   │   ├── test_crawler.py
│   │   ├── test_injection.py
│   │   ├── test_detection.py
│   │   ├── test_scoring.py
│   │   └── test_api/
│   │       ├── test_scans.py
│   │       ├── test_assets.py
│   │       └── test_auth.py
│   ├── integration/
│   │   ├── test_scan_pipeline.py
│   │   ├── test_celery_workflows.py
│   │   └── test_elasticsearch.py
│   └── e2e/
│       └── test_full_scan.py
│
├── scripts/
│   ├── seed_templates.py             # Load vulnerability templates
│   ├── seed_payloads.py              # Load payload wordlists
│   └── migrate.sh                    # Run Alembic migrations
│
├── .env.example
├── pyproject.toml
├── Makefile
└── README.md
```

---

## 8. API Surface

### Authentication

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/auth/register` | Register new user |
| POST | `/api/v1/auth/login` | Login → JWT tokens |
| POST | `/api/v1/auth/refresh` | Refresh access token |

### Scans

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/scans` | Create and launch scan |
| GET | `/api/v1/scans` | List scans (paginated, filtered) |
| GET | `/api/v1/scans/{id}` | Get scan details + progress |
| DELETE | `/api/v1/scans/{id}` | Cancel scan |
| POST | `/api/v1/scans/{id}/pause` | Pause running scan |
| POST | `/api/v1/scans/{id}/resume` | Resume paused scan |
| WS | `/api/v1/ws/scans/{id}` | Real-time scan progress |

### Assets

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/assets` | List assets (paginated, filtered) |
| GET | `/api/v1/assets/{id}` | Asset detail + vulns + tech stack |
| DELETE | `/api/v1/assets/{id}` | Remove asset |
| GET | `/api/v1/assets/{id}/history` | Risk score history |

### Vulnerabilities

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/vulnerabilities` | Search/filter vulns |
| GET | `/api/v1/vulnerabilities/{id}` | Vuln detail + evidence + AI analysis |
| PATCH | `/api/v1/vulnerabilities/{id}` | Update status (confirm, mitigate, false positive) |
| GET | `/api/v1/vulnerabilities/search` | Elasticsearch full-text search |

### Reports

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/reports` | Generate report for scan |
| GET | `/api/v1/reports` | List reports |
| GET | `/api/v1/reports/{id}/download` | Download report file |

### Schedules

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/v1/schedules` | Create scheduled scan |
| GET | `/api/v1/schedules` | List schedules |
| PATCH | `/api/v1/schedules/{id}` | Update schedule |
| DELETE | `/api/v1/schedules/{id}` | Delete schedule |

### Dashboard

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/dashboard/stats` | Aggregate metrics |
| GET | `/api/v1/dashboard/posture` | Posture score + trend |
| GET | `/api/v1/dashboard/top-risks` | Top risk assets |

---

## 9. Security Considerations

### Platform Self-Protection

| Concern | Mitigation |
|---|---|
| **Authentication** | bcrypt password hashing, JWT with short-lived access tokens (15min), refresh token rotation |
| **Authorization** | RBAC with `admin` / `analyst` / `viewer` roles enforced at route level |
| **API Security** | Rate limiting (Redis token bucket), request size limits, CORS allowlist |
| **Secret Management** | Environment variables via `.env`, no secrets in code or DB; support for Vault integration |
| **Data at Rest** | PostgreSQL column encryption for credentials; TLS for all inter-service communication |
| **Worker Isolation** | Scanning workers run in network-restricted containers; no outbound except target + infrastructure |
| **Input Validation** | All inputs validated via Pydantic models before reaching any engine |
| **SQL Injection (self)** | SQLAlchemy ORM with parameterized queries exclusively |
| **Scan Safety** | Safe mode default (read-only payloads); destructive payloads require explicit opt-in |
| **Report Access** | Signed, time-limited download URLs for report files |
| **Audit Log** | All state-changing operations logged with user, timestamp, and correlation ID |

### Responsible Scanning

- Targets must be verified as owned by the organization (domain verification via DNS TXT record)
- Built-in request rate limiting per target to prevent accidental DoS
- Out-of-scope URL exclusion patterns
- Scan scope boundaries enforced by crawler (stay within target domain)

---

## 10. Deployment Topology

### Docker Compose (Development / Small Self-Hosted)

```yaml
services:
  api:
    build: { dockerfile: docker/Dockerfile.api }
    ports: ["8000:8000"]
    depends_on: [postgres, redis, elasticsearch]
    environment:
      DATABASE_URL: postgresql+asyncpg://hqg:secret@postgres/hqg
      REDIS_URL: redis://redis:6379/0
      ES_URL: http://elasticsearch:9200

  worker-discovery:
    build: { dockerfile: docker/Dockerfile.worker }
    command: celery -A hqg.celery_app worker -Q queue_discovery,queue_crawler -c 8
    depends_on: [redis, postgres]

  worker-attack:
    build: { dockerfile: docker/Dockerfile.worker }
    command: celery -A hqg.celery_app worker -Q queue_attack,queue_detection -c 4
    depends_on: [redis, postgres]

  worker-ai:
    build: { dockerfile: docker/Dockerfile.worker }
    command: celery -A hqg.celery_app worker -Q queue_ai,queue_analysis,queue_report -c 2
    depends_on: [redis, postgres, elasticsearch]

  beat:
    build: { dockerfile: docker/Dockerfile.api }
    command: celery -A hqg.celery_app beat --scheduler celery_sqlalchemy_scheduler.schedulers:DatabaseScheduler
    depends_on: [redis, postgres]

  postgres:
    image: postgres:16-alpine
    volumes: [pgdata:/var/lib/postgresql/data]
    environment:
      POSTGRES_DB: hqg
      POSTGRES_USER: hqg
      POSTGRES_PASSWORD: secret

  redis:
    image: redis:7-alpine
    volumes: [redisdata:/data]

  elasticsearch:
    image: elasticsearch:8.12.0
    environment:
      discovery.type: single-node
      xpack.security.enabled: "false"
    volumes: [esdata:/usr/share/elasticsearch/data]

volumes:
  pgdata:
  redisdata:
  esdata:
```

### Production (Kubernetes)

```
┌─────────────────────────────────────────────────────┐
│                   Kubernetes Cluster                 │
│                                                     │
│  ┌──────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ Ingress  │  │ API Deploy   │  │ Beat Deploy  │  │
│  │ (NGINX)  │→ │ (3 replicas) │  │ (1 replica)  │  │
│  └──────────┘  └──────────────┘  └──────────────┘  │
│                                                     │
│  ┌──────────────┐  ┌────────────┐  ┌────────────┐  │
│  │ Discovery    │  │ Attack     │  │ AI Workers │  │
│  │ Workers HPA  │  │ Workers HPA│  │ (GPU node) │  │
│  │ (2-20 pods)  │  │ (2-10 pods)│  │ (1-4 pods) │  │
│  └──────────────┘  └────────────┘  └────────────┘  │
│                                                     │
│  ┌────────────┐  ┌───────┐  ┌────────────────┐     │
│  │ PostgreSQL │  │ Redis │  │ Elasticsearch  │     │
│  │ (Operator) │  │ (HA)  │  │ (ECK Operator) │     │
│  └────────────┘  └───────┘  └────────────────┘     │
└─────────────────────────────────────────────────────┘
```

**Horizontal Pod Autoscaler** on worker deployments scales based on Redis queue depth:

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: worker-attack
  minReplicas: 2
  maxReplicas: 20
  metrics:
    - type: External
      external:
        metric:
          name: redis_queue_length
          selector:
            matchLabels:
              queue: queue_attack
        target:
          type: AverageValue
          averageValue: "10"
```

---

## Summary

| Component | Technology | Scale Strategy |
|---|---|---|
| API Gateway | FastAPI + Uvicorn | Horizontal (load balancer) |
| Task Broker | Redis 7 | Redis Sentinel / Cluster |
| Task Workers | Celery 5.x | Horizontal (add containers) |
| Database | PostgreSQL 16 | Vertical + read replicas |
| Search | Elasticsearch 8.x | Horizontal (data nodes) |
| Object Storage | S3 / MinIO | Managed or distributed |
| Scheduler | Celery Beat | Single instance (leader election) |
| AI Backend | OpenAI API / local LLM | Horizontal (GPU nodes) |

This architecture supports scanning **thousands of targets concurrently** by simply adding worker containers. The queue-based decoupling ensures no single component is a bottleneck, and the pipeline design allows each engine to evolve independently.
