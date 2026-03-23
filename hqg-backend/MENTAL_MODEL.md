# MENTAL MODEL — HQG Security Scanner

> Quick-reference guide for developers. Read this first.

---

## System in One Sentence

A Celery worker runs a 7-stage sequential pipeline that crawls a target, injects payloads, detects vulnerabilities, and stores results in Redis — exposed via a FastAPI REST API.

---

## Simplified Pipeline

```
POST /scans { target, mode }
       │
       ▼
  ┌─ ASSET DISCOVERY ─── DNS, subdomains, HTTP probes, tech fingerprint
  │
  ├─ CRAWLING ─────────── BFS spider → endpoints + forms + EndpointInfo
  │
  ├─ TEMPLATE SCAN ────── 10 YAML templates × endpoints → quick matches
  │
  ├─ PAYLOAD INJECTION ── sqli/xss/ssrf/cmdi/lfi payloads × params → HTTP requests
  │
  ├─ DETECTION ────────── 3 analyzers (pattern + diff + timing) → findings
  │
  ├─ AI ANALYSIS ──────── FP filter + OWASP/CWE mapping + explanations
  │
  └─ CVE INTELLIGENCE ── NVD + CISA KEV → severity enrichment
       │
       ▼
  Redis: findings + discovery + status=completed
```

Each stage reads from the previous stage's output. All state lives in Redis with 7-day TTL.

---

## Core Rules

1. **One pipeline, one worker thread.** Each scan runs `asyncio.run(run_pipeline())` inside a single Celery task. Concurrency is per-scan via `asyncio.Semaphore`.

2. **Crawler feeds everything.** The crawler's `CrawlOutput` (endpoints, forms, endpoint_info) is consumed by both template engine and payload engine. If the crawler produces poor output, all downstream stages suffer.

3. **EndpointInfo is king.** The `EndpointInfo` objects carry parameter names per endpoint. Without them, payload injection falls back to guessing generic params (`id`, `q`, `search`...).

4. **Three detection methods, not one.** Detection uses pattern matching (regex on response body), differential analysis (compare to baseline), and timing analysis (blind injection). A finding from any method counts.

5. **Template scan ≠ Payload scan.** Templates are predefined YAML attack recipes (quick, focused). Payload injection is brute-force (all payloads × all params). Both produce findings that get merged.

6. **Redis is the only state store.** No database. No files (except reports in `/tmp`). Everything is in Redis hashes and strings.

---

## Debug Method

### "Where is my data?"

```
Scan not starting?     → Check Redis connection + Celery worker logs
No endpoints found?    → Check crawler output (endpoint count in pipeline logs)
No findings?           → Check endpoint_info (are params populated?)
Wrong params injected? → Check request_builder (known_params vs fallback)
Detection misses?      → Check response_analyzer patterns + diff thresholds
```

### "Which function actually runs?"

```python
# Python uses the LAST definition of a name in a module.
# In crawler.py, the OLD crawl_target_async is last → it's active.
# Verify: python -c "import inspect; from scanner.crawler.crawler import crawl_target_async; print(inspect.getsource(crawl_target_async)[:100])"
```

### "How do I trace a scan?"

```bash
# 1. Get scan ID from POST response
# 2. Watch progress:  curl localhost:8000/scans/{id} | jq '{status,stage,progress}'
# 3. Check worker logs: docker compose logs worker --follow
# 4. Check findings:   curl localhost:8000/scans/{id} | jq '.findings'
```

---

## Known Bugs (Current State)

| # | Bug | Severity | Impact | Fix |
|---|-----|----------|--------|-----|
| 1 | `crawler.py` has old code after new code — old version shadows new | **CRITICAL** | No EndpointInfo → blind param injection | Delete lines ~266–497 |
| 2 | `executor.py` has dead code after `return matches` | Low | None (unreachable) | Delete ~16 lines after return |
| 3 | `_collect_query_params` returns `set` in active (old) code vs `list` in new | Low | Minimal | Fixed by Bug #1 fix |

---

## Success Conditions

A scan is working correctly when:

- [ ] `endpoint_info` list is **non-empty** after crawling
- [ ] Template scan uses **actual parameter names** (not just `id`)
- [ ] Payload injection uses **known_params** from EndpointInfo
- [ ] Detection produces findings with **specific parameter names** in the output
- [ ] Total findings > 0 for a known-vulnerable target (testphp.vulnweb.com)
- [ ] Pipeline completes all stages: status=`completed`, progress=`1.0`

## Failure Conditions

Something is broken when:

- `endpoint_info` is empty after crawling → **Crawler bug #1**
- All findings show parameter=`id` or parameter=`q` → **No EndpointInfo, fallback params used**
- Template scan returns 0 matches → Check template YAML loading + endpoint list
- Pipeline stuck at a stage → Check Celery logs for exceptions
- Status=`failed` → Check `error` field in scan job

---

## Focus Priority

```
1. FIX CRAWLER     → Delete old code, let new EndpointInfo-producing code run
2. VERIFY DATA     → Run scan, check endpoint_info is populated
3. CHECK FINDINGS  → Confirm findings reference real params, not generic
4. CLEAN UP        → Remove dead code (executor), remove force-inject (pipeline)
```

**Everything else works.** The detection engine, AI analyzer, CVE intelligence, reporting, API, Redis storage — all functional. The single point of failure is the crawler producing empty `endpoint_info`.

---

## Final Goal

After fixing Bug #1 (delete old crawler code):

```
Crawler finds endpoints WITH parameters
  → Template engine injects into REAL params
  → Payload engine injects into REAL params  
  → Detection engine finds MORE TRUE POSITIVES
  → AI analyzer produces ACCURATE classifications
  → Developer sees ACTIONABLE vulnerability reports
```

The system was designed correctly. The new crawler code exists and works. It's just not the code that Python executes.
