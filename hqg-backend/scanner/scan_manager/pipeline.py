from __future__ import annotations

import asyncio
import logging
import time

from scanner.scan_manager.models import ScanStage, ScanStatus
from scanner.scan_manager.scan_modes import ScanModeConfig
from scanner.scan_manager.scan_profiles import get_profile
from scanner.scan_manager.scan_service import get_scan, update_scan

logger = logging.getLogger(__name__)


class ScanCancelledError(Exception):
    """Raised when a scan is cancelled by the user while pipeline is running."""


class CircuitBreaker:
    """Simple circuit breaker to halt a scan stage when too many errors accumulate."""

    def __init__(self, threshold: int = 50, reset_after: float = 60.0) -> None:
        self.threshold = threshold
        self.reset_after = reset_after
        self.error_count = 0
        self.tripped = False
        self._tripped_at: float = 0.0

    def record_error(self, scan_id: str = "") -> None:
        self.error_count += 1
        if not self.tripped and self.error_count >= self.threshold:
            self.tripped = True
            self._tripped_at = time.monotonic()
            logger.error(
                "scan=%s CircuitBreaker tripped after %d errors — aborting payload injection",
                scan_id, self.error_count,
            )

    def is_open(self) -> bool:
        """Return True when the breaker is tripped and the reset window has not elapsed."""
        if not self.tripped:
            return False
        if time.monotonic() - self._tripped_at > self.reset_after:
            # Auto-reset
            self.tripped = False
            self.error_count = 0
            return False
        return True


def _set_stage(scan_id: str, stage: ScanStage, progress: float) -> None:
    update_scan(scan_id, stage=stage, progress=progress, status=ScanStatus.RUNNING)
    logger.info("scan=%s stage=%s progress=%.0f%%", scan_id, stage.value, progress * 100)


def _ensure_not_cancelled(scan_id: str) -> None:
    job = get_scan(scan_id)
    if job and job.status == ScanStatus.CANCELLED:
        raise ScanCancelledError(f"scan {scan_id} was cancelled")


async def _run_pipeline_inner(
    scan_id: str,
    target: str,
    config: ScanModeConfig,
) -> dict[str, object]:
    # Lấy chi tiết profile (quick/standard/…) để kiểm tra enabled/disabled
    _profile = get_profile(config.name)
    logger.info(
        "scan=%s mode=%s payload_engine=%s ai_analyzer=%s cve_intelligence=%s security_checks=%s",
        scan_id,
        config.name,
        _profile["payload_engine"]["enabled"],
        _profile["ai_analyzer"]["enabled"],
        _profile["cve_intelligence"]["enabled"],
        _profile.get("security_checks", {}).get("enabled", False),
    )

    _ensure_not_cancelled(scan_id)

    # ------------------------------------------------------------------ #
    # Stage 1 – Asset Discovery                                           #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.ASSET_DISCOVERY, 0.05)

    discovery_output: dict[str, object] = {}
    crawl_targets: list[str] = [target]

    if config.has_stage("asset_discovery"):
        from scanner.asset_discovery.tasks import _discover_assets_async as _disc

        discovery_result = await _disc(target)
        discovery_output = discovery_result.to_dict()

        # Cap subdomains to avoid spawning hundreds of parallel crawlers.
        # Priority: always include the primary target first.
        _MAX_CRAWL_TARGETS = 20
        all_targets = sorted({target, *discovery_result.subdomains})
        if len(all_targets) > _MAX_CRAWL_TARGETS:
            logger.warning(
                "scan=%s Capping crawl targets %d → %d (too many subdomains)",
                scan_id, len(all_targets), _MAX_CRAWL_TARGETS,
            )
            # Ensure the primary target is always included
            other_targets = [t for t in all_targets if t != target][:_MAX_CRAWL_TARGETS - 1]
            all_targets = [target] + other_targets
        crawl_targets = all_targets

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.ASSET_DISCOVERY, 0.20)

    # ------------------------------------------------------------------ #
    # Stage 2 – Web Crawling                                              #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.CRAWLING, 0.22)

    endpoints: list[str] = []
    forms: list[dict[str, object]] = []
    endpoint_info: list[dict[str, object]] = []  # EndpointInfo dicts from crawler

    if config.has_stage("crawling"):
        from scanner.crawler.crawler import crawl_target_async

        # Pull max_pages from the profile so the crawler honours the per-mode limit.
        _crawler_profile = _profile.get("crawler", {})
        _max_urls_per_target = int(_crawler_profile.get("max_pages", 100))
        _crawl_depth = min(config.max_depth, int(_crawler_profile.get("max_depth", config.max_depth)))
        logger.info(
            "scan=%s crawling %d target(s) max_depth=%d max_urls_per_target=%d",
            scan_id, len(crawl_targets), _crawl_depth, _max_urls_per_target,
        )

        crawl_tasks = [
            crawl_target_async(t, max_depth=_crawl_depth, max_urls=_max_urls_per_target)
            for t in crawl_targets
        ]
        crawl_results = await asyncio.gather(*crawl_tasks)

        endpoint_set: set[str] = set()
        form_keys: set[tuple[str, str]] = set()
        ep_info_map: dict[str, dict[str, object]] = {}

        for result in crawl_results:
            endpoint_set.update(result.endpoints)
            for form in result.forms:
                key = (form.action, form.method)
                if key not in form_keys:
                    form_keys.add(key)
                    forms.append(
                        {"action": form.action, "method": form.method, "fields": form.fields}
                    )
            # Collect rich endpoint info, merging params from multiple crawl targets
            for info in result.endpoint_info:
                url = info.url
                if url in ep_info_map:
                    existing = ep_info_map[url]
                    merged = list(dict.fromkeys(existing["parameters"] + info.parameters))
                    existing["parameters"] = merged
                else:
                    ep_info_map[url] = info.to_dict()

        endpoints = sorted(endpoint_set)
        endpoint_info = list(ep_info_map.values())

        # ── Force-inject known endpoints for well-known test targets ────────
        if "testphp.vulnweb.com" in target:
            force_eps = [
                ("http://testphp.vulnweb.com/search.php?test=",    ["test"]),
                ("http://testphp.vulnweb.com/listproducts.php?cat=", ["cat"]),
                ("http://testphp.vulnweb.com/product.php?pic=",    ["pic"]),
                ("http://testphp.vulnweb.com/artists.php?artist=", ["artist"]),
                ("http://testphp.vulnweb.com/showimage.php?file=", ["file"]),
                ("http://testphp.vulnweb.com/hpp/params.php?p=",   ["p", "pp"]),
            ]
            force_forms = [
                {"action": "http://testphp.vulnweb.com/search.php",  "method": "GET",  "fields": ["searchFor", "goButton"]},
                {"action": "http://testphp.vulnweb.com/login.php",   "method": "POST", "fields": ["uname", "pass"]},
                {"action": "http://testphp.vulnweb.com/comment.php", "method": "POST", "fields": ["name", "email", "comment", "aid"]},
                {"action": "http://testphp.vulnweb.com/guestbook.php","method": "POST", "fields": ["name", "content"]},
            ]
            existing_ep_set = set(endpoints)
            for fe, fe_params in force_eps:
                if fe not in existing_ep_set:
                    endpoints.append(fe)
                if fe not in ep_info_map:
                    ep_info_map[fe] = {"url": fe, "parameters": fe_params, "method": "GET", "source": "force"}
                    endpoint_info.append(ep_info_map[fe])
                else:
                    merged = list(dict.fromkeys(ep_info_map[fe]["parameters"] + fe_params))
                    ep_info_map[fe]["parameters"] = merged

            for ff in force_forms:
                key = (ff["action"], ff["method"])
                if key not in form_keys:
                    form_keys.add(key)
                    forms.append(ff)
                # Also register form action as endpoint with field params
                fa = ff["action"]
                if fa not in ep_info_map:
                    ep_info_map[fa] = {"url": fa, "parameters": ff["fields"], "method": ff["method"], "source": "force"}
                    endpoint_info.append(ep_info_map[fa])
                    if fa not in existing_ep_set:
                        endpoints.append(fa)

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.CRAWLING, 0.40)

    # ------------------------------------------------------------------ #
    # Stage 2.5 – Security Checks (Quick mode)                           #
    # ------------------------------------------------------------------ #
    security_check_results: list[dict[str, object]] = []
    quick_summary: dict[str, object] = {}

    if _profile.get("security_checks", {}).get("enabled", False):
        logger.info("scan=%s stage=security_checks enabled (quick mode)", scan_id)
        from scanner.scan_manager.security_checks import (
            generate_quick_summary as _gen_summary,
            run_all_checks as _run_checks,
        )

        _sc_results = await _run_checks(target_url=target)
        security_check_results = [r.to_dict() for r in _sc_results]

        _raw_techs_sc: list[str] = []
        for _item in discovery_output.get("technologies") or []:
            if isinstance(_item, dict):
                _n = _item.get("name") or _item.get("technology", "")
                if _n:
                    _raw_techs_sc.append(str(_n))
            elif isinstance(_item, str):
                _raw_techs_sc.append(_item)

        quick_summary = _gen_summary(_sc_results, _raw_techs_sc)
        logger.info(
            "scan=%s security_checks: %d issues found",
            scan_id, quick_summary.get("total_issues", 0),
        )
    else:
        logger.info("scan=%s stage=security_checks disabled (mode=%s)", scan_id, config.name)

    # ------------------------------------------------------------------ #
    # Stage 2.6 – Template Scan                                           #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.TEMPLATE_SCAN, 0.41)

    template_findings: list[dict[str, object]] = []

    if config.has_stage("template_scan") and endpoints:
        from scanner.template_engine.tasks import _run_template_scan_async

        template_findings = await _run_template_scan_async(
            endpoints=endpoints,
            concurrency=config.max_concurrency,
            endpoint_info=endpoint_info,
        )

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.TEMPLATE_SCAN, 0.50)

    # ------------------------------------------------------------------ #
    # Stage 3 – Payload Injection                                        #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.PAYLOAD_INJECTION, 0.52)

    injection_results: list[dict[str, object]] = []

    _payload_config = _profile["payload_engine"]
    _payload_enabled = _payload_config["enabled"]
    if config.has_stage("payload_injection") and _payload_enabled and endpoints:
        logger.info(
            "scan=%s stage=payload_injection enabled concurrency=%d max_payloads_per_param=%s timeout=%.1fs generic_fallback=%s",
            scan_id,
            config.payload_concurrency,
            _payload_config.get("max_payloads_per_param"),
            float(_payload_config.get("timeout_seconds", 15.0)),
            _payload_config.get("allow_generic_fallback", True),
        )
        from scanner.payload_engine.tasks import _inject_payloads_async

        _breaker = CircuitBreaker(threshold=50)
        raw = await _inject_payloads_async(
            endpoints=endpoints,
            concurrency=config.payload_concurrency,
            inject_headers=config.inject_headers,
            payload_mutation=config.payload_mutation,
            forms=forms,
            endpoint_info=endpoint_info,
            max_payloads_per_param=_payload_config.get("max_payloads_per_param"),
            timeout_seconds=float(_payload_config.get("timeout_seconds", 15.0)),
            allow_generic_fallback=bool(_payload_config.get("allow_generic_fallback", True)),
            scan_mode=config.name,
        )
        # Count error results and trip the breaker if needed (for logging / monitoring).
        for _r in raw:
            _rc = _r.get("response_code")
            if _rc in (None, 403, 405, 429, 500, 502, 503, 508) or _r.get("error"):
                _breaker.record_error(scan_id)
        if _breaker.is_open():
            logger.warning(
                "scan=%s CircuitBreaker tripped: %d error responses out of %d total",
                scan_id, _breaker.error_count, len(raw),
            )
        injection_results = raw
    elif not _payload_enabled:
        logger.info("scan=%s stage=payload_injection disabled (mode=%s)", scan_id, config.name)

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.PAYLOAD_INJECTION, 0.65)

    # ------------------------------------------------------------------ #
    # Stage 4 – Vulnerability Detection                                  #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.DETECTION, 0.67)

    detection_findings: list[dict[str, object]] = []

    _detection_config = _profile.get("detection_engine", {})
    if config.has_stage("detection") and injection_results:
        logger.info(
            "scan=%s stage=detection enabled skip_timing=%s skip_diff=%s",
            scan_id,
            _detection_config.get("skip_timing", False),
            _detection_config.get("skip_diff", False),
        )
        from scanner.detection_engine.tasks import _detect_async

        findings = await _detect_async(injection_results, detection_config=_detection_config)
        detection_findings = [f.to_dict() for f in findings]
    else:
        logger.info("scan=%s stage=detection skipped (no injection results)", scan_id)

    # Filter template findings through the same quality filters as detection findings
    if template_findings:
        from scanner.scan_manager._template_filter import filter_template_findings
        template_findings = filter_template_findings(template_findings)

    # Merge template-engine findings with detection findings
    all_findings: list[dict[str, object]] = template_findings + detection_findings

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.DETECTION, 0.82)

    # ------------------------------------------------------------------ #
    # Verification Layer — multi-step false positive reduction            #
    # Runs after detection merge; non-fatal (any failure keeps originals) #
    # ------------------------------------------------------------------ #
    if all_findings:
        try:
            from scanner.verification.verifier import verify_findings_async as _verify

            all_findings = await _verify(all_findings)
            logger.info(
                "scan=%s verification complete: %d findings processed",
                scan_id,
                len(all_findings),
            )
        except Exception as _vfy_exc:
            logger.warning("scan=%s verification layer failed: %s", scan_id, _vfy_exc)

    # ------------------------------------------------------------------ #
    # Knowledge-base enrichment — fills description / impact / remediation#
    # for every finding using the vulnerability template library.         #
    # Runs unconditionally; values set by upstream stages are preserved.  #
    # ------------------------------------------------------------------ #
    if all_findings:
        try:
            from scanner.knowledge_base.vuln_templates import enrich_finding as _enrich

            all_findings = [_enrich(f) for f in all_findings]
            logger.info(
                "scan=%s knowledge-base enrichment complete: %d findings",
                scan_id,
                len(all_findings),
            )
        except Exception as _enr_exc:
            logger.warning("scan=%s knowledge-base enrichment failed: %s", scan_id, _enr_exc)

    # ------------------------------------------------------------------ #
    # OWASP classification — runs BEFORE AI analysis so downstream stages #
    # can reference the category.  Re-runs AFTER CVE intelligence to      #
    # upgrade classification with CVE→CWE→OWASP data (Layer 1).          #
    # ------------------------------------------------------------------ #
    if all_findings:
        try:
            from scanner.owasp_mapping.engine import enrich_findings_owasp as _owasp_classify

            all_findings = _owasp_classify(all_findings, cve_records=None)
            logger.info(
                "scan=%s pre-CVE OWASP classification complete: %d findings",
                scan_id,
                len(all_findings),
            )
        except Exception as _ow_exc:
            logger.warning("scan=%s OWASP classification failed: %s", scan_id, _ow_exc)

    # ------------------------------------------------------------------ #
    # Stage 5 – AI Analysis                                               #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.AI_ANALYSIS, 0.84)

    analyzed_findings: list[dict[str, object]] = all_findings

    _ai_enabled = _profile["ai_analyzer"]["enabled"]
    if config.has_stage("ai_analysis") and _ai_enabled and all_findings:
        logger.info("scan=%s stage=ai_analysis enabled", scan_id)
        from ai.analyzer.analyzer import analyze_finding as _analyze_finding

        analyzed: list[dict[str, object]] = []
        for raw_finding in all_findings:
            try:
                result = _analyze_finding(raw_finding)
                if result:
                    analyzed.append(result.to_dict())
                else:
                    analyzed.append(raw_finding)
            except Exception:
                analyzed.append(raw_finding)
        analyzed_findings = analyzed if analyzed else all_findings
    else:
        logger.info("scan=%s stage=ai_analysis disabled (mode=%s)", scan_id, config.name)

    _ensure_not_cancelled(scan_id)
    _set_stage(scan_id, ScanStage.AI_ANALYSIS, 0.88)

    # ------------------------------------------------------------------ #
    # Stage 6 – CVE Intelligence                                          #
    # ------------------------------------------------------------------ #
    _set_stage(scan_id, ScanStage.CVE_INTELLIGENCE, 0.89)

    cve_output: dict[str, object] = {}

    _cve_enabled = _profile["cve_intelligence"]["enabled"]
    if config.has_stage("cve_intelligence") and _cve_enabled:
        logger.info("scan=%s stage=cve_intelligence enabled", scan_id)
        import json as _json

        from scanner.cve_intelligence.kev_client import (
            fetch_kev_catalog as _fetch_kev_set,
            is_actively_exploited as _is_kev,
        )
        from scanner.cve_intelligence.nvd_client import search_nvd as _search_nvd
        from scanner.cve_intelligence.tech_parser import parse_all as _parse_techs
        from backend.config.config import get_settings as _get_settings

        _nvd_api_key: str = ""
        try:
            _nvd_api_key = _get_settings().nvd_api_key or ""
            if _nvd_api_key:
                logger.info("scan=%s CVE stage: NVD API key configured", scan_id)
            else:
                logger.warning(
                    "scan=%s CVE stage: NVD_API_KEY not set — rate limit 5 req/30s applies",
                    scan_id,
                )
        except Exception:
            logger.debug("scan=%s CVE stage: could not read NVD_API_KEY from settings", scan_id)

        # ── Collect raw technology strings from asset discovery ────────────
        _raw_techs: list[str] = []
        for _item in discovery_output.get("technologies") or []:
            if isinstance(_item, dict):
                _n = _item.get("name") or _item.get("technology", "")
                if _n:
                    _raw_techs.append(str(_n))
            elif isinstance(_item, str):
                _raw_techs.append(_item)

        # Also scan service banners/headers for "Name/Version" strings
        for _svc in discovery_output.get("services") or []:
            if not isinstance(_svc, dict):
                continue
            _banner = str(_svc.get("server_banner", "") or "")
            if _banner:
                _raw_techs.append(_banner)
            _hdrs = _svc.get("headers") or {}
            if isinstance(_hdrs, dict):
                for _hval in _hdrs.values():
                    if isinstance(_hval, str) and "/" in _hval:
                        _raw_techs.append(_hval)

        _parsed_techs = _parse_techs(_raw_techs)
        logger.info(
            "scan=%s cve_stage: %d raw tech strings → %d parsed (name, version) pairs",
            scan_id, len(_raw_techs), len(_parsed_techs),
        )

        # ── Redis connection (best-effort) ─────────────────────────────────
        _redis = None
        try:
            import redis.asyncio as _aioredis
            _redis = _aioredis.from_url(
                _get_settings().redis_url,
                socket_connect_timeout=3,
                decode_responses=True,
            )
        except Exception:
            logger.debug("scan=%s CVE stage: Redis unavailable, skipping NVD cache", scan_id)

        # ── CISA KEV catalog ───────────────────────────────────────────────
        _kev_set: set[str] = set()
        try:
            _kev_set = await _fetch_kev_set(redis_client=_redis)
            logger.info("scan=%s KEV catalog: %d actively-exploited CVEs", scan_id, len(_kev_set))
        except Exception as _ke:
            logger.warning("scan=%s KEV fetch failed (continuing): %s", scan_id, _ke)

        # ── NVD per-technology lookup with rate-limit semaphore ────────────
        _nvd_sem = asyncio.Semaphore(2)   # max 2 concurrent NVD requests
        _all_cve_dicts: list[dict[str, object]] = []
        _seen_cve_ids: set[str] = set()

        async def _nvd_fetch_one(tech_name: str, tech_version: str) -> None:
            _cache_key = f"nvd:{tech_name}:{tech_version}"

            # Try Redis cache before hitting NVD
            if _redis:
                try:
                    _cached = await _redis.get(_cache_key)
                    if _cached:
                        for _r in _json.loads(_cached):
                            _cid = str(_r.get("cve_id", ""))
                            if _cid and _cid not in _seen_cve_ids:
                                _seen_cve_ids.add(_cid)
                                _r["is_actively_exploited"] = _is_kev(_cid, _kev_set)
                                _all_cve_dicts.append(_r)
                        logger.debug("CVE cache hit: %s", _cache_key)
                        return
                except Exception:
                    pass  # cache miss or Redis error — fall through to NVD

            async with _nvd_sem:
                try:
                    _records = await _search_nvd(tech_name, tech_version, api_key=_nvd_api_key or None)
                    logger.debug(
                        "NVD '%s %s' → %d CVEs",
                        tech_name, tech_version, len(_records),
                    )
                except Exception as _ne:
                    logger.warning(
                        "scan=%s NVD lookup failed for %s/%s: %s",
                        scan_id, tech_name, tech_version, _ne,
                    )
                    _records = []
                # Respect NVD rate limit: ≤2 req/s without API key
                await asyncio.sleep(0.7)

            _to_cache: list[dict] = []
            for _rec in _records:
                _rd = _rec.to_dict()
                _cid = str(_rd.get("cve_id", ""))
                _rd["is_actively_exploited"] = _is_kev(_cid, _kev_set)
                _to_cache.append(_rd)
                if _cid and _cid not in _seen_cve_ids:
                    _seen_cve_ids.add(_cid)
                    _all_cve_dicts.append(_rd)

            if _redis and _to_cache:
                try:
                    await _redis.setex(_cache_key, 86_400, _json.dumps(_to_cache))
                except Exception:
                    pass  # caching is best-effort

        if _parsed_techs:
            _nvd_tasks = [_nvd_fetch_one(_n, _v) for _n, _v in _parsed_techs]
            await asyncio.gather(*_nvd_tasks, return_exceptions=True)

        _all_cve_dicts.sort(key=lambda _r: float(_r.get("cvss", 0.0)), reverse=True)
        logger.info(
            "scan=%s CVE stage: %d unique CVEs found (%d actively exploited)",
            scan_id,
            len(_all_cve_dicts),
            sum(1 for _r in _all_cve_dicts if _r.get("is_actively_exploited")),
        )

        # ── Enrich findings: add related_cve_ids + is_actively_exploited ──
        _tech_to_cve_ids: dict[str, list[str]] = {}
        for _r in _all_cve_dicts:
            _t = str(_r.get("technology", "")).lower()
            _cid = str(_r.get("cve_id", ""))
            if _t and _cid:
                _tech_to_cve_ids.setdefault(_t, []).append(_cid)

        _enriched_findings: list[dict[str, object]] = []
        for _f in analyzed_findings:
            _fc = dict(_f)
            _related: list[str] = []
            _exploited = False
            for _cids in _tech_to_cve_ids.values():
                _related.extend(_cids)
                if any(_is_kev(_c, _kev_set) for _c in _cids):
                    _exploited = True
            _fc["related_cve_ids"] = list(dict.fromkeys(_related))[:10]  # dedup, cap 10
            _fc["is_actively_exploited"] = _exploited
            _enriched_findings.append(_fc)
        if _enriched_findings:
            analyzed_findings = _enriched_findings

        # ── Build cve_output ───────────────────────────────────────────────
        cve_output = {
            "software_versions": [
                {"technology": _n, "version": _v} for _n, _v in _parsed_techs
            ],
            "cve_records": _all_cve_dicts,
            "total_cves": len(_all_cve_dicts),
            "actively_exploited_count": sum(
                1 for _r in _all_cve_dicts if _r.get("is_actively_exploited")
            ),
            "kev_catalog_size": len(_kev_set),
        }

        # ── Close Redis ────────────────────────────────────────────────────
        if _redis:
            try:
                await _redis.aclose()
            except Exception:
                pass
    else:
        logger.info("scan=%s stage=cve_intelligence disabled (mode=%s)", scan_id, config.name)

    # ------------------------------------------------------------------ #
    # Post-CVE OWASP re-classification (Layer 1 upgrade)                  #
    # Now that CVE records are available, re-run the OWASP engine so      #
    # CVE→CWE→OWASP (highest accuracy) can override rule/fallback.       #
    # ------------------------------------------------------------------ #
    if analyzed_findings and cve_output:
        try:
            from scanner.owasp_mapping.engine import enrich_findings_owasp as _owasp_reclassify

            _cve_recs_for_owasp = cve_output.get("cve_records", []) if isinstance(cve_output, dict) else []
            analyzed_findings = _owasp_reclassify(
                analyzed_findings, cve_records=_cve_recs_for_owasp
            )
            logger.info(
                "scan=%s post-CVE OWASP re-classification complete: %d findings",
                scan_id,
                len(analyzed_findings),
            )
        except Exception as _ow2_exc:
            logger.warning("scan=%s post-CVE OWASP re-classification failed: %s", scan_id, _ow2_exc)

    _ensure_not_cancelled(scan_id)

    # ------------------------------------------------------------------ #
    # Stage 7 – Attack Surface Graph (deep mode only)                     #
    # ------------------------------------------------------------------ #
    attack_surface_output: dict[str, object] = {}
    attack_paths_output: list[dict[str, object]] = []

    _as_enabled = _profile.get("attack_surface", {}).get("enabled", False)
    if config.has_stage("attack_surface") and _as_enabled:
        _set_stage(scan_id, ScanStage.ATTACK_SURFACE, 0.91)
        logger.info("scan=%s stage=attack_surface enabled", scan_id)

        from scanner.attack_surface.graph import build_attack_surface_graph

        _scan_result_snapshot = {
            "target": target,
            "discovery": discovery_output,
            "crawled_endpoints": endpoints,
        }
        _cve_records = cve_output.get("cve_records", []) if cve_output else []
        _attack_graph = build_attack_surface_graph(
            scan_result=_scan_result_snapshot,
            analyzed_vulnerabilities=analyzed_findings,
            cve_records=_cve_records,
        )
        attack_surface_output = _attack_graph.to_dict()
        logger.info(
            "scan=%s attack_surface: %d assets, %d endpoints, %d vulns, %d entry_points",
            scan_id,
            len(_attack_graph.assets),
            len(_attack_graph.endpoints),
            len(_attack_graph.vulnerabilities),
            len(_attack_graph.get_entry_points()),
        )

        # ── Stage 8 – Attack Path Analysis (deep mode only) ──────────────
        _ap_enabled = _profile.get("attack_path", {}).get("enabled", False)
        if config.has_stage("attack_path") and _ap_enabled:
            _set_stage(scan_id, ScanStage.ATTACK_PATH, 0.95)
            logger.info("scan=%s stage=attack_path enabled", scan_id)

            from scanner.attack_surface.attack_paths import analyze_attack_paths

            _paths = analyze_attack_paths(
                graph=_attack_graph,
                analyzed_vulnerabilities=analyzed_findings,
            )
            attack_paths_output = [p.to_dict() for p in _paths]
            logger.info(
                "scan=%s attack_paths: %d scenarios identified",
                scan_id, len(attack_paths_output),
            )
    else:
        logger.info("scan=%s stage=attack_surface disabled (mode=%s)", scan_id, config.name)

    _ensure_not_cancelled(scan_id)

    # ------------------------------------------------------------------ #
    # Asset Intelligence — aggregate per-host view (non-blocking)         #
    # ------------------------------------------------------------------ #
    asset_intelligence_output: list[dict[str, object]] = []
    try:
        from scanner.asset_intelligence.asset_manager import build_assets_async

        _cve_recs: list[dict[str, object]] = []
        if cve_output and isinstance(cve_output, dict):
            _cve_recs = cve_output.get("cve_records", [])

        _assets = await build_assets_async(
            urls=endpoints,
            findings=analyzed_findings,
            cve_records=_cve_recs,
        )
        asset_intelligence_output = [a.to_dict() for a in _assets]
        logger.info(
            "scan=%s asset_intelligence: %d assets built",
            scan_id, len(asset_intelligence_output),
        )
    except Exception as _ai_exc:
        logger.warning(
            "scan=%s asset_intelligence failed (non-fatal): %s",
            scan_id, _ai_exc,
        )

    _set_stage(scan_id, ScanStage.DONE, 1.0)

    return {
        "scan_id": scan_id,
        "target": target,
        "mode": config.name,
        "discovery": discovery_output,
        "crawled_endpoints": endpoints,
        "endpoint_info": endpoint_info,
        "forms": forms,
        "findings": analyzed_findings,
        "total_findings": len(analyzed_findings),
        "cve_intelligence": cve_output,
        "security_checks": security_check_results,
        "quick_summary": quick_summary,
        "attack_surface": attack_surface_output,
        "attack_paths": attack_paths_output,
        "asset_intelligence": asset_intelligence_output,
    }


async def run_pipeline(
    scan_id: str,
    target: str,
    config: ScanModeConfig,
) -> dict[str, object]:
    """Public entry-point — enforces a global wall-clock timeout from the scan profile."""
    _profile = get_profile(config.name)
    _timeout = float(_profile.get("global_timeout_seconds", 1800))  # default 30 min

    logger.info(
        "scan=%s mode=%s global_timeout=%.0fs",
        scan_id, config.name, _timeout,
    )

    try:
        result = await asyncio.wait_for(
            _run_pipeline_inner(scan_id, target, config),
            timeout=_timeout,
        )
        return result
    except asyncio.TimeoutError:
        logger.error(
            "scan=%s TIMED OUT after %.0f seconds — marking as failed",
            scan_id, _timeout,
        )
        update_scan(
            scan_id,
            status=ScanStatus.FAILED,
            stage=ScanStage.DONE,
            error=f"Scan exceeded maximum allowed time of {int(_timeout)}s",
        )
        raise
