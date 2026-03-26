"""
HQG Security Checks — kiểm tra bảo mật nhanh không cần inject payload.

Dùng chủ yếu trong Quick mode để phát hiện misconfiguration và exposed files
mà không cần chạy full payload injection.

Public API
----------
SecurityCheckResult     dataclass cho kết quả từng check
check_security_headers  kiểm tra HTTP security headers
check_exposed_files     kiểm tra file nhạy cảm bị lộ
check_cors              kiểm tra CORS misconfiguration
run_all_checks          chạy tất cả checks
generate_quick_summary  tổng hợp kết quả thành summary dict
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class SecurityCheckResult:
    check_id: str
    check_type: str          # headers | exposed_file | cors | misc
    target: str
    detail: str
    severity: str            # Critical | High | Medium | Low | Info
    recommendation: str
    is_finding: bool = True  # False = OK/info, không phải lỗ hổng

    def to_dict(self) -> dict[str, object]:
        return {
            "check_id": self.check_id,
            "check_type": self.check_type,
            "target": self.target,
            "detail": self.detail,
            "severity": self.severity,
            "recommendation": self.recommendation,
            "is_finding": self.is_finding,
        }


# ---------------------------------------------------------------------------
# Security Headers
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS: list[tuple[str, str, str, str]] = [
    # (header_name, display_name, severity, recommendation_vi)
    (
        "content-security-policy",
        "Content-Security-Policy",
        "High",
        "Thêm header Content-Security-Policy để ngăn chặn XSS và data injection attacks.",
    ),
    (
        "strict-transport-security",
        "Strict-Transport-Security (HSTS)",
        "High",
        "Thêm HSTS header (max-age≥31536000) để buộc kết nối HTTPS.",
    ),
    (
        "x-content-type-options",
        "X-Content-Type-Options",
        "Medium",
        "Thêm 'X-Content-Type-Options: nosniff' để ngăn MIME-type sniffing.",
    ),
    (
        "x-frame-options",
        "X-Frame-Options",
        "Medium",
        "Thêm 'X-Frame-Options: DENY' hoặc 'SAMEORIGIN' để ngăn clickjacking.",
    ),
    (
        "referrer-policy",
        "Referrer-Policy",
        "Low",
        "Thêm 'Referrer-Policy: strict-origin-when-cross-origin' để kiểm soát referrer.",
    ),
    (
        "permissions-policy",
        "Permissions-Policy",
        "Low",
        "Thêm Permissions-Policy header để giới hạn quyền truy cập browser APIs.",
    ),
]


def check_security_headers(
    url: str,
    headers: dict[str, str],
) -> list[SecurityCheckResult]:
    """
    Kiểm tra HTTP response headers so với danh sách security headers bắt buộc.

    Trả về danh sách SecurityCheckResult cho các header bị thiếu.
    """
    results: list[SecurityCheckResult] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for i, (header_key, display_name, severity, rec) in enumerate(_REQUIRED_HEADERS):
        if header_key not in lower_headers:
            results.append(
                SecurityCheckResult(
                    check_id=f"hdr-{i:03d}-missing",
                    check_type="headers",
                    target=url,
                    detail=f"Header bảo mật bị thiếu: {display_name}",
                    severity=severity,
                    recommendation=rec,
                )
            )

    return results


# ---------------------------------------------------------------------------
# Exposed Files
# ---------------------------------------------------------------------------

_EXPOSED_PATHS: list[tuple[str, str, str, str]] = [
    # (path, display_name, severity, recommendation_vi)
    (".git/HEAD",         "Git repository",        "Critical", "Xóa thư mục .git khỏi webroot hoặc chặn bằng web server config."),
    (".env",              "Environment file",      "Critical", "Xóa file .env khỏi webroot; dùng environment variables hoặc secret manager."),
    (".htaccess",         "Apache .htaccess",      "Medium",   "Chặn truy cập .htaccess qua web server config."),
    ("robots.txt",        "robots.txt",            "Low",      "Rà soát robots.txt để không lộ đường dẫn nhạy cảm."),
    ("admin",             "Admin panel",           "High",     "Bảo vệ trang admin bằng xác thực 2 yếu tố và IP whitelist."),
    ("phpinfo.php",       "PHP Info page",         "High",     "Xóa phpinfo.php khỏi môi trường production."),
    ("server-status",     "Apache server-status",  "Medium",   "Chặn /server-status với 'Require local' trong Apache config."),
    ("wp-login.php",      "WordPress login",       "Medium",   "Giới hạn truy cập wp-login.php theo IP hoặc dùng bảo vệ 2FA."),
    ("config.php",        "Config file",           "High",     "Chặn truy cập trực tiếp tới config.php qua web server."),
    ("backup.sql",        "SQL backup",            "Critical", "Xóa file backup khỏi webroot và lưu trữ ở vị trí an toàn."),
    ("web.config",        "IIS web.config",        "Medium",   "Chặn truy cập web.config qua IIS request filtering."),
]


async def check_exposed_files(
    base_url: str,
    client: httpx.AsyncClient,
) -> list[SecurityCheckResult]:
    """
    Kiểm tra các file/path nhạy cảm có bị lộ không bằng cách gửi HEAD request.

    Trả về SecurityCheckResult cho các path trả về HTTP 200/301/302.
    """
    results: list[SecurityCheckResult] = []
    base = base_url.rstrip("/")

    for path, display_name, severity, rec in _EXPOSED_PATHS:
        url = f"{base}/{path}"
        try:
            resp = await client.head(url, follow_redirects=False)
            if resp.status_code in (200, 301, 302):
                results.append(
                    SecurityCheckResult(
                        check_id=f"exposed-{path.replace('/', '_').replace('.', '')}",
                        check_type="exposed_file",
                        target=url,
                        detail=f"File/path nhạy cảm có thể truy cập: {display_name} ({resp.status_code})",
                        severity=severity,
                        recommendation=rec,
                    )
                )
        except Exception as exc:
            logger.debug("check_exposed_files: %s → error: %s", url, exc)

    return results


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------


async def check_cors(
    url: str,
    client: httpx.AsyncClient,
) -> list[SecurityCheckResult]:
    """
    Kiểm tra CORS misconfiguration:
    - Wildcard Access-Control-Allow-Origin: *
    - Origin reflection (server echo lại bất kỳ Origin nào)

    Trả về SecurityCheckResult nếu phát hiện vấn đề.
    """
    results: list[SecurityCheckResult] = []

    # Test 1: Gửi request thông thường, check wildcard
    try:
        resp = await client.get(url, follow_redirects=True)
        acao = resp.headers.get("access-control-allow-origin", "")

        if acao == "*":
            results.append(
                SecurityCheckResult(
                    check_id="cors-wildcard",
                    check_type="cors",
                    target=url,
                    detail="CORS wildcard: Access-Control-Allow-Origin: * cho phép bất kỳ origin nào đọc response.",
                    severity="Medium",
                    recommendation=(
                        "Thay thế wildcard bằng danh sách origin được phép cụ thể. "
                        "Không dùng * cho endpoints yêu cầu xác thực."
                    ),
                )
            )

        # Test 2: Gửi request với Origin giả, kiểm tra reflection
        evil_origin = "https://evil.attacker.com"
        resp2 = await client.get(url, headers={"Origin": evil_origin}, follow_redirects=True)
        acao2 = resp2.headers.get("access-control-allow-origin", "")

        if acao2 == evil_origin:
            results.append(
                SecurityCheckResult(
                    check_id="cors-reflect",
                    check_type="cors",
                    target=url,
                    detail=(
                        "CORS Origin Reflection: server phản chiếu lại Origin của attacker "
                        f"({evil_origin}), cho phép cross-origin request."
                    ),
                    severity="High",
                    recommendation=(
                        "Kiểm tra và whitelist danh sách origin cho phép thay vì reflect. "
                        "Kết hợp với credentials=include thì đây là lỗ hổng nghiêm trọng."
                    ),
                )
            )

    except Exception as exc:
        logger.debug("check_cors: %s → error: %s", url, exc)

    return results


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------


async def run_all_checks(
    target_url: str,
    crawl_results: list[str] | None = None,
    client: httpx.AsyncClient | None = None,
) -> list[SecurityCheckResult]:
    """
    Chạy tất cả security checks cho *target_url*.

    Nếu *client* là None, tạo client nội bộ.
    Không raise exception — mọi lỗi đều được log và bỏ qua.
    """
    all_results: list[SecurityCheckResult] = []
    _own_client = client is None

    try:
        if _own_client:
            client = httpx.AsyncClient(
                follow_redirects=True,
                timeout=httpx.Timeout(10.0),
                verify=False,
            )

        # 1. Lấy homepage response để check headers
        try:
            resp = await client.get(target_url)
            headers_dict = dict(resp.headers)
            all_results.extend(check_security_headers(target_url, headers_dict))
        except Exception as exc:
            logger.warning("run_all_checks: header check failed for %s: %s", target_url, exc)

        # 2. Exposed files
        try:
            exposed = await check_exposed_files(target_url, client)
            all_results.extend(exposed)
        except Exception as exc:
            logger.warning("run_all_checks: exposed_files check failed: %s", exc)

        # 3. CORS
        try:
            cors = await check_cors(target_url, client)
            all_results.extend(cors)
        except Exception as exc:
            logger.warning("run_all_checks: cors check failed: %s", exc)

    finally:
        if _own_client and client is not None:
            try:
                await client.aclose()
            except Exception:
                pass

    logger.info(
        "run_all_checks: %s → %d issues found",
        target_url,
        sum(1 for r in all_results if r.is_finding),
    )
    return all_results


# ---------------------------------------------------------------------------
# Quick summary
# ---------------------------------------------------------------------------


def generate_quick_summary(
    checks: list[SecurityCheckResult],
    technologies: list[str] | None = None,
) -> dict[str, object]:
    """
    Tổng hợp kết quả security checks thành summary dict dùng cho quick mode report.

    Trả về dict với:
        status_summary  — {"critical": n, "high": n, "medium": n, "low": n}
        total_issues    — tổng số vấn đề
        recommendations — list[str] tiếng Việt, tối đa 5 mục ưu tiên cao nhất
        technologies    — danh sách công nghệ phát hiện
    """
    status_summary: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    recs: list[tuple[int, str]] = []  # (priority_weight, recommendation)

    _sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for check in checks:
        if not check.is_finding:
            continue
        sev_lower = check.severity.lower()
        if sev_lower in status_summary:
            status_summary[sev_lower] += 1
        weight = _sev_weight.get(sev_lower, 0)
        recs.append((weight, check.recommendation))

    # Sort by weight desc, dedup, take top 5
    recs.sort(key=lambda x: x[0], reverse=True)
    seen_recs: set[str] = set()
    top_recs: list[str] = []
    for _, rec in recs:
        if rec not in seen_recs:
            seen_recs.add(rec)
            top_recs.append(rec)
        if len(top_recs) >= 5:
            break

    return {
        "status_summary": status_summary,
        "total_issues": sum(status_summary.values()),
        "recommendations": top_recs,
        "technologies": technologies or [],
    }
