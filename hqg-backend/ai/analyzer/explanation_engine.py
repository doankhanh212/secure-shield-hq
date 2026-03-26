"""
Deterministic explanation, impact, and fix-recommendation generator.
All text is in Vietnamese. Zero external dependencies.
"""
from __future__ import annotations

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Explanation templates (3-4 câu tiếng Việt)
# Variables: {endpoint}, {parameter}, {payload}, {evidence_snippet}, {detection_method}
# ---------------------------------------------------------------------------

EXPLANATION_TEMPLATES: dict[str, str] = {
    "sqli": (
        "Phát hiện lỗ hổng SQL Injection tại endpoint {endpoint}. "
        "Khi gửi payload `{payload}` vào tham số '{parameter}', ứng dụng trả về thông báo lỗi SQL rõ ràng, "
        "cho thấy dữ liệu đầu vào được nhúng trực tiếp vào câu truy vấn mà không qua xử lý. "
        "Bằng chứng thu được: {evidence_snippet}."
    ),
    "time_based_sqli": (
        "Phát hiện lỗ hổng SQL Injection dạng Time-Based tại endpoint {endpoint}. "
        "Khi inject payload `{payload}` vào tham số '{parameter}', "
        "thời gian phản hồi của server tăng bất thường so với baseline, "
        "cho thấy payload được thực thi trong câu truy vấn SQL ({evidence_snippet})."
    ),
    "xss": (
        "Phát hiện lỗ hổng Cross-Site Scripting (XSS) phản chiếu tại endpoint {endpoint}. "
        "Payload `{payload}` được inject vào tham số '{parameter}' và xuất hiện nguyên vẹn trong HTML response, "
        "cho phép attacker thực thi mã JavaScript tùy ý trong trình duyệt của nạn nhân. "
        "Phương pháp phát hiện: {detection_method}."
    ),
    "xss_stored": (
        "Phát hiện lỗ hổng Stored XSS tại endpoint {endpoint}. "
        "Payload `{payload}` được lưu vào cơ sở dữ liệu và phản chiếu lại trong response, "
        "cho phép thực thi script độc hại với mọi người dùng truy cập trang. "
        "Đây là dạng XSS nguy hiểm nhất vì không cần user click link đặc biệt."
    ),
    "cmdi": (
        "Phát hiện lỗ hổng Command Injection tại endpoint {endpoint}. "
        "Khi gửi payload `{payload}` vào tham số '{parameter}', "
        "ứng dụng thực thi lệnh hệ điều hành và trả về kết quả trong response. "
        "Bằng chứng: {evidence_snippet}."
    ),
    "time_based_cmdi": (
        "Phát hiện lỗ hổng Command Injection dạng Time-Based tại endpoint {endpoint}. "
        "Payload `{payload}` inject vào tham số '{parameter}' gây delay bất thường trong response "
        "({evidence_snippet}), "
        "cho thấy lệnh hệ thống được thực thi với tham số sleep/timeout."
    ),
    "ssrf": (
        "Phát hiện lỗ hổng Server-Side Request Forgery (SSRF) tại endpoint {endpoint}. "
        "Payload `{payload}` khiến server thực hiện request đến địa chỉ nội bộ hoặc dịch vụ metadata cloud. "
        "Bằng chứng trong response: {evidence_snippet}. "
        "Attacker có thể dùng vector này để truy cập mạng nội bộ và cloud metadata service."
    ),
    "lfi": (
        "Phát hiện lỗ hổng Local File Inclusion (LFI) tại endpoint {endpoint}. "
        "Payload `{payload}` inject vào tham số '{parameter}' khiến ứng dụng đọc và trả về "
        "nội dung file hệ thống nhạy cảm. "
        "Bằng chứng: {evidence_snippet}."
    ),
    "path_traversal": (
        "Phát hiện lỗ hổng Path Traversal tại endpoint {endpoint}. "
        "Chuỗi `{payload}` trong tham số '{parameter}' cho phép duyệt ra ngoài thư mục được phép, "
        "dẫn đến việc đọc các file nhạy cảm trên server. "
        "Bằng chứng: {evidence_snippet}."
    ),
    "info_disclosure": (
        "Phát hiện lỗ hổng lộ thông tin nhạy cảm tại endpoint {endpoint}. "
        "Response của server chứa thông tin kỹ thuật nội bộ không nên hiển thị công khai. "
        "Bằng chứng: {evidence_snippet}. "
        "Thông tin này có thể giúp attacker lập kế hoạch tấn công chính xác hơn."
    ),
    "open_redirect": (
        "Phát hiện lỗ hổng Open Redirect tại endpoint {endpoint}. "
        "Tham số '{parameter}' nhận giá trị `{payload}` và redirect người dùng "
        "đến URL tùy ý mà không có kiểm tra whitelist. "
        "Attacker có thể dùng để thực hiện phishing hoặc bypass security filter."
    ),
    "cors_misconfiguration": (
        "Phát hiện cấu hình CORS không an toàn tại endpoint {endpoint}. "
        "Server phản hồi với header Access-Control-Allow-Origin chấp nhận origin không tin cậy, "
        "cho phép các trang web độc hại đọc response từ endpoint này. "
        "Bằng chứng: {evidence_snippet}."
    ),
    "xxe": (
        "Phát hiện lỗ hổng XML External Entity (XXE) tại endpoint {endpoint}. "
        "Payload XML chứa entity tham chiếu đến tài nguyên bên ngoài được xử lý bởi XML parser. "
        "Lỗ hổng này có thể dẫn đến đọc file hệ thống, SSRF hoặc DoS. "
        "Bằng chứng: {evidence_snippet}."
    ),
    "crlf_injection": (
        "Phát hiện lỗ hổng CRLF Injection tại endpoint {endpoint}. "
        "Ký tự carriage return/line feed trong tham số '{parameter}' không được lọc, "
        "cho phép inject HTTP response headers tùy ý. "
        "Attacker có thể dùng để thực hiện HTTP Response Splitting hoặc cache poisoning."
    ),
    "_default": (
        "Phát hiện dấu hiệu bất thường tại endpoint {endpoint} thông qua phương pháp {detection_method}. "
        "Payload `{payload}` gửi vào tham số '{parameter}' tạo ra response khác biệt so với baseline. "
        "Cần kiểm tra thủ công để xác nhận lỗ hổng này."
    ),
}

# ---------------------------------------------------------------------------
# Impact templates (2 câu business/technical impact)
# ---------------------------------------------------------------------------

IMPACT_TEMPLATES: dict[str, str] = {
    "sqli": (
        "Kẻ tấn công có thể đọc, sửa hoặc xóa toàn bộ dữ liệu trong cơ sở dữ liệu, "
        "bao gồm thông tin tài khoản người dùng, dữ liệu kinh doanh và dữ liệu khách hàng. "
        "Trong trường hợp nghiêm trọng, attacker có thể thực thi lệnh hệ thống thông qua stored procedure."
    ),
    "time_based_sqli": (
        "Attacker có thể khai thác lỗ hổng này để trích xuất dữ liệu từng bit một (blind extraction), "
        "mặc dù chậm hơn error-based SQLi nhưng vẫn đủ để đánh cắp thông tin nhạy cảm hoàn toàn."
    ),
    "xss": (
        "Kẻ tấn công có thể đánh cắp session cookie, thực thi hành động thay mặt người dùng "
        "và redirect nạn nhân đến trang giả mạo. "
        "Trong môi trường doanh nghiệp, XSS có thể dẫn đến chiếm quyền tài khoản admin."
    ),
    "xss_stored": (
        "Mọi người dùng truy cập trang bị ảnh hưởng đều là nạn nhân tiềm năng, "
        "không cần tương tác thêm từ phía attacker. "
        "Đây là vector hiệu quả nhất để phát tán malware hoặc đánh cắp thông tin xác thực hàng loạt."
    ),
    "cmdi": (
        "Kẻ tấn công có thể thực thi lệnh tùy ý trên server với quyền của web application, "
        "dẫn đến chiếm toàn bộ hệ thống, cài backdoor và lateral movement trong mạng nội bộ. "
        "Đây là lỗ hổng nghiêm trọng nhất trong OWASP Top 10."
    ),
    "time_based_cmdi": (
        "Mặc dù không thấy output trực tiếp, attacker vẫn có thể xác nhận khả năng thực thi lệnh "
        "và tiếp tục khai thác để exfiltrate dữ liệu thông qua DNS hoặc HTTP callback."
    ),
    "ssrf": (
        "Kẻ tấn công có thể sử dụng server làm proxy để truy cập mạng nội bộ, "
        "đọc cloud metadata (IAM credentials, instance info) và tấn công các service không expose ra internet. "
        "Trong môi trường cloud, SSRF thường dẫn đến leo thang đặc quyền hoàn toàn."
    ),
    "lfi": (
        "Attacker có thể đọc các file hệ thống nhạy cảm như /etc/passwd, "
        "file cấu hình chứa mật khẩu database, private key SSH và source code ứng dụng. "
        "Trong một số cấu hình, LFI có thể leo thang thành Remote Code Execution."
    ),
    "path_traversal": (
        "Kẻ tấn công có thể duyệt ra ngoài web root và đọc file tùy ý trên filesystem, "
        "bao gồm file cấu hình, log và các secret quan trọng của ứng dụng."
    ),
    "info_disclosure": (
        "Thông tin lộ ra giúp attacker thu thập intelligence về hệ thống: "
        "phiên bản phần mềm, cấu trúc code, cấu hình server và các điểm yếu tiềm ẩn khác. "
        "Đây thường là bước đầu trong một cuộc tấn công lớn hơn."
    ),
    "open_redirect": (
        "Lỗ hổng này thường được dùng trong các chiến dịch phishing, "
        "lợi dụng domain uy tín để redirect người dùng đến trang lừa đảo. "
        "OAuth và SSO flow có thể bị tấn công để đánh cắp token xác thực."
    ),
    "cors_misconfiguration": (
        "Trang web độc hại có thể thực hiện authenticated request đến API "
        "và đọc dữ liệu nhạy cảm của người dùng đã đăng nhập. "
        "Nếu kết hợp với XSS, attacker có thể bypass SameSite cookie protection."
    ),
    "xxe": (
        "Kẻ tấn công có thể đọc file hệ thống, thực hiện SSRF và trong một số parser, "
        "gây DoS thông qua Billion Laughs attack. "
        "XXE trong microservice thường bị bỏ qua nhưng rất nguy hiểm."
    ),
    "crlf_injection": (
        "Attacker có thể inject header tùy ý vào HTTP response, "
        "dẫn đến cache poisoning, XSS thông qua response splitting, "
        "và bypass security control dựa trên header."
    ),
    "_default": (
        "Lỗ hổng này có thể ảnh hưởng đến tính bảo mật, toàn vẹn hoặc khả dụng của hệ thống. "
        "Cần đánh giá thêm để xác định mức độ rủi ro cụ thể."
    ),
}

# ---------------------------------------------------------------------------
# Fix recommendation templates (list[str], mỗi item 1 khuyến nghị cụ thể)
# Variables: {parameter}
# ---------------------------------------------------------------------------

FIX_TEMPLATES: dict[str, list[str]] = {
    "sqli": [
        "Sử dụng Prepared Statements (Parameterized Queries) cho mọi câu truy vấn SQL — "
        "không bao giờ nối chuỗi trực tiếp input người dùng vào SQL.",
        "Áp dụng ORM (SQLAlchemy, Hibernate) thay vì raw SQL để giảm surface attack.",
        "Validate và whitelist kiểu dữ liệu cho tham số '{parameter}': "
        "nếu là số nguyên thì parse int và reject nếu không hợp lệ.",
    ],
    "time_based_sqli": [
        "Sử dụng Prepared Statements — đây là fix dứt điểm duy nhất cho time-based SQLi.",
        "Thiết lập statement timeout ở cấp database để giới hạn thời gian thực thi query.",
        "Monitor query execution time và alert khi vượt ngưỡng bất thường (>2 giây).",
    ],
    "xss": [
        "Escape HTML entities cho mọi output động: dùng html.escape() (Python), "
        "htmlspecialchars() (PHP), hoặc thư viện tương đương theo ngôn ngữ backend.",
        "Thiết lập Content Security Policy (CSP) header nghiêm ngặt: "
        "`Content-Security-Policy: default-src 'self'; script-src 'self'`.",
        "Validate và sanitize input tham số '{parameter}' ở cả client và server side, "
        "từ chối các ký tự `<`, `>`, `\"`, `'` nếu không cần thiết.",
    ],
    "xss_stored": [
        "Sanitize dữ liệu trước khi lưu vào database sử dụng thư viện như DOMPurify (JS) "
        "hoặc bleach (Python).",
        "Khi render dữ liệu từ DB ra HTML, luôn escape bằng template engine "
        "(Jinja2 auto-escape, React JSX tự escape).",
        "Thiết lập CSP header với nonce-based script để ngăn inline script thực thi.",
    ],
    "cmdi": [
        "Không bao giờ truyền input người dùng trực tiếp vào system command. "
        "Nếu cần gọi OS command, dùng whitelist các giá trị cho phép.",
        "Sử dụng thư viện native thay vì shell command: "
        "ví dụ dùng Python's `subprocess` với `shell=False` và argument list.",
        "Chạy web application với user có quyền tối thiểu (principle of least privilege), "
        "không chạy với quyền root/admin.",
    ],
    "time_based_cmdi": [
        "Áp dụng nguyên tắc tương tự Command Injection: loại bỏ hoàn toàn shell command từ input.",
        "Thiết lập timeout cho mọi external process call để phát hiện sleep-based attacks.",
        "Dùng allowlist nghiêm ngặt cho tham số '{parameter}' — chỉ cho phép ký tự alphanumeric.",
    ],
    "ssrf": [
        "Validate URL đầu vào chống SSRF: block các IP private (10.0.0.0/8, 172.16.0.0/12, "
        "192.168.0.0/16), loopback (127.0.0.0/8) và metadata IP (169.254.169.254).",
        "Sử dụng allowlist domain thay vì denylist — chỉ cho phép fetch từ domain đã xác định.",
        "Tắt cloud metadata endpoint hoặc yêu cầu IMDSv2 (với AWS) để giảm rủi ro khi bị SSRF.",
    ],
    "lfi": [
        "Không dùng input người dùng để xây dựng đường dẫn file. "
        "Dùng mapping ID → path được định nghĩa trước trong code.",
        "Validate đường dẫn sau khi resolve: đảm bảo path nằm trong web root "
        "bằng `os.path.realpath()` và kiểm tra prefix.",
        "Tắt `allow_url_include` và `allow_url_fopen` trong PHP nếu dùng PHP.",
    ],
    "path_traversal": [
        "Normalize đường dẫn và kiểm tra không vượt ra ngoài base directory "
        "trước khi mở file: sử dụng `Path.resolve()` và kiểm tra startswith base_dir.",
        "Từ chối các input chứa `../`, `..\\`, `%2e%2e`, `%252e` trong tham số '{parameter}'.",
        "Dùng chroot hoặc container để giới hạn filesystem access của web process.",
    ],
    "info_disclosure": [
        "Tắt debug mode và error reporting chi tiết trong production: "
        "không hiển thị stack trace, query SQL hay thông tin môi trường cho user.",
        "Cấu hình custom error page trả về thông báo chung (500 Internal Server Error) "
        "thay vì thông báo lỗi kỹ thuật.",
        "Review và xóa các endpoint test, phpinfo(), debug endpoint trước khi deploy production.",
    ],
    "open_redirect": [
        "Dùng whitelist URL hoặc path để kiểm tra giá trị redirect: "
        "chỉ cho phép redirect đến domain nội bộ đã định nghĩa.",
        "Nếu cần redirect đến URL bên ngoài, dùng intermediate warning page "
        "thông báo cho người dùng biết họ sắp rời trang.",
        "Validate tham số '{parameter}': từ chối URL có scheme khác http/https "
        "hoặc host khác với domain hiện tại.",
    ],
    "cors_misconfiguration": [
        "Thiết lập `Access-Control-Allow-Origin` với danh sách domain whitelist cụ thể "
        "thay vì dùng wildcard `*` hoặc reflect Origin header.",
        "Không bao giờ kết hợp `Access-Control-Allow-Origin: *` với "
        "`Access-Control-Allow-Credentials: true`.",
        "Với API private, tắt hoàn toàn CORS header nếu không cần cross-origin access.",
    ],
    "xxe": [
        "Disable external entity processing trong XML parser: "
        "với Python `defusedxml`, Java `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`.",
        "Không accept XML input từ user nếu không cần thiết — dùng JSON thay thế.",
        "Update XML library lên version mới nhất, nhiều CVE XXE nằm ở parser cũ.",
    ],
    "crlf_injection": [
        "Strip hoặc encode ký tự `\\r` (CR, 0x0D) và `\\n` (LF, 0x0A) từ mọi input "
        "được dùng trong HTTP header.",
        "Dùng framework HTTP response API thay vì set header thủ công để tránh CRLF injection.",
        "Validate tham số '{parameter}': từ chối input có chứa newline character.",
    ],
    "_default": [
        "Validate và sanitize toàn bộ input từ người dùng trước khi xử lý.",
        "Áp dụng principle of least privilege cho các component liên quan.",
        "Kiểm tra thủ công để xác nhận lỗ hổng và xác định fix phù hợp với codebase cụ thể.",
    ],
}


def generate_explanation(finding_dict: dict) -> dict[str, object]:
    """
    Generate explanation, impact, and fix_recommendation for a finding dict.

    Returns:
        {
            "explanation": str,
            "impact": str,
            "fix_recommendation": list[str],
        }
    """
    vuln_type = str(finding_dict.get("vulnerability_type", "")).strip()

    # Build format context — missing keys default to empty string
    ctx: dict[str, str] = defaultdict(str)
    ctx.update(
        {
            "endpoint": str(finding_dict.get("endpoint", "")),
            "parameter": str(finding_dict.get("parameter", "")) or "N/A",
            "payload": str(finding_dict.get("payload", "")),
            "evidence_snippet": str(finding_dict.get("evidence", ""))[:120],
            "detection_method": str(finding_dict.get("detection_method", "")),
        }
    )

    explanation_tpl = EXPLANATION_TEMPLATES.get(vuln_type, EXPLANATION_TEMPLATES["_default"])
    impact_tpl = IMPACT_TEMPLATES.get(vuln_type, IMPACT_TEMPLATES["_default"])
    fix_list = FIX_TEMPLATES.get(vuln_type, FIX_TEMPLATES["_default"])

    try:
        explanation = explanation_tpl.format_map(ctx)
    except Exception:
        logger.warning("explanation template format failed for %s", vuln_type)
        explanation = explanation_tpl

    try:
        impact = impact_tpl.format_map(ctx)
    except Exception:
        logger.warning("impact template format failed for %s", vuln_type)
        impact = impact_tpl

    fix_recommendation: list[str] = []
    for item in fix_list:
        try:
            fix_recommendation.append(item.format_map(ctx))
        except Exception:
            fix_recommendation.append(item)

    return {
        "explanation": explanation,
        "impact": impact,
        "fix_recommendation": fix_recommendation,
    }
