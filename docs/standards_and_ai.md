# Tiêu chuẩn bảo mật & AI trong HQG Platform

Tài liệu này giải thích **nguồn gốc dữ liệu** và **cách mapping** của từng tiêu chuẩn bảo mật trong sản phẩm, cũng như vai trò thực tế của AI.

---

## 1. OWASP Top 10 2021 — Phân loại lỗ hổng

### Lấy từ đâu?

Hardcoded trong `hqg-backend/scanner/detection_engine/models.py` dưới dạng lookup table tĩnh:

```python
OWASP_MAP: dict[str, str] = {
    "sqli":              "A03:2021 Injection",
    "xss":               "A03:2021 Injection",
    "ssrf":              "A10:2021 SSRF",
    "cmdi":              "A03:2021 Injection",
    "lfi":               "A05:2021 Security Misconfiguration",
    "path_traversal":    "A05:2021 Security Misconfiguration",
    "info_disclosure":   "A02:2021 Cryptographic Failures",
    "time_based_sqli":   "A03:2021 Injection",
    "time_based_cmdi":   "A03:2021 Injection",
}
```

### Mapping như nào?

Khi detection engine phát hiện một lỗ hổng, nó tạo ra một `VulnerabilityFinding` object. Object này có property `owasp` tự tra trong `OWASP_MAP` theo `vulnerability_type`. Kết quả được ghi vào dict `finding.to_dict()["owasp"]` rồi lưu vào Redis.

**Luồng dữ liệu:**

```
Detection Engine phát hiện "sqli"
    → VulnerabilityFinding(vulnerability_type="sqli")
    → finding.owasp = OWASP_MAP["sqli"] = "A03:2021 Injection"
    → lưu vào Redis (scan:{id}:findings)
    → enrich_finding() copy sang owasp_category
    → Frontend hiển thị trong tab "Verification Details"
```

---

## 2. CWE (Common Weakness Enumeration) — Root cause mapping

### Lấy từ đâu?

Cũng hardcoded trong `models.py`, bảng `CWE_MAP`:

```python
CWE_MAP: dict[str, str] = {
    "sqli":            "CWE-89",   # Improper Neutralization of SQL
    "xss":             "CWE-79",   # Improper Neutralization of Input in HTML
    "ssrf":            "CWE-918",  # Server-Side Request Forgery
    "cmdi":            "CWE-78",   # OS Command Injection
    "lfi":             "CWE-22",   # Path Traversal
    "path_traversal":  "CWE-22",
    "info_disclosure": "CWE-200",  # Exposure of Sensitive Information
    "time_based_sqli": "CWE-89",
    "time_based_cmdi": "CWE-78",
}
```

### Mapping như nào?

Tương tự OWASP — property `cwe` trên `VulnerabilityFinding`. Sau đó `enrich_finding()` trong `knowledge_base/vuln_templates.py` copy giá trị này sang `cwe_id` nếu chưa có:

```python
if not result.get("cwe_id"):
    if result.get("cwe"):
        result["cwe_id"] = result["cwe"]
    else:
        # fallback: lấy từ references của template (VD: "CWE-89")
        refs = tmpl.get("references", [])
        cwe_refs = [r for r in refs if str(r).startswith("CWE-")]
        if cwe_refs:
            result["cwe_id"] = cwe_refs[0]
```

---

## 3. CVSS v3.1 — Severity scoring

### Lấy từ đâu?

Hai nguồn khác nhau tùy context:

**a) Vulnerability findings (lỗ hổng tìm được khi scan):**

Bảng tĩnh `CVSS_MAP` trong `models.py`, gán theo loại lỗ hổng:

```python
CVSS_MAP: dict[str, float] = {
    "sqli":            9.8,   → Critical
    "cmdi":            9.8,   → Critical
    "ssrf":            8.6,   → High
    "lfi":             7.5,   → High
    "path_traversal":  7.5,   → High
    "xss":             6.1,   → Medium
    "info_disclosure": 5.3,   → Medium
}
```

Hàm `_cvss_to_severity()` chuyển score → label (Critical/High/Medium/Low) theo ngưỡng CVSS v3.1 chuẩn (≥9.0, ≥7.0, ≥4.0).

**b) CVE records (lỗ hổng từ NVD):**

Score thực tế lấy từ API NVD, ưu tiên theo thứ tự: `cvssMetricV31 → cvssMetricV30 → cvssMetricV2`.

```python
for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
    entries = metrics.get(version_key, [])
    if entries:
        return float(entries[0]["cvssData"]["baseScore"])
```

### Mapping như nào?

```
Scan finding:  vulnerability_type → CVSS_MAP → score → severity label
CVE từ NVD:   NVD API response → cvssMetricV31.baseScore → severity label
Cả hai:       severity label hiển thị màu trong UI (Critical=đỏ, High=cam...)
```

---

## 4. CVE (Common Vulnerabilities and Exposures) — Known vulnerability reference

### Lấy từ đâu?

**Nguồn 1 — NVD keyword search** (`scanner/cve_intelligence/nvd_client.py`):

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?keywordSearch=Apache 2.4.51
    &resultsPerPage=10
    [Header: apiKey: <NVD_API_KEY>]
```

Gọi sau bước fingerprint công nghệ (Wappalyzer) để tra CVE cho từng technology+version phát hiện được.

**Nguồn 2 — NVD CPE lookup** (chính xác hơn):

```
GET https://services.nvd.nist.gov/rest/json/cves/2.0
    ?cpeName=cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*
```

Chỉ dùng khi Wappalyzer trả về versioned CPE (ví dụ: `cpe:2.3:a:wordpress:wordpress:6.4.1`).

**Nguồn 3 — CISA KEV** (xem phần 5).

### Mapping như nào?

```
Wappalyzer fingerprint → technology + version + CPE
    → NVD keyword search (broad)
    → NVD CPE search (version-exact, nếu có CPE)
    → CVERecord(cve_id, cvss, severity, summary, published_date)
    → lưu Redis (scan:{id}:cve_intelligence)
    → Asset Intelligence layer → AssetCVE[]
    → Frontend hiển thị trong tab CVE Intelligence
```

**Rate limiting:** Có `asyncio.sleep(0.7)` giữa các request để tránh bị NVD throttle (50 req/30s không có key, 2000 req/30s có key).

---

## 5. CISA KEV — Actively exploited vulnerability tracking

### Lấy từ đâu?

Download trực tiếp từ CISA public feed (`scanner/cve_intelligence/kev_client.py`):

```
GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

JSON này chứa ~1000+ CVE IDs mà CISA xác nhận đang bị khai thác trong thực tế.

### Cache như nào?

```python
# Lưu Redis key "kev:catalog", TTL 24 giờ
await redis_client.setex("kev:catalog", 86_400, json.dumps(list(cve_ids)))
```

Mỗi lần scan chỉ fetch 1 lần/24h, không gọi CISA mỗi request.

### Mapping như nào?

Sau khi có danh sách CVE từ NVD, system check từng CVE ID với KEV set:

```python
def is_actively_exploited(cve_id: str, kev_set: set[str]) -> bool:
    return bool(cve_id) and cve_id in kev_set
```

Nếu CVE thuộc KEV → `is_actively_exploited = True` → hiển thị badge "🔴 Actively Exploited" trong UI.

```
CVERecord từ NVD
    → check cve_id in KEV set (O(1) set lookup)
    → AssetCVE.is_actively_exploited = True/False
    → Frontend: badge đỏ "Actively Exploited" nếu True
```

---

## 6. NVD 2.0 API — Vulnerability database queries

Đây là **cơ sở hạ tầng** cho CVE lookup (đã mô tả ở phần 4). Một số chi tiết kỹ thuật:

| Tham số | Giá trị |
|---------|---------|
| Base URL | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| Auth | Header `apiKey` (optional nhưng nên có) |
| Timeout | 20 giây per request |
| Kết quả | Tối đa 10 (keyword) hoặc 20 (CPE) CVE per lookup |
| Fallback | Network error → log warning, trả về list rỗng (không block scan) |

Cấu hình NVD API key trong `.env`:
```env
NVD_API_KEY=your-key-here
```

Không có key vẫn hoạt động nhưng rate limit thấp hơn nhiều (50 req/30s).

---

## 7. AI trong sản phẩm — Làm gì và dữ liệu ở đâu?

### Hiện tại AI làm gì?

AI trong sản phẩm hiện tại là **rule-based explanation engine**, không phải LLM. Nằm ở `hqg-backend/ai/analyzer/ai_client.py`.

**Chức năng:** Sinh văn bản giải thích kỹ thuật cho từng finding dựa trên template:

```python
_EXPLANATION_TEMPLATES = {
    "sqli": (
        "The payload {payload!r} caused the server to return a database error "
        "at {endpoint}, indicating that user input reaches a SQL query without "
        "proper sanitisation."
    ),
    "xss": "...",
    "ssrf": "...",
    # 8 loại lỗ hổng khác
}

def generate_explanation(vulnerability_type, endpoint, payload) -> str:
    template = _EXPLANATION_TEMPLATES.get(vulnerability_type)
    return template.format(endpoint=endpoint, payload=payload)
```

### Dữ liệu đầu vào của AI:

| Input | Nguồn |
|-------|-------|
| `vulnerability_type` | Detection engine (sqli, xss, ssrf...) |
| `endpoint` | URL bị phát hiện lỗ hổng |
| `payload` | Payload đã inject để trigger finding |

### Dữ liệu đầu ra (lưu vào Redis):

```python
finding["explanation"] = generate_explanation(vuln_type, endpoint, payload)
```

Output được lưu cùng với finding trong Redis key `scan:{id}:findings`, hiển thị trong mục **"Attack Summary"** trên UI.

### Quan hệ với Knowledge Base:

Có **2 lớp enrichment** chạy theo thứ tự:

```
1. ai_client.generate_explanation()
   → Sinh explanation cụ thể cho finding đó (có payload + endpoint thực)
   → Ví dụ: "Payload '1 OR 1=1' caused error at /api/users?id=..."

2. knowledge_base.enrich_finding()
   → Chỉ fill các field CÒN THIẾU (không ghi đè AI output)
   → Thêm: impact, remediation, owasp_category, cwe_id
   → Nguồn: VULN_TEMPLATES (12 loại lỗ hổng với text viết sẵn)
```

**Rule:** Nếu AI đã sinh explanation → knowledge base KHÔNG ghi đè. Nếu AI không chạy (quick mode) hoặc fail → knowledge base fill fallback.

### Tại sao không dùng LLM thật?

File `ai_client.py` có stub sẵn cho LLM:

```python
async def generate_explanation_llm(
    vulnerability_type, endpoint, payload, evidence=""
) -> str:
    """Placeholder — Wire OpenAI/Anthropic/local Llama here."""
    return generate_explanation(vulnerability_type, endpoint, payload)
```

Hiện tại `generate_explanation_llm` chỉ fallback về rule-based engine. Khi muốn tích hợp LLM thật (GPT-4, Claude, Llama), chỉ cần implement hàm này mà không cần thay đổi phần còn lại của pipeline.

### Tóm tắt luồng AI:

```
Detection Engine
    ↓ (finding với payload + endpoint)
AI Analyzer (rule-based)
    ↓ explanation = template.format(endpoint=..., payload=...)
Knowledge Base Enricher
    ↓ impact, remediation, owasp_category, cwe_id (nếu chưa có)
Redis Storage
    ↓ scan:{id}:findings
Frontend
    → Attack Summary: explanation
    → Impact: impact
    → Recommended Fix: remediation
    → Verification Details: owasp_category, cwe_id, cvss_score
```

---

## Sơ đồ tổng quan

```
┌─────────────────────────────────────────────────────────┐
│                    Scan Pipeline                         │
│                                                          │
│  Target URL                                              │
│      ↓                                                   │
│  Wappalyzer Fingerprint                                  │
│      │                                                   │
│      ├──→ technology + version + CPE                     │
│      │         ↓                                         │
│      │    NVD 2.0 API ──→ CVERecord (cvss, severity)     │
│      │    CISA KEV    ──→ is_actively_exploited flag      │
│      │                                                   │
│  Detection Engine (payload injection)                    │
│      │                                                   │
│      ├──→ VulnerabilityFinding                           │
│      │       OWASP_MAP  → owasp_category                 │
│      │       CWE_MAP    → cwe_id                         │
│      │       CVSS_MAP   → cvss_score → severity          │
│      │                                                   │
│  AI Analyzer (rule-based templates)                      │
│      │                                                   │
│      ├──→ explanation (endpoint + payload specific)      │
│      │                                                   │
│  Knowledge Base Enricher                                 │
│      ├──→ impact (VULN_TEMPLATES)                        │
│      ├──→ remediation (VULN_TEMPLATES)                   │
│      └──→ owasp_category, cwe_id (fallback)              │
│                                                          │
│  Redis Storage → Frontend                                │
└─────────────────────────────────────────────────────────┘
```
