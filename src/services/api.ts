const API_BASE = "/api/v1";

// ── Types ──────────────────────────────────────────────────────────────────

interface DashboardStats {
  total_assets: number;
  open_vulnerabilities: number;
  active_scans: number;
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  domains: number;
  subdomains: number;
  api_endpoints: number;
  ips: number;
  exposed_services: number;
}

interface PostureData {
  current_score: number;
  trend: { label: string; score: number }[];
}

interface TopRisksData {
  assets: {
    domain: string;
    score: number;
    critical_count: number;
    high_count: number;
  }[];
}

export interface Scan {
  scan_id: string;
  target: string;
  mode: string;
  status: string;
  stage: string;
  progress: number;
  created_at: string;
  error?: string | null;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  severity: string;
  endpoint: string;
  vulnerability_type: string;
  is_false_positive: boolean;
  false_positive_reason?: string;
  explanation?: string;
  remediation?: string;
  status?: string;
  owasp_category?: string;
  cwe_id?: string;
  attack_vector?: string;
  poc?: string;
  ai_confidence?: number;
  remediation_note?: string;
  // Additional fields returned by the backend
  evidence?: string;
  impact?: string;
  fix_recommendation?: string;
  confidence_label?: string;
  false_positive_likelihood?: string;
  payload?: string;
  parameter?: string;
  cvss_score?: number;
  finding_id?: string;
}

export interface VulnerabilityResponse {
  total: number;
  items: Vulnerability[];
}

export interface Asset {
  id: string;
  domain: string;
  ip: string;
  cloud: string;
  status: string;
  exposure: string;
  open_ports: number[];
  technologies: string[];
  risk_score: number;
  created_at: string;
}

export interface AssetDiscovery {
  scan_id: string;
  target: string;
  domains: string[];
  subdomains: string[];
  services: { port: number; service: string; version?: string }[];
  technologies: string[];
}

export interface Domain {
  id: string;
  domain: string;
  url: string;
  subdomains: string[];
  technologies: string[];
  last_scan_id: string | null;
  last_scan_date: string | null;
  last_scan_mode: string | null;
  total_scans: number;
  total_vulnerabilities: number;
  severity_counts: Record<string, number>;
  vuln_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  false_positive_count: number;
  active_vuln_count: number;
  risk_score: number;
  status: string;
  created_at: string;
}

export interface ReportMeta {
  scan_id: string;
  target: string;
  scan_status: string;
  available_formats: string[];
  files: Record<string, { format: string; size_bytes: number; generated_at: string }>;
}

// ── Helpers ────────────────────────────────────────────────────────────────

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const token = localStorage.getItem("access_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string>),
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(url, { ...init, headers });

  if (res.status === 401) {
    // Token expired or invalid — force re-login
    localStorage.removeItem("access_token");
    localStorage.removeItem("user_role");
    localStorage.removeItem("username");
    window.location.href = "/login";
    throw new Error("Session expired. Please log in again.");
  }

  if (res.status === 429) {
    throw new Error("Quá nhiều yêu cầu. Vui lòng thử lại sau.");
  }

  if (!res.ok) {
    let detail = `Lỗi ${res.status}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = body.detail;
    } catch {
      const text = await res.text().catch(() => "");
      if (text) detail = text;
    }
    throw new Error(detail);
  }

  return res.json();
}

// ── Auth ───────────────────────────────────────────────────────────────────

export async function login(
  username: string,
  password: string
): Promise<{ access_token: string; role: string; username: string }> {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (res.status === 429) {
    throw new Error("Quá nhiều lần thử. Vui lòng chờ 1 phút rồi thử lại.");
  }
  if (!res.ok) {
    let msg = "Sai tên đăng nhập hoặc mật khẩu";
    try {
      const body = await res.json();
      if (body?.detail) msg = body.detail;
    } catch {}
    throw new Error(msg);
  }
  const data = await res.json();
  localStorage.setItem("access_token", data.access_token);
  localStorage.setItem("user_role", data.role);
  localStorage.setItem("username", data.username);
  return data;
}

export function logout(): void {
  localStorage.removeItem("access_token");
  localStorage.removeItem("user_role");
  localStorage.removeItem("username");
  window.location.href = "/login";
}

export function isAuthenticated(): boolean {
  const token = localStorage.getItem("access_token");
  if (!token) return false;
  // Decode JWT payload (base64url) and check expiry without a library
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp && Date.now() / 1000 >= payload.exp) {
      // Token expired — clear storage silently
      localStorage.removeItem("access_token");
      localStorage.removeItem("user_role");
      localStorage.removeItem("username");
      return false;
    }
  } catch {
    // Malformed token — treat as unauthenticated
    localStorage.removeItem("access_token");
    return false;
  }
  return true;
}

export function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<{ message: string }> {
  return request(`${API_BASE}/auth/change-password`, {
    method: "POST",
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });
}

// ── Scans ──────────────────────────────────────────────────────────────────

export function getScans(): Promise<Scan[]> {
  return request<Scan[]>(`${API_BASE}/scans`);
}

export function getScan(scanId: string): Promise<Scan> {
  return request<Scan>(`${API_BASE}/scans/${encodeURIComponent(scanId)}`);
}

export function createScan(target: string, mode: string): Promise<{ scan_id: string }> {
  return request(`${API_BASE}/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, mode }),
  });
}

export function deleteScan(scanId: string): Promise<{ message: string }> {
  return request(`${API_BASE}/scans/${encodeURIComponent(scanId)}`, {
    method: "DELETE",
  });
}

// ── Assets (standalone CRUD) ───────────────────────────────────────────────

export function getAssets(): Promise<Asset[]> {
  return request<Asset[]>(`${API_BASE}/assets`);
}

export function createAsset(data: Omit<Asset, "id" | "created_at">): Promise<Asset> {
  return request(`${API_BASE}/assets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function updateAsset(id: string, data: Partial<Asset>): Promise<Asset> {
  return request(`${API_BASE}/assets/${encodeURIComponent(id)}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function deleteAsset(id: string): Promise<{ message: string }> {
  return request(`${API_BASE}/assets/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

// ── Assets (scan-based discovery) ──────────────────────────────────────────

export function getAssetDiscovery(scanId: string): Promise<AssetDiscovery> {
  return request<AssetDiscovery>(`${API_BASE}/assets/${encodeURIComponent(scanId)}/discovery`);
}

// ── Domains ─────────────────────────────────────────────────────────────────

export function getDomains(): Promise<Domain[]> {
  return request<Domain[]>(`${API_BASE}/domains`);
}

export function createDomain(url: string): Promise<Domain> {
  return request<Domain>(`${API_BASE}/domains`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

export function deleteDomain(id: string): Promise<{ message: string }> {
  return request(`${API_BASE}/domains/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
}

export function getDomainReportDownloadUrl(domainId: string, format: string): string {
  return `${API_BASE}/domains/${encodeURIComponent(domainId)}/report?format=${encodeURIComponent(format)}`;
}

// ── Vulnerabilities ────────────────────────────────────────────────────────

export function getVulnerabilities(params?: {
  scan_id?: string;
  severity?: string;
  domain?: string;
  endpoint?: string;
  limit?: number;
}): Promise<VulnerabilityResponse> {
  const url = new URL(`${API_BASE}/vulnerabilities`, window.location.origin);
  if (params?.scan_id) url.searchParams.set("scan_id", params.scan_id);
  if (params?.severity) url.searchParams.set("severity", params.severity);
  if (params?.domain) url.searchParams.set("domain", params.domain);
  if (params?.endpoint) url.searchParams.set("endpoint", params.endpoint);
  if (params?.limit) url.searchParams.set("limit", String(params.limit));
  return request<VulnerabilityResponse>(url.toString());
}

export function getVulnerability(id: string): Promise<Vulnerability> {
  return request<Vulnerability>(`${API_BASE}/vulnerabilities/${encodeURIComponent(id)}`);
}

export function patchVulnerability(
  id: string,
  data: { status?: string; is_false_positive?: boolean; false_positive_reason?: string; remediation_note?: string }
): Promise<Vulnerability> {
  return request(`${API_BASE}/vulnerabilities/${encodeURIComponent(id)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export function setFindingFalsePositive(
  id: string,
  data: { is_false_positive: boolean; false_positive_reason?: string }
): Promise<Vulnerability> {
  return request(`${API_BASE}/findings/${encodeURIComponent(id)}/false-positive`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

// ── Reports ────────────────────────────────────────────────────────────────

export function getReports(): Promise<ReportMeta[]> {
  return request<ReportMeta[]>(`${API_BASE}/reports`);
}

export function getReportByScan(scanId: string): Promise<ReportMeta> {
  return request<ReportMeta>(`${API_BASE}/reports/${encodeURIComponent(scanId)}`);
}

export function getReportDownloadUrl(scanId: string, format: string): string {
  return `${API_BASE}/reports/${encodeURIComponent(scanId)}/download?format=${encodeURIComponent(format)}`;
}

// ── Dashboard ──────────────────────────────────────────────────────────────

export async function getDashboardStats(): Promise<DashboardStats> {
  return request(`${API_BASE}/dashboard/stats`);
}

export async function getDashboardPosture(): Promise<PostureData> {
  return request(`${API_BASE}/dashboard/posture`);
}

export async function getDashboardTopRisks(): Promise<TopRisksData> {
  return request(`${API_BASE}/dashboard/top-risks`);
}

// ── Settings ──────────────────────────────────────────────────────────────

export interface PlatformSettings {
  platform_name: string;
  language: string;
  nvd_api_key_configured: boolean;
  daily_scans: boolean;
  ai_analysis: boolean;
  distributed_scanning: boolean;
  email_notifications: boolean;
  scan_workers: number;
}

export function getSettings(): Promise<PlatformSettings> {
  return request<PlatformSettings>(`${API_BASE}/settings`);
}

export function updateSettings(data: Record<string, unknown>): Promise<{ status: string; nvd_api_key_configured: boolean }> {
  return request(`${API_BASE}/settings`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export async function verifyNvdKey(apiKey: string): Promise<{ valid: boolean; message?: string }> {
  const token = localStorage.getItem("access_token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`${API_BASE}/settings/verify-nvd-key`, {
    method: "POST",
    headers,
    body: JSON.stringify({ api_key: apiKey }),
  });
  if (res.status === 401) {
    logout();
    return { valid: false, message: "Unauthorized" };
  }
  const payload = await res.json().catch(() => ({}));
  return {
    valid: !!payload.valid,
    message: typeof payload.message === "string" ? payload.message : undefined,
  };
}

// ── WebSocket ──────────────────────────────────────────────────────────────

export function createScanWebSocket(
  scanId: string,
  onMessage: (data: unknown) => void,
  onClose?: () => void
): WebSocket {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.host || "localhost:8000";
  const token = localStorage.getItem("access_token") ?? "";
  const ws = new WebSocket(
    `${protocol}://${host}/api/v1/ws/scans/${scanId}?token=${encodeURIComponent(token)}`
  );
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {}
  };
  ws.onclose = (event) => {
    // 4401 = server closed due to invalid/missing token
    if (event.code === 4401) {
      logout();
    }
    onClose?.();
  };
  return ws;
}

// ── Asset Intelligence ────────────────────────────────────────────────────

export interface AssetTechnology {
  name: string;
  version: string | null;
  confidence: number;
  sources: string[];
  cpe?: string | null;
  categories?: string[];
}

export interface AssetVulnerability {
  id: string;
  type: string;
  endpoint: string;
  severity: string;
  confidence: string; // confirmed | high | medium | low
  evidence?: string;
  verification_steps?: string[];
  payload?: string;
  parameter?: string;
  cvss_score?: number;
  cwe_id?: string;
  explanation?: string;
  impact?: string;
  remediation?: string;
  owasp_category?: string;
  detection_method?: string;
}

export interface AssetCVE {
  id: string;
  cvss: number;
  severity: string;
  summary?: string;
  published?: string;
  is_actively_exploited?: boolean;
}

export interface AssetIntelligenceItem {
  host: string;
  endpoints: string[];
  technologies: AssetTechnology[];
  vulnerabilities: AssetVulnerability[];
  cves: AssetCVE[];
  risk_score: number;
}

export interface AssetIntelligenceResponse {
  scan_id: string;
  target: string;
  assets: AssetIntelligenceItem[];
  total_assets: number;
  critical_assets: number;
  high_risk_assets: number;
  total_cves: number;
}

export function getAssetIntelligence(scanId: string): Promise<AssetIntelligenceResponse> {
  return request<AssetIntelligenceResponse>(
    `${API_BASE}/scans/${encodeURIComponent(scanId)}/asset-intelligence`
  );
}

export function getLatestAssetIntelligence(): Promise<AssetIntelligenceResponse> {
  return request<AssetIntelligenceResponse>(`${API_BASE}/asset-intelligence/latest`);
}

// ── Legacy aliases (used by use-dashboard-data) ────────────────────────────

export const fetchScans = getScans;
export const fetchVulnerabilities = getVulnerabilities;
export function fetchAssets(scanId: string): Promise<AssetDiscovery> {
  return getAssetDiscovery(scanId);
}

// ── Reports legacy alias (used by Reports.tsx) ─────────────────────────────
export { getReportByScan as getReportsByScan };
