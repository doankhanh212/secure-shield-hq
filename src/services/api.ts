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
  explanation?: string;
  remediation?: string;
  status?: string;
  owasp_category?: string;
  cwe_id?: string;
  attack_vector?: string;
  poc?: string;
  ai_confidence?: number;
  remediation_note?: string;
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
    logout();
    return undefined as unknown as T;
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API ${res.status}: ${text}`);
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
  if (!res.ok) throw new Error("Sai tên đăng nhập hoặc mật khẩu");
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
  return !!localStorage.getItem("access_token");
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

// ── Vulnerabilities ────────────────────────────────────────────────────────

export function getVulnerabilities(params?: {
  scan_id?: string;
  severity?: string;
  endpoint?: string;
  limit?: number;
}): Promise<VulnerabilityResponse> {
  const url = new URL(`${API_BASE}/vulnerabilities`, window.location.origin);
  if (params?.scan_id) url.searchParams.set("scan_id", params.scan_id);
  if (params?.severity) url.searchParams.set("severity", params.severity);
  if (params?.endpoint) url.searchParams.set("endpoint", params.endpoint);
  if (params?.limit) url.searchParams.set("limit", String(params.limit));
  return request<VulnerabilityResponse>(url.toString());
}

export function getVulnerability(id: string): Promise<Vulnerability> {
  return request<Vulnerability>(`${API_BASE}/vulnerabilities/${encodeURIComponent(id)}`);
}

export function patchVulnerability(
  id: string,
  data: { status?: string; is_false_positive?: boolean; remediation_note?: string }
): Promise<Vulnerability> {
  return request(`${API_BASE}/vulnerabilities/${encodeURIComponent(id)}`, {
    method: "PATCH",
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

// ── WebSocket ──────────────────────────────────────────────────────────────

export function createScanWebSocket(
  scanId: string,
  onMessage: (data: unknown) => void,
  onClose?: () => void
): WebSocket {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const host = window.location.host || "localhost:8000";
  const ws = new WebSocket(
    `${protocol}://${host}/api/v1/ws/scans/${scanId}`
  );
  ws.onmessage = (event) => {
    try {
      onMessage(JSON.parse(event.data));
    } catch {}
  };
  ws.onclose = () => onClose?.();
  return ws;
}

// ── Legacy aliases (used by use-dashboard-data) ────────────────────────────

export const fetchScans = getScans;
export const fetchVulnerabilities = getVulnerabilities;
export function fetchAssets(scanId: string): Promise<AssetDiscovery> {
  return getAssetDiscovery(scanId);
}

// ── Reports legacy alias (used by Reports.tsx) ─────────────────────────────
export { getReportByScan as getReportsByScan };
