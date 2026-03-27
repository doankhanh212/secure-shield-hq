import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { useNavigate } from "react-router-dom";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Search, Globe, Trash2, Loader2, ExternalLink, FileDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { deleteAsset } from "@/services/api";

const API_BASE = "/api/v1";

interface Domain {
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
  vuln_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  false_positive_count?: number;
  active_vuln_count?: number;
  risk_score: number;
  status: string;
  created_at: string;
}

function getDomains(): Promise<Domain[]> {
  return fetch(`${API_BASE}/assets`).then((r) => {
    if (!r.ok) throw new Error("Failed to fetch domains");
    return r.json();
  });
}

function addDomain(url: string): Promise<Domain> {
  return fetch(`${API_BASE}/assets`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  }).then((r) => {
    if (!r.ok) throw new Error("Failed to add domain");
    return r.json();
  });
}

function getRiskBarColor(score: number): string {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 60) return "bg-yellow-500";
  if (score >= 40) return "bg-orange-500";
  return "bg-red-500";
}

function getRiskTextColor(score: number): string {
  if (score >= 80) return "text-emerald-500";
  if (score >= 60) return "text-yellow-500";
  if (score >= 40) return "text-orange-500";
  return "text-red-500";
}

function relativeTime(iso: string | null): string {
  if (!iso) return "—";
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Vừa xong";
  if (mins < 60) return `${mins} phút trước`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours} giờ trước`;
  const days = Math.floor(hours / 24);
  return `${days} ngày trước`;
}

const modeBadge: Record<string, { label: string; cls: string }> = {
  quick: { label: "Quick", cls: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30" },
  standard: { label: "Standard", cls: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
  deep: { label: "Deep", cls: "bg-violet-500/10 text-violet-400 border-violet-500/30" },
  full: { label: "Full", cls: "bg-amber-500/10 text-amber-400 border-amber-500/30" },
};

const AssetManagement = () => {
  const { t } = useLanguage();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newUrl, setNewUrl] = useState("");

  const { data: domains = [], isLoading, isError, refetch } = useQuery({
    queryKey: ["assets"],
    queryFn: getDomains,
  });

  const addMutation = useMutation({
    mutationFn: () => addDomain(newUrl),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setDialogOpen(false);
      setNewUrl("");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assets"] }),
  });

  const filtered = domains.filter(
    (d) =>
      !search ||
      d.domain.toLowerCase().includes(search.toLowerCase()) ||
      d.url.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("assets.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {isLoading ? "Đang tải..." : `${domains.length} tên miền đang giám sát`}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0">
              <Plus className="h-4 w-4" />
              {t("assets.addAsset")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-[#06b6d4]" />
                {t("assets.addAsset")}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-sm font-medium">URL hoặc tên miền</Label>
                <Input
                  value={newUrl}
                  onChange={(e) => setNewUrl(e.target.value)}
                  placeholder="https://example.com hoặc example.com"
                  className="mt-1.5 font-mono"
                />
              </div>
              <Button
                className="w-full gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0"
                disabled={!newUrl.trim() || addMutation.isPending}
                onClick={() => addMutation.mutate()}
              >
                {addMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin" /> Đang thêm...</>
                ) : (
                  "Thêm tên miền"
                )}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Search */}
      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("common.search")}
            className="pl-9 h-9 bg-muted/40 border text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Error state */}
      {isError && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center mb-4">
          <p className="text-sm text-red-600">Đã xảy ra lỗi khi tải dữ liệu.</p>
          <button className="mt-2 text-xs text-red-500 underline" onClick={() => void refetch()}>
            Thử lại
          </button>
        </div>
      )}

      {/* Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Tên miền
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Tên miền phụ
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Quét gần nhất
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Chế độ
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Lỗ hổng
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Rủi ro
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Hành động
                </th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 3 }).map((_, i) => (
                  <tr key={i} className="border-b border-border">
                    {Array.from({ length: 8 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8}>
                    <div className="text-center py-16">
                      <div className="w-12 h-12 mx-auto mb-4 bg-muted rounded-xl flex items-center justify-center">
                        <Globe className="w-6 h-6 text-muted-foreground" />
                      </div>
                      <h3 className="text-sm font-semibold mb-1">
                        {domains.length === 0 ? "Chưa có tên miền nào" : "Không tìm thấy kết quả"}
                      </h3>
                      <p className="text-sm text-muted-foreground mb-4">
                        {domains.length === 0
                          ? "Tên miền sẽ tự động thêm khi bạn quét."
                          : "Thử thay đổi từ khóa tìm kiếm"}
                      </p>
                      {domains.length === 0 && (
                        <button
                          className="bg-[#06b6d4] text-white px-4 py-2 rounded-lg text-sm hover:bg-[#0891b2] transition-colors"
                          onClick={() => setDialogOpen(true)}
                        >
                          + Thêm Tên miền
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map((d) => {
                  const mode = modeBadge[d.last_scan_mode || ""] || null;

                  return (
                    <tr
                      key={d.id}
                      className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors"
                    >
                      {/* Domain */}
                      <td className="px-4 py-3">
                        <p className="font-mono text-sm font-medium">{d.domain}</p>
                        {d.technologies.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-1">
                            {d.technologies.slice(0, 3).map((tech) => (
                              <span
                                key={tech}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-muted text-muted-foreground border border-border"
                              >
                                {tech}
                              </span>
                            ))}
                            {d.technologies.length > 3 && (
                              <span className="text-[10px] text-muted-foreground">
                                +{d.technologies.length - 3}
                              </span>
                            )}
                          </div>
                        )}
                      </td>

                      {/* Subdomains */}
                      <td className="px-4 py-3">
                        {d.subdomains.length > 0 ? (
                          <span className="text-xs font-mono">{d.subdomains.length} tên miền phụ</span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>

                      {/* Last scan */}
                      <td className="px-4 py-3">
                        <span className="text-xs">{relativeTime(d.last_scan_date)}</span>
                      </td>

                      {/* Mode */}
                      <td className="px-4 py-3">
                        {mode ? (
                          <span className={cn("text-[10px] font-medium px-2 py-0.5 rounded border", mode.cls)}>
                            {mode.label}
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </td>

                      {/* Vulnerabilities — severity pills */}
                      <td className="px-4 py-3">
                        {(() => {
                          const vc = d.vuln_counts ?? {
                            critical: d.severity_counts?.critical ?? 0,
                            high: d.severity_counts?.high ?? 0,
                            medium: d.severity_counts?.medium ?? 0,
                            low: d.severity_counts?.low ?? 0,
                            total: d.total_vulnerabilities,
                          };
                          const fp = d.false_positive_count ?? 0;
                          const hasVulns = vc.total > 0;
                          return (
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {vc.critical > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-500/30">
                                  {vc.critical}C
                                </span>
                              )}
                              {vc.high > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-orange-50 dark:bg-orange-500/10 text-orange-600 dark:text-orange-400 border border-orange-200 dark:border-orange-500/30">
                                  {vc.high}H
                                </span>
                              )}
                              {vc.medium > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 border border-amber-200 dark:border-amber-500/30">
                                  {vc.medium}M
                                </span>
                              )}
                              {vc.low > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-green-50 dark:bg-green-500/10 text-green-600 dark:text-green-400 border border-green-200 dark:border-green-500/30">
                                  {vc.low}L
                                </span>
                              )}
                              {fp > 0 && (
                                <span className="px-1.5 py-0.5 rounded text-[10px] bg-muted text-muted-foreground border border-border">
                                  {fp} FP
                                </span>
                              )}
                              {!hasVulns && (
                                <span className="text-xs text-muted-foreground">Chưa có</span>
                              )}
                            </div>
                          );
                        })()}
                      </td>

                      {/* Risk score */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-14 h-1.5 rounded-full bg-muted overflow-hidden">
                            <div
                              className={cn("h-full rounded-full transition-all", getRiskBarColor(d.risk_score))}
                              style={{ width: `${d.risk_score}%` }}
                            />
                          </div>
                          <span className={cn("text-xs font-mono font-semibold", getRiskTextColor(d.risk_score))}>
                            {d.risk_score.toFixed(0)}
                          </span>
                        </div>
                      </td>

                      {/* Actions: view vulns + export report */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          {d.total_vulnerabilities > 0 && (
                            <button
                              className="flex items-center gap-1 text-xs text-cyan-500 hover:text-cyan-400 transition-colors"
                              onClick={() => void navigate(`/vulnerabilities?domain=${encodeURIComponent(d.domain)}`)}
                            >
                              <ExternalLink className="h-3 w-3" />
                              Chi tiết
                            </button>
                          )}
                          {d.last_scan_id && (
                            <a
                              href={`/api/v1/assets/${encodeURIComponent(d.id)}/report?format=html`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                            >
                              <FileDown className="h-3 w-3" />
                              Xuất
                            </a>
                          )}
                        </div>
                      </td>

                      {/* Delete */}
                      <td className="px-4 py-3">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            removeMutation.mutate(d.id);
                          }}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AssetManagement;
