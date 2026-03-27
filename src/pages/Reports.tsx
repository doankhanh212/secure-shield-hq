import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { FileText, Download, Loader2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery } from "@tanstack/react-query";
import { getScans, getReportByScan, getReportDownloadUrl, type ReportMeta } from "@/services/api";
import { cn } from "@/lib/utils";

type SortOption = "newest" | "oldest" | "critical-first";

type SeveritySummary = {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
};

const modeBadgeStyles: Record<string, string> = {
  quick: "bg-cyan-500/10 text-cyan-500 border-cyan-500/30",
  standard: "bg-blue-500/10 text-blue-500 border-blue-500/30",
  deep: "bg-violet-500/10 text-violet-500 border-violet-500/30",
  full: "bg-orange-500/10 text-orange-500 border-orange-500/30",
};

const modeLabel: Record<string, string> = {
  quick: "Nhanh",
  standard: "Tiêu chuẩn",
  deep: "Sâu",
  full: "Đầy đủ",
};

function extractSeveritySummary(report: ReportMeta | null | undefined): SeveritySummary | null {
  if (!report) return null;
  const r = report as ReportMeta & {
    severity_summary?: SeveritySummary;
    findings_by_severity?: SeveritySummary;
    stats?: { severity?: SeveritySummary };
  };
  return r.severity_summary ?? r.findings_by_severity ?? r.stats?.severity ?? null;
}

function getHighestSeverity(s: SeveritySummary | null): "critical" | "high" | "medium" | "none" {
  if (!s) return "none";
  if ((s.critical ?? 0) > 0) return "critical";
  if ((s.high ?? 0) > 0) return "high";
  if ((s.medium ?? 0) > 0) return "medium";
  return "none";
}

const severityDotColor: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  none: "bg-emerald-500",
};

const severityPillStyles: Record<string, string> = {
  critical: "bg-red-500/10 text-red-500 border-red-500/20",
  high: "bg-orange-500/10 text-orange-500 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
};

// Quick mode only generates HTML; standard/deep/full expose all four formats on demand.
function getFormatsForMode(mode: string): string[] {
  if (mode === "quick") return ["html"];
  return ["html", "pdf", "json", "csv"];
}

const Reports = () => {
  const { t } = useLanguage();
  const navigate = useNavigate();
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<SortOption>("newest");

  const { data: scans, isLoading: scansLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
  });

  const completedScans = (scans ?? []).filter(
    (s) => s.status === "completed" || s.status === "running"
  );

  const { data: reportsMap, isLoading: reportsLoading } = useQuery({
    queryKey: ["reports", completedScans.map((s) => s.scan_id)],
    queryFn: async () => {
      const results: Record<string, ReportMeta | null> = {};
      await Promise.all(
        completedScans.map(async (scan) => {
          try {
            results[scan.scan_id] = await getReportByScan(scan.scan_id);
          } catch {
            results[scan.scan_id] = null;
          }
        })
      );
      return results;
    },
    enabled: completedScans.length > 0,
  });

  const isLoading = scansLoading || (completedScans.length > 0 && reportsLoading);

  const filteredAndSortedScans = useMemo(() => {
    const filtered = completedScans.filter((scan) =>
      scan.target.toLowerCase().includes(search.toLowerCase())
    );
    return [...filtered].sort((a, b) => {
      if (sortBy === "oldest") {
        return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      }
      if (sortBy === "critical-first") {
        const aSummary = extractSeveritySummary(reportsMap?.[a.scan_id]);
        const bSummary = extractSeveritySummary(reportsMap?.[b.scan_id]);
        const aCritical = aSummary?.critical ?? 0;
        const bCritical = bSummary?.critical ?? 0;
        if (bCritical !== aCritical) return bCritical - aCritical;
        const aHigh = aSummary?.high ?? 0;
        const bHigh = bSummary?.high ?? 0;
        if (bHigh !== aHigh) return bHigh - aHigh;
      }
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });
  }, [completedScans, reportsMap, search, sortBy]);

  return (
    <DashboardLayout>
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("reports.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {isLoading ? "Đang tải..." : `${filteredAndSortedScans.length} báo cáo`}
        </p>
      </div>

      {/* Filters */}
      <div className="mb-5 flex items-center justify-between gap-3">
        <div className="relative w-80">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Tìm theo mục tiêu..."
            className="h-9 pl-3 bg-muted/40"
          />
        </div>
        <select
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as SortOption)}
          className="h-9 rounded-lg border border-border bg-background px-3 text-sm shrink-0"
        >
          <option value="newest">Mới nhất</option>
          <option value="oldest">Cũ nhất</option>
          <option value="critical-first">Critical trước</option>
        </select>
      </div>

      {/* Report Cards */}
      <div className="space-y-3">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="bg-card rounded-xl border border-border p-5 flex items-center gap-4">
              <Skeleton className="h-10 w-10 rounded-lg shrink-0" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-4 w-60" />
                <Skeleton className="h-3 w-40" />
              </div>
              <div className="flex gap-2">
                <Skeleton className="h-8 w-14 rounded-lg" />
                <Skeleton className="h-8 w-14 rounded-lg" />
              </div>
            </div>
          ))
        ) : filteredAndSortedScans.length === 0 ? (
          <div className="bg-card rounded-xl border border-border py-16 text-center">
            <div className="w-12 h-12 mx-auto mb-4 bg-muted rounded-xl flex items-center justify-center">
              <FileText className="w-6 h-6 text-muted-foreground" />
            </div>
            <h3 className="text-sm font-semibold mb-1">Chưa có báo cáo nào</h3>
            <p className="text-sm text-muted-foreground mb-4">
              Báo cáo được tạo tự động sau khi quét hoàn tất
            </p>
            <button
              className="bg-[#06b6d4] text-white px-4 py-2 rounded-lg text-sm hover:bg-[#0891b2] transition-colors"
              onClick={() => void navigate("/scans")}
            >
              Bắt đầu quét ngay
            </button>
          </div>
        ) : (
          filteredAndSortedScans.map((scan) => {
            const report = reportsMap?.[scan.scan_id];
            const isReady = scan.status === "completed" && report;
            const isGenerating = !isReady;
            const formats = getFormatsForMode(scan.mode);

            const severitySummary = extractSeveritySummary(report);
            const highest = getHighestSeverity(severitySummary);

            const severityPills = [
              { key: "critical", label: "Nghiêm trọng", count: severitySummary?.critical ?? 0 },
              { key: "high", label: "Cao", count: severitySummary?.high ?? 0 },
              { key: "medium", label: "Trung bình", count: severitySummary?.medium ?? 0 },
            ].filter((p) => p.count > 0);

            return (
              <div
                key={scan.scan_id}
                className="bg-card rounded-xl border border-border p-5 flex items-center justify-between hover:shadow-sm transition-shadow relative overflow-hidden"
              >
                {/* Left: icon + info */}
                <div className="flex items-center gap-4 min-w-0 flex-1">
                  <div className="relative shrink-0">
                    <div className="w-10 h-10 bg-muted rounded-lg flex items-center justify-center">
                      <FileText className="w-5 h-5 text-muted-foreground" />
                    </div>
                    <span
                      className={cn(
                        "absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full border-2 border-card",
                        severityDotColor[highest]
                      )}
                    />
                  </div>
                  <div className="min-w-0">
                    <p className="font-semibold text-sm truncate">
                      Security Assessment — {scan.target}
                    </p>
                    <div className="flex items-center gap-2.5 mt-1 flex-wrap">
                      <span className="font-mono text-xs text-muted-foreground">
                        {scan.scan_id.slice(0, 8)}
                      </span>
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px] font-semibold px-1.5 py-0",
                          modeBadgeStyles[scan.mode] ?? "bg-muted text-muted-foreground border-border"
                        )}
                      >
                        {modeLabel[scan.mode] ?? scan.mode}
                      </Badge>
                      <span className="text-xs text-muted-foreground">
                        {new Date(scan.created_at).toLocaleDateString("vi-VN")}
                      </span>
                    </div>
                    {severityPills.length > 0 && (
                      <div className="mt-2 flex items-center gap-1.5 flex-wrap">
                        {severityPills.map((pill) => (
                          <Badge
                            key={pill.key}
                            variant="outline"
                            className={cn("text-[10px] px-1.5 py-0", severityPillStyles[pill.key])}
                          >
                            {pill.count} {pill.label}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Right: download buttons */}
                <div className="flex items-center gap-2 shrink-0 ml-4">
                  {isGenerating ? (
                    <div className="inline-flex items-center gap-2 text-xs text-[#06b6d4] bg-[#06b6d4]/10 border border-[#06b6d4]/20 rounded-lg px-3 py-1.5">
                      <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      Đang tạo...
                    </div>
                  ) : (
                    formats.map((fmt) => (
                      <a
                        key={fmt}
                        href={getReportDownloadUrl(scan.scan_id, fmt)}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <button className="px-3 py-1.5 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-muted/50 transition-colors flex items-center gap-1">
                          <Download className="h-3 w-3" />
                          {fmt.toUpperCase()}
                        </button>
                      </a>
                    ))
                  )}
                </div>

                {isGenerating && (
                  <div className="absolute bottom-0 left-0 h-0.5 w-full bg-[#06b6d4] animate-pulse" />
                )}
              </div>
            );
          })
        )}
      </div>
    </DashboardLayout>
  );
};

export default Reports;
