import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { FileText, Download, Loader2 } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery } from "@tanstack/react-query";
import { getScans, getReportByScan, getReportDownloadUrl, type ReportMeta } from "@/services/api";

type SortOption = "newest" | "oldest" | "critical-first";

type SeveritySummary = {
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
};

const modeBadgeStyles: Record<string, string> = {
  quick: "bg-blue-500/10 text-blue-600 border-blue-500/30",
  standard: "bg-indigo-500/10 text-indigo-600 border-indigo-500/30",
  deep: "bg-orange-500/10 text-orange-600 border-orange-500/30",
  full: "bg-red-500/10 text-red-600 border-red-500/30",
};

function extractSeveritySummary(report: ReportMeta | null | undefined): SeveritySummary | null {
  if (!report) return null;
  const reportWithSummary = report as ReportMeta & {
    severity_summary?: SeveritySummary;
    findings_by_severity?: SeveritySummary;
    stats?: { severity?: SeveritySummary };
  };

  return (
    reportWithSummary.severity_summary ??
    reportWithSummary.findings_by_severity ??
    reportWithSummary.stats?.severity ??
    null
  );
}

function getHighestSeverity(summary: SeveritySummary | null): "critical" | "high" | "medium" | "none" {
  if (!summary) return "none";
  if ((summary.critical ?? 0) > 0) return "critical";
  if ((summary.high ?? 0) > 0) return "high";
  if ((summary.medium ?? 0) > 0) return "medium";
  return "none";
}

function formatMode(mode: string): string {
  const map: Record<string, string> = {
    quick: "Quick",
    standard: "Standard",
    deep: "Deep",
    full: "Full",
  };
  return map[mode] ?? mode;
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

        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      }

      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    });
  }, [completedScans, reportsMap, search, sortBy]);

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("reports.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">{filteredAndSortedScans.length} báo cáo</p>
      </div>

      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="w-full max-w-sm">
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Tìm theo mục tiêu..."
            className="h-9"
          />
        </div>
        <div className="shrink-0">
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as SortOption)}
            className="h-9 rounded-md border border-border bg-background px-3 text-sm"
          >
            <option value="newest">Mới nhất</option>
            <option value="oldest">Cũ nhất</option>
            <option value="critical-first">Critical trước</option>
          </select>
        </div>
      </div>

      <div className="grid gap-4">
        {isLoading ? (
          Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="bg-card rounded-lg border border-border p-5 flex items-center gap-4">
              <Skeleton className="h-11 w-11 rounded-md" />
              <div className="flex-1 space-y-2">
                <Skeleton className="h-4 w-60" />
                <Skeleton className="h-3 w-40" />
              </div>
              <Skeleton className="h-8 w-24" />
            </div>
          ))
        ) : filteredAndSortedScans.length === 0 ? (
          <div className="bg-card rounded-lg border border-border p-12 text-center animate-fade-in">
            <FileText className="h-12 w-12 mx-auto text-muted-foreground" />
            <p className="text-lg font-medium mt-4">Chưa có báo cáo nào</p>
            <p className="text-sm text-muted-foreground mt-1">Báo cáo được tạo tự động sau khi quét hoàn tất</p>
            <Button type="button" variant="outline" className="mt-4" onClick={() => navigate("/scans")}>
              Bắt đầu quét ngay
            </Button>
          </div>
        ) : (
          filteredAndSortedScans.map((scan) => {
            const report = reportsMap?.[scan.scan_id];
            const isReady = scan.status === "completed" && report;
            const isGenerating =
              scan.status === "running" ||
              scan.status === "scanning" ||
              scan.status === "queued" ||
              scan.status === "generating" ||
              !isReady;
            const formats = report?.available_formats ?? [];

            const severitySummary = extractSeveritySummary(report);
            const highestSeverity = getHighestSeverity(severitySummary);
            const severityDotColor =
              highestSeverity === "critical"
                ? "bg-destructive"
                : highestSeverity === "high"
                  ? "bg-orange-500"
                  : highestSeverity === "medium"
                    ? "bg-primary"
                    : "bg-success";

            const severityPills = [
              {
                key: "critical",
                label: "Nghiêm trọng",
                count: severitySummary?.critical ?? 0,
                className: "bg-destructive/10 text-destructive border-destructive/20",
              },
              {
                key: "high",
                label: "Cao",
                count: severitySummary?.high ?? 0,
                className: "bg-orange-500/10 text-orange-600 border-orange-500/20",
              },
              {
                key: "medium",
                label: "Trung bình",
                count: severitySummary?.medium ?? 0,
                className: "bg-primary/10 text-primary border-primary/20",
              },
            ].filter((item) => item.count > 0);

            return (
              <div
                key={scan.scan_id}
                className="bg-card rounded-lg border border-border p-5 hover:bg-muted/30 transition-colors animate-fade-in relative overflow-hidden"
              >
                <div className="flex items-start gap-4">
                  <div className="relative p-3 rounded-md bg-primary/10 shrink-0">
                    <FileText className="h-5 w-5 text-primary" />
                    <span className={"absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full border border-card " + severityDotColor} />
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="font-medium truncate">Security Assessment — {scan.target}</p>
                    <div className="text-xs text-muted-foreground mt-1 flex items-center gap-2 flex-wrap">
                      <span className="font-mono">{scan.scan_id.slice(0, 8)}</span>
                      <Badge
                        variant="outline"
                        className={modeBadgeStyles[scan.mode] ?? "bg-muted text-muted-foreground border-border"}
                      >
                        {formatMode(scan.mode)}
                      </Badge>
                      <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                    </div>

                    {severityPills.length > 0 && (
                      <div className="mt-2 flex items-center gap-2 flex-wrap">
                        {severityPills.map((pill) => (
                          <Badge key={pill.key} variant="outline" className={pill.className}>
                            {pill.count} {pill.label}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>

                  {isGenerating ? (
                    <div className="shrink-0">
                      <div className="inline-flex items-center gap-2 text-xs text-primary bg-primary/10 border border-primary/20 rounded-md px-2 py-1">
                        <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        Đang tạo báo cáo...
                      </div>
                      <div className="mt-3 flex gap-2">
                        {Array.from({ length: 4 }).map((_, index) => (
                          <Skeleton key={index} className="h-8 w-14 rounded-md" />
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="flex gap-2 shrink-0">
                      {(formats.length > 0 ? formats : ["pdf", "json", "csv", "html"]).map((fmt) => (
                        <a
                          key={fmt}
                          href={getReportDownloadUrl(scan.scan_id, fmt)}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <Button variant="outline" size="sm" className="text-xs gap-1.5 h-8">
                            <Download className="h-3 w-3" />
                            {fmt.toUpperCase()}
                          </Button>
                        </a>
                      ))}
                    </div>
                  )}
                </div>

                {isGenerating && <div className="absolute bottom-0 left-0 h-1 w-full rounded-full bg-primary animate-pulse" />}
              </div>
            );
          })
        )}
      </div>
    </DashboardLayout>
  );
};

export default Reports;
