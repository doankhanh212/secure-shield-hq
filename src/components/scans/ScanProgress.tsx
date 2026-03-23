import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Search, Globe, Code, Zap, Brain, FileText, Loader2 } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { getScan } from "@/services/api";

interface ScanStage {
  key: string;
  icon: typeof Search;
  status: "completed" | "active" | "pending";
  progress?: number;
  details?: string;
}

interface ScanProgressProps {
  target: string;
  scanId?: string;
  scanMode?: string;
  startedAt?: string;
  stages?: ScanStage[];
}

const STAGE_ORDER = ["asset_discovery", "crawling", "template_scan", "payload_injection", "detection", "ai_analysis", "reporting"];
const STAGE_META: Record<string, { key: string; icon: typeof Globe }> = {
  asset_discovery: { key: "Khám phá Tài sản", icon: Globe },
  crawling: { key: "Thu thập Endpoint", icon: Code },
  template_scan: { key: "Quét Template", icon: Search },
  payload_injection: { key: "Kiểm tra Payload", icon: Zap },
  detection: { key: "Phân tích Phát hiện", icon: Search },
  ai_analysis: { key: "Phân tích AI", icon: Brain },
  reporting: { key: "Tạo Báo cáo", icon: FileText },
};

const modeBadgeStyles: Record<string, string> = {
  quick: "bg-blue-500/10 text-blue-600 border-blue-500/30",
  standard: "bg-indigo-500/10 text-indigo-600 border-indigo-500/30",
  deep: "bg-orange-500/10 text-orange-600 border-orange-500/30",
  full: "bg-red-500/10 text-red-600 border-red-500/30",
};

function modeLabel(mode?: string): string {
  const map: Record<string, string> = {
    quick: "Quick",
    standard: "Standard",
    deep: "Deep",
    full: "Full",
  };
  return map[mode ?? ""] ?? (mode ?? "Unknown");
}

function formatStartedAgo(iso?: string): string {
  if (!iso) return "Bắt đầu vừa xong";
  const started = new Date(iso).getTime();
  if (Number.isNaN(started)) return "Bắt đầu vừa xong";
  const diffMs = Date.now() - started;
  const diffMinutes = Math.max(1, Math.floor(diffMs / 60_000));
  if (diffMinutes < 60) return `Bắt đầu ${diffMinutes} phút trước`;
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) return `Bắt đầu ${diffHours} giờ trước`;
  const diffDays = Math.floor(diffHours / 24);
  return `Bắt đầu ${diffDays} ngày trước`;
}

function buildStages(currentStage: string, progress: number): ScanStage[] {
  const normalizedStage = currentStage === "done" ? "reporting" : currentStage;
  const idx = STAGE_ORDER.indexOf(normalizedStage);
  return STAGE_ORDER.map((stage, i) => {
    const meta = STAGE_META[stage];
    let status: ScanStage["status"] = "pending";
    let stageProgress: number | undefined;
    if (i < idx) {
      status = "completed";
      stageProgress = 100;
    } else if (i === idx) {
      status = "active";
      stageProgress = Math.round(progress * 100);
    }
    return { key: meta.key, icon: meta.icon, status, progress: stageProgress };
  });
}

export function ScanProgress({ target, scanId, scanMode, startedAt, stages: stagesProp }: ScanProgressProps) {
  const { t } = useLanguage();

  const { data: scan } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: 5_000,
  });

  const stages = stagesProp ?? (scan ? buildStages(scan.stage, scan.progress) : buildStages("pending", 0));
  const mode = scanMode ?? scan?.mode;
  const createdAt = startedAt ?? scan?.created_at;

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <div className="flex items-center gap-2 flex-wrap mb-3">
        <span className="text-[11px] text-muted-foreground">Scan ID:</span>
        <span className="font-mono text-xs px-2 py-0.5 rounded border border-border bg-muted/40">{scanId?.slice(0, 8) ?? "--------"}</span>
        <Badge variant="outline" className={cn("text-[10px] uppercase", modeBadgeStyles[mode ?? ""] ?? "bg-muted text-muted-foreground border-border")}>
          {modeLabel(mode)}
        </Badge>
        <span className="text-xs text-muted-foreground">{formatStartedAgo(createdAt)}</span>
      </div>

      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-semibold">{t("scans.progress")}</h3>
          <p className="text-xs text-muted-foreground font-mono mt-0.5">{target}</p>
        </div>
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/20">
          <span className="h-2 w-2 rounded-full bg-primary animate-scan-pulse" />
          <span className="text-xs font-medium text-primary">{t("common.scanning")}</span>
        </div>
      </div>

      <div className="space-y-1">
        {stages.map((stage, i) => (
          <div key={stage.key} className="flex items-center gap-3">
            {/* Timeline connector */}
            <div className="flex flex-col items-center w-8">
              <div className={cn(
                "h-8 w-8 rounded-full flex items-center justify-center border-2 transition-all",
                stage.status === "completed" && "bg-success border-success text-success-foreground",
                stage.status === "active" && "bg-primary/10 border-primary text-primary",
                stage.status === "pending" && "bg-transparent border-muted-foreground/40 text-muted-foreground"
              )}>
                {stage.status === "active" ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <stage.icon className="h-4 w-4" />
                )}
              </div>
              {i < stages.length - 1 && (
                <div className={cn(
                  "w-0.5 h-6",
                  stage.status === "completed" ? "bg-success/50" : "bg-border"
                )} />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 pb-6">
              <div className="flex items-center justify-between">
                <p className={cn(
                  "text-sm font-medium",
                  stage.status === "completed" && "text-success",
                  stage.status === "active" && "text-primary font-semibold",
                  stage.status === "pending" && "text-muted-foreground"
                )}>
                  {stage.key}
                </p>
                {stage.progress !== undefined && stage.status !== "pending" && (
                  <span className="text-xs font-mono font-bold">
                    {stage.progress}%
                  </span>
                )}
              </div>
              {stage.details && (
                <p className="text-xs text-muted-foreground mt-0.5">{stage.details}</p>
              )}
              {stage.status === "active" && stage.progress !== undefined && (
                <div className="w-full h-1.5 bg-muted rounded-full mt-2 overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full progress-striped"
                    style={{ width: `${stage.progress}%` }}
                  />
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
