import { useLanguage } from "@/hooks/use-language";
import { Badge } from "@/components/ui/badge";
import { Radar } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import type { Scan } from "@/services/api";

interface RecentScansProps {
  scans: Scan[];
  isLoading?: boolean;
}

function formatTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function modeLabel(mode: string): string {
  const map: Record<string, string> = {
    quick: "Quick Scan",
    standard: "Standard Scan",
    deep: "Deep Scan",
    full: "Full Scan",
  };
  return map[mode] ?? mode;
}

export function RecentScans({ scans, isLoading }: RecentScansProps) {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.recentScans")}</h3>
      <div className="space-y-3">
        {isLoading ? (
          [1, 2, 3, 4].map((i) => (
            <div key={i} className="flex items-center gap-3 py-2">
              <Skeleton className="h-4 w-4 rounded" />
              <div className="flex-1 space-y-1">
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-3 w-28" />
              </div>
              <Skeleton className="h-5 w-16" />
            </div>
          ))
        ) : scans.length === 0 ? (
          <p className="text-sm text-muted-foreground py-4 text-center">No scans yet</p>
        ) : (
          scans.map((scan) => (
            <div key={scan.scan_id} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
              <Radar className="h-4 w-4 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate font-mono">{scan.target}</p>
                <p className="text-xs text-muted-foreground">
                  {modeLabel(scan.mode)} • {formatTime(scan.created_at)}
                </p>
              </div>
              {scan.status === "running" || scan.status === "scanning" ? (
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                    <div
                      className="h-full bg-primary rounded-full transition-all"
                      style={{ width: `${scan.progress}%` }}
                    />
                  </div>
                  <span className="text-xs text-muted-foreground">{scan.progress}%</span>
                </div>
              ) : (
                <Badge variant="secondary" className="text-xs">
                  {t("common.completed")}
                </Badge>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
