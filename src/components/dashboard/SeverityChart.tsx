import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck } from "lucide-react";

interface SeverityChartProps {
  critical: number;
  high: number;
  medium: number;
  low: number;
  isLoading?: boolean;
}

export function SeverityChart({ critical, high, medium, low, isLoading }: SeverityChartProps) {
  const { t } = useLanguage();

  const severities = [
    { key: "dashboard.critical", count: critical, color: "bg-destructive", textColor: "text-destructive" },
    { key: "dashboard.high", count: high, color: "bg-warning", textColor: "text-warning" },
    { key: "dashboard.medium", count: medium, color: "bg-info", textColor: "text-info" },
    { key: "dashboard.low", count: low, color: "bg-success", textColor: "text-success" },
  ];

  const total = severities.reduce((s, i) => s + i.count, 0);

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.topVulnerabilities")}</h3>

      {isLoading ? (
        <div className="space-y-3">
          <Skeleton className="h-4 w-full rounded-full" />
          {[1, 2, 3, 4].map((i) => (
            <Skeleton key={i} className="h-5 w-full" />
          ))}
        </div>
      ) : total === 0 ? (
        <div className="py-8 px-4 rounded-lg border border-success/20 bg-success/5 text-center">
          <ShieldCheck className="h-8 w-8 text-success mx-auto mb-2" />
          <p className="text-sm font-medium text-success">Không có lỗ hổng nào được phát hiện</p>
        </div>
      ) : (
        <>
          {/* Donut-style horizontal bar */}
          <div className="flex h-4 rounded-full overflow-hidden mb-5 border border-border/50">
            {total > 0 &&
              severities.map((s) => (
                <div
                  key={s.key}
                  className={cn(s.color, "transition-all duration-500")}
                  style={{ width: `${(s.count / total) * 100}%` }}
                />
              ))}
          </div>

          <div className="space-y-3">
            {severities.map((s) => (
              <div key={s.key} className="flex items-center gap-3">
                <span className={cn("h-3 w-3 rounded-sm shrink-0", s.color)} />
                <span className="text-sm text-muted-foreground flex-1">{t(s.key)}</span>
                <span className={cn("text-sm font-bold font-mono", s.textColor)}>{s.count}</span>
                <span className="text-xs text-muted-foreground w-10 text-right">
                  {total > 0 ? Math.round((s.count / total) * 100) : 0}%
                </span>
              </div>
            ))}
          </div>

          <div className="mt-4 pt-4 border-t border-border">
            <div className="flex justify-between text-xs">
              <span className="text-muted-foreground">Total</span>
              <span className="font-bold font-mono">{total}</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
