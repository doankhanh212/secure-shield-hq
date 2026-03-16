import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";

const severities = [
  { key: "dashboard.critical", count: 12, color: "bg-destructive", textColor: "text-destructive" },
  { key: "dashboard.high", count: 34, color: "bg-warning", textColor: "text-warning" },
  { key: "dashboard.medium", count: 67, color: "bg-info", textColor: "text-info" },
  { key: "dashboard.low", count: 123, color: "bg-success", textColor: "text-success" },
];

export function SeverityChart() {
  const { t } = useLanguage();
  const total = severities.reduce((s, i) => s + i.count, 0);

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.topVulnerabilities")}</h3>
      
      {/* Donut-style horizontal bar */}
      <div className="flex h-4 rounded-full overflow-hidden mb-5 border border-border/50">
        {severities.map((s) => (
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
              {Math.round((s.count / total) * 100)}%
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
    </div>
  );
}
