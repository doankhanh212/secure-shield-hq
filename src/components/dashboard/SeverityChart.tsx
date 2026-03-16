import { useLanguage } from "@/hooks/use-language";

const severities = [
  { key: "dashboard.critical", count: 12, color: "bg-destructive" },
  { key: "dashboard.high", count: 34, color: "bg-warning" },
  { key: "dashboard.medium", count: 67, color: "bg-info" },
  { key: "dashboard.low", count: 123, color: "bg-muted-foreground" },
];

export function SeverityChart() {
  const { t } = useLanguage();
  const total = severities.reduce((s, i) => s + i.count, 0);

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.topVulnerabilities")}</h3>
      <div className="flex h-3 rounded-full overflow-hidden mb-4">
        {severities.map((s) => (
          <div key={s.key} className={cn(s.color)} style={{ width: `${(s.count / total) * 100}%` }} />
        ))}
      </div>
      <div className="grid grid-cols-2 gap-3">
        {severities.map((s) => (
          <div key={s.key} className="flex items-center gap-2">
            <span className={cn("h-2.5 w-2.5 rounded-sm", s.color)} />
            <span className="text-xs text-muted-foreground">{t(s.key)}</span>
            <span className="text-xs font-semibold ml-auto">{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function cn(...classes: string[]) {
  return classes.filter(Boolean).join(" ");
}
