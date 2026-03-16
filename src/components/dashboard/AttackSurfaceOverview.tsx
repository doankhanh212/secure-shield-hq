import { useLanguage } from "@/hooks/use-language";
import { Globe, GitBranch, Wifi, Server, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

const metrics = [
  { key: "dashboard.domains", value: 12, icon: Globe, color: "text-primary" },
  { key: "dashboard.subdomains", value: 87, icon: GitBranch, color: "text-info" },
  { key: "dashboard.apis", value: 34, icon: Server, color: "text-success" },
  { key: "dashboard.ips", value: 156, icon: Wifi, color: "text-warning" },
  { key: "dashboard.exposed", value: 8, icon: AlertTriangle, color: "text-destructive" },
];

export function AttackSurfaceOverview() {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
        <Globe className="h-4 w-4 text-primary" />
        {t("dashboard.attackSurface")}
      </h3>
      <div className="grid grid-cols-5 gap-3">
        {metrics.map((m) => (
          <div key={m.key} className="text-center p-3 rounded-lg bg-muted/50 border border-border/50 hover:border-primary/30 transition-colors">
            <m.icon className={cn("h-5 w-5 mx-auto mb-2", m.color)} />
            <p className="text-2xl font-bold font-mono">{m.value}</p>
            <p className="text-[11px] text-muted-foreground mt-1">{t(m.key)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
