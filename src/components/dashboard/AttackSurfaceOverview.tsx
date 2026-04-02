import { useLanguage } from "@/hooks/use-language";
import { Globe, GitBranch, Wifi, Server, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useNavigate } from "react-router-dom";

interface AttackSurfaceOverviewProps {
  domains: number;
  subdomains: number;
  apis: number;
  ips: number;
  exposed: number;
  isLoading?: boolean;
}

export function AttackSurfaceOverview({ domains, subdomains, apis, ips, exposed, isLoading }: AttackSurfaceOverviewProps) {
  const { t } = useLanguage();
  const navigate = useNavigate();

  const allMetrics = [
    { key: "dashboard.domains", value: domains, icon: Globe, color: "text-primary", to: "/assets?type=domains", alwaysShow: true },
    { key: "dashboard.subdomains", value: subdomains, icon: GitBranch, color: "text-info", to: "/assets?type=subdomains", alwaysShow: true },
    { key: "dashboard.apis", value: apis, icon: Server, color: "text-success", to: "/assets?type=apis", alwaysShow: false },
    { key: "dashboard.ips", value: ips, icon: Wifi, color: "text-warning", to: "/assets?type=ips", alwaysShow: false },
    { key: "dashboard.exposed", value: exposed, icon: AlertTriangle, color: "text-destructive", to: "/assets?type=exposed", alwaysShow: false },
  ];

  const metrics = allMetrics.filter((m) => m.alwaysShow || m.value > 0);

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4 flex items-center gap-2">
        <Globe className="h-4 w-4 text-primary" />
        {t("dashboard.attackSurface")}
      </h3>
      <div className={cn("grid gap-3", {
        "grid-cols-2": metrics.length === 2,
        "grid-cols-3": metrics.length === 3,
        "grid-cols-4": metrics.length === 4,
        "grid-cols-5": metrics.length >= 5,
      })}>
        {metrics.map((m) => (
          <button
            key={m.key}
            type="button"
            onClick={() => {
              navigate(m.to);
            }}
            className="text-center p-3 rounded-lg bg-muted/50 border border-border/50 hover:border-primary/30 hover:bg-muted/70 transition-colors"
          >
            <m.icon className={cn("h-5 w-5 mx-auto mb-2", m.color)} />
            {isLoading ? (
              <Skeleton className="h-8 w-12 mx-auto" />
            ) : (
              <p className="text-2xl font-bold font-mono">{m.value}</p>
            )}
            <p className="text-[11px] text-muted-foreground mt-1">{t(m.key)}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
