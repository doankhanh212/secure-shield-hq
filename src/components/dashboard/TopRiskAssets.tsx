import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";

const assets = [
  { domain: "admin.example.com", score: 94, criticals: 4, highs: 8 },
  { domain: "api.example.com", score: 78, criticals: 2, highs: 5 },
  { domain: "example.com", score: 65, criticals: 1, highs: 3 },
  { domain: "staging.example.com", score: 52, criticals: 1, highs: 2 },
  { domain: "cdn.example.com", score: 22, criticals: 0, highs: 1 },
];

function getRiskColor(score: number) {
  if (score >= 80) return "text-destructive bg-destructive";
  if (score >= 60) return "text-warning bg-warning";
  if (score >= 40) return "text-info bg-info";
  return "text-success bg-success";
}

export function TopRiskAssets() {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.topRiskAssets")}</h3>
      <div className="space-y-3">
        {assets.map((asset) => {
          const colors = getRiskColor(asset.score);
          return (
            <div key={asset.domain} className="flex items-center gap-3 group cursor-pointer">
              <div className="flex-1 min-w-0">
                <p className="text-sm font-mono font-medium truncate group-hover:text-primary transition-colors">
                  {asset.domain}
                </p>
                <div className="flex items-center gap-2 mt-1">
                  {asset.criticals > 0 && (
                    <span className="text-[10px] font-semibold text-destructive">{asset.criticals}C</span>
                  )}
                  <span className="text-[10px] font-semibold text-warning">{asset.highs}H</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                  <div
                    className={cn("h-full rounded-full transition-all", colors.split(" ")[1])}
                    style={{ width: `${asset.score}%` }}
                  />
                </div>
                <span className={cn("text-xs font-bold font-mono w-8 text-right", colors.split(" ")[0])}>
                  {asset.score}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
