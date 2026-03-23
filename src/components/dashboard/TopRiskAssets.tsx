import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { Shield } from "lucide-react";

interface TopRiskAssetsProps {
  assets: { domain: string; score: number; criticals: number; highs: number }[];
  isLoading?: boolean;
}

function getRiskColor(score: number) {
  if (score >= 80) return "text-destructive bg-destructive";
  if (score >= 60) return "text-warning bg-warning";
  if (score >= 40) return "text-info bg-info";
  return "text-success bg-success";
}

export function TopRiskAssets({ assets, isLoading }: TopRiskAssetsProps) {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.topRiskAssets")}</h3>
      <div className="space-y-3">
        {isLoading ? (
          [1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="flex-1 space-y-1">
                <Skeleton className="h-4 w-36" />
                <Skeleton className="h-3 w-16" />
              </div>
              <Skeleton className="h-4 w-24" />
            </div>
          ))
        ) : assets.length === 0 ? (
          <div className="rounded-lg border border-border bg-muted/30 px-4 py-8 text-center">
            <div className="h-12 w-12 rounded-full bg-card border border-border flex items-center justify-center mx-auto mb-3">
              <Shield className="h-5 w-5 text-muted-foreground" />
            </div>
            <p className="text-sm font-medium">Chưa có tài sản rủi ro cao</p>
            <p className="text-xs text-muted-foreground mt-1">Dữ liệu sẽ hiển thị sau khi có kết quả quét</p>
          </div>
        ) : (
          assets.map((asset) => {
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
          })
        )}
      </div>
    </div>
  );
}
