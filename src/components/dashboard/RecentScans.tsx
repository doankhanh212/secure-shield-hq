import { useLanguage } from "@/hooks/use-language";
import { Badge } from "@/components/ui/badge";
import { Radar } from "lucide-react";

const scans = [
  { target: "example.com", type: "Deep Scan", status: "scanning", progress: 67, time: "12 phút trước" },
  { target: "api.example.com", type: "Quick Scan", status: "completed", progress: 100, time: "1 giờ trước" },
  { target: "staging.example.com", type: "Standard Scan", status: "scanning", progress: 34, time: "5 phút trước" },
  { target: "admin.example.com", type: "Full Scan", status: "completed", progress: 100, time: "3 giờ trước" },
];

export function RecentScans() {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.recentScans")}</h3>
      <div className="space-y-3">
        {scans.map((scan, i) => (
          <div key={i} className="flex items-center gap-3 py-2 border-b border-border last:border-0">
            <Radar className="h-4 w-4 text-muted-foreground shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium truncate font-mono">{scan.target}</p>
              <p className="text-xs text-muted-foreground">{scan.type} • {scan.time}</p>
            </div>
            {scan.status === "scanning" ? (
              <div className="flex items-center gap-2">
                <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                  <div className="h-full bg-primary rounded-full transition-all" style={{ width: `${scan.progress}%` }} />
                </div>
                <span className="text-xs text-muted-foreground">{scan.progress}%</span>
              </div>
            ) : (
              <Badge variant="secondary" className="text-xs">
                {t("common.completed")}
              </Badge>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
