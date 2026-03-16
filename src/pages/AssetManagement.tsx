import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Search, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

const assets = [
  { domain: "example.com", ip: "203.0.113.42", type: "Web App", status: "active", lastScan: "2024-01-15", vulns: { critical: 2, high: 5, medium: 12 }, tech: ["React", "Nginx", "Node.js"], ports: [80, 443, 8080], cloud: "AWS", riskScore: 72, exposure: "Public" },
  { domain: "api.example.com", ip: "203.0.113.43", type: "API", status: "active", lastScan: "2024-01-14", vulns: { critical: 0, high: 3, medium: 8 }, tech: ["FastAPI", "PostgreSQL"], ports: [443, 5432], cloud: "AWS", riskScore: 58, exposure: "Public" },
  { domain: "staging.example.com", ip: "10.0.1.15", type: "Web App", status: "scanning", lastScan: "2024-01-15", vulns: { critical: 1, high: 2, medium: 5 }, tech: ["React", "Docker"], ports: [443, 3000], cloud: "GCP", riskScore: 45, exposure: "Internal" },
  { domain: "admin.example.com", ip: "203.0.113.50", type: "Admin Panel", status: "active", lastScan: "2024-01-13", vulns: { critical: 4, high: 8, medium: 15 }, tech: ["Vue.js", "Django"], ports: [80, 443, 8443], cloud: "Azure", riskScore: 94, exposure: "Public" },
  { domain: "cdn.example.com", ip: "104.16.132.229", type: "CDN", status: "inactive", lastScan: "2024-01-10", vulns: { critical: 0, high: 1, medium: 3 }, tech: ["CloudFront"], ports: [443], cloud: "AWS", riskScore: 18, exposure: "Public" },
  { domain: "mail.example.com", ip: "203.0.113.55", type: "Mail Server", status: "active", lastScan: "2024-01-12", vulns: { critical: 0, high: 0, medium: 2 }, tech: ["Postfix"], ports: [25, 465, 587], cloud: "On-Prem", riskScore: 31, exposure: "Public" },
];

const statusStyles: Record<string, string> = {
  active: "bg-success/10 text-success border-success/20",
  scanning: "bg-primary/10 text-primary border-primary/20",
  inactive: "bg-muted text-muted-foreground border-border",
};

const exposureStyles: Record<string, string> = {
  Public: "bg-warning/10 text-warning border-warning/20",
  Internal: "bg-info/10 text-info border-info/20",
};

function getRiskColor(score: number) {
  if (score >= 80) return "text-destructive";
  if (score >= 60) return "text-warning";
  if (score >= 40) return "text-info";
  return "text-success";
}

const AssetManagement = () => {
  const { t } = useLanguage();

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("assets.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{assets.length} assets monitored</p>
        </div>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          {t("assets.addAsset")}
        </Button>
      </div>

      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t("common.search")} className="pl-9 h-9 bg-muted/50 border text-sm" />
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.domain")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.ip")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.status")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.cloud")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.ports")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.exposure")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.vulns")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.risk")}</th>
              </tr>
            </thead>
            <tbody>
              {assets.map((asset, i) => (
                <tr key={i} className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium">{asset.domain}</span>
                      <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100" />
                    </div>
                    <div className="flex gap-1 mt-1">
                      {asset.tech.slice(0, 2).map((tech) => (
                        <Badge key={tech} variant="outline" className="text-[10px] px-1.5 py-0">{tech}</Badge>
                      ))}
                      {asset.tech.length > 2 && <Badge variant="outline" className="text-[10px] px-1.5 py-0">+{asset.tech.length - 2}</Badge>}
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{asset.ip}</td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={cn("text-[10px] font-medium", statusStyles[asset.status])}>
                      {asset.status === "scanning" && <span className="h-1.5 w-1.5 rounded-full bg-primary animate-scan-pulse mr-1" />}
                      {asset.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs font-medium">{asset.cloud}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-muted-foreground">{asset.ports.join(", ")}</span>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={cn("text-[10px]", exposureStyles[asset.exposure])}>
                      {asset.exposure}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5 font-mono text-xs">
                      {asset.vulns.critical > 0 && <span className="text-destructive font-bold">{asset.vulns.critical}C</span>}
                      {asset.vulns.high > 0 && <span className="text-warning font-bold">{asset.vulns.high}H</span>}
                      <span className="text-muted-foreground">{asset.vulns.medium}M</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={cn("h-full rounded-full", asset.riskScore >= 80 ? "bg-destructive" : asset.riskScore >= 60 ? "bg-warning" : asset.riskScore >= 40 ? "bg-info" : "bg-success")}
                          style={{ width: `${asset.riskScore}%` }}
                        />
                      </div>
                      <span className={cn("text-xs font-bold font-mono", getRiskColor(asset.riskScore))}>{asset.riskScore}</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AssetManagement;
