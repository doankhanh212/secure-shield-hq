import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Plus, Search, ExternalLink } from "lucide-react";
import { cn } from "@/lib/utils";

const assets = [
  { domain: "example.com", type: "Web App", status: "active", lastScan: "2024-01-15", vulns: { critical: 2, high: 5, medium: 12 }, tech: ["React", "Nginx", "Node.js"] },
  { domain: "api.example.com", type: "API", status: "active", lastScan: "2024-01-14", vulns: { critical: 0, high: 3, medium: 8 }, tech: ["FastAPI", "PostgreSQL"] },
  { domain: "staging.example.com", type: "Web App", status: "scanning", lastScan: "2024-01-15", vulns: { critical: 1, high: 2, medium: 5 }, tech: ["React", "Docker"] },
  { domain: "admin.example.com", type: "Admin Panel", status: "active", lastScan: "2024-01-13", vulns: { critical: 4, high: 8, medium: 15 }, tech: ["Vue.js", "Django"] },
  { domain: "cdn.example.com", type: "CDN", status: "inactive", lastScan: "2024-01-10", vulns: { critical: 0, high: 1, medium: 3 }, tech: ["CloudFront"] },
  { domain: "mail.example.com", type: "Mail Server", status: "active", lastScan: "2024-01-12", vulns: { critical: 0, high: 0, medium: 2 }, tech: ["Postfix"] },
];

const statusStyles: Record<string, string> = {
  active: "bg-success/10 text-success",
  scanning: "bg-primary/10 text-primary",
  inactive: "bg-muted text-muted-foreground",
};

const AssetManagement = () => {
  const { t } = useLanguage();

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("assets.title")}</h1>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          {t("assets.addAsset")}
        </Button>
      </div>

      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t("common.search")} className="pl-9 h-9 bg-card border text-sm" />
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">{t("assets.domain")}</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">{t("assets.type")}</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">{t("assets.status")}</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">Tech</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">{t("assets.vulns")}</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">{t("assets.lastScan")}</th>
            </tr>
          </thead>
          <tbody>
            {assets.map((asset, i) => (
              <tr key={i} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors cursor-pointer">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-medium">{asset.domain}</span>
                    <ExternalLink className="h-3 w-3 text-muted-foreground" />
                  </div>
                </td>
                <td className="px-4 py-3 text-muted-foreground">{asset.type}</td>
                <td className="px-4 py-3">
                  <Badge variant="secondary" className={cn("text-xs font-medium", statusStyles[asset.status])}>
                    {asset.status === "scanning" && <span className="h-1.5 w-1.5 rounded-full bg-primary animate-scan-pulse mr-1.5" />}
                    {asset.status}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-1 flex-wrap">
                    {asset.tech.slice(0, 2).map((tech) => (
                      <Badge key={tech} variant="outline" className="text-xs">{tech}</Badge>
                    ))}
                    {asset.tech.length > 2 && <Badge variant="outline" className="text-xs">+{asset.tech.length - 2}</Badge>}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2 font-mono text-xs">
                    {asset.vulns.critical > 0 && <span className="text-destructive font-semibold">{asset.vulns.critical}C</span>}
                    {asset.vulns.high > 0 && <span className="text-warning font-semibold">{asset.vulns.high}H</span>}
                    <span className="text-muted-foreground">{asset.vulns.medium}M</span>
                  </div>
                </td>
                <td className="px-4 py-3 text-muted-foreground text-xs">{asset.lastScan}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default AssetManagement;
