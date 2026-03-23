import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Search, ExternalLink, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getAssets, createAsset, deleteAsset, type Asset } from "@/services/api";

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
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [newIp, setNewIp] = useState("");
  const [newCloud, setNewCloud] = useState("");
  const [newExposure, setNewExposure] = useState("Public");

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ["assets"],
    queryFn: getAssets,
  });

  const addMutation = useMutation({
    mutationFn: () =>
      createAsset({
        domain: newDomain,
        ip: newIp,
        cloud: newCloud,
        status: "active",
        exposure: newExposure,
        open_ports: [],
        technologies: [],
        risk_score: 0,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["assets"] });
      setDialogOpen(false);
      setNewDomain("");
      setNewIp("");
      setNewCloud("");
      setNewExposure("Public");
    },
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["assets"] }),
  });

  const filtered = assets.filter(
    (a) =>
      !search ||
      a.domain.toLowerCase().includes(search.toLowerCase()) ||
      a.ip.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("assets.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {isLoading ? "Loading..." : `${assets.length} assets monitored`}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2">
              <Plus className="h-4 w-4" />
              {t("assets.addAsset")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>{t("assets.addAsset")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-sm font-medium">{t("assets.domain")}</Label>
                <Input value={newDomain} onChange={(e) => setNewDomain(e.target.value)} placeholder="example.com" className="mt-1.5 font-mono" />
              </div>
              <div>
                <Label className="text-sm font-medium">{t("assets.ip")}</Label>
                <Input value={newIp} onChange={(e) => setNewIp(e.target.value)} placeholder="203.0.113.42" className="mt-1.5 font-mono" />
              </div>
              <div>
                <Label className="text-sm font-medium">{t("assets.cloud")}</Label>
                <Input value={newCloud} onChange={(e) => setNewCloud(e.target.value)} placeholder="AWS / GCP / Azure" className="mt-1.5" />
              </div>
              <div>
                <Label className="text-sm font-medium">{t("assets.exposure")}</Label>
                <div className="flex gap-2 mt-1.5">
                  {["Public", "Internal"].map((v) => (
                    <Button
                      key={v}
                      type="button"
                      variant={newExposure === v ? "default" : "outline"}
                      size="sm"
                      onClick={() => setNewExposure(v)}
                    >
                      {v}
                    </Button>
                  ))}
                </div>
              </div>
              <Button
                className="w-full"
                disabled={!newDomain.trim() || addMutation.isPending}
                onClick={() => addMutation.mutate()}
              >
                {addMutation.isPending ? "Creating..." : "Add Asset"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("common.search")}
            className="pl-9 h-9 bg-muted/50 border text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
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
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("assets.risk")}</th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider"></th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="border-b border-border">
                    {Array.from({ length: 8 }).map((_, j) => (
                      <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-muted-foreground">
                    {assets.length === 0 ? "No assets discovered yet" : "No matching assets"}
                  </td>
                </tr>
              ) : (
                filtered.map((asset) => (
                  <tr key={asset.id} className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">{asset.domain}</span>
                        <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100" />
                      </div>
                      {asset.technologies.length > 0 && (
                        <div className="flex gap-1 mt-1">
                          {asset.technologies.slice(0, 2).map((tech) => (
                            <Badge key={tech} variant="outline" className="text-[10px] px-1.5 py-0">{tech}</Badge>
                          ))}
                          {asset.technologies.length > 2 && (
                            <Badge variant="outline" className="text-[10px] px-1.5 py-0">+{asset.technologies.length - 2}</Badge>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{asset.ip || "—"}</td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={cn("text-[10px] font-medium", statusStyles[asset.status] ?? statusStyles.active)}>
                        {asset.status === "scanning" && <span className="h-1.5 w-1.5 rounded-full bg-primary animate-scan-pulse mr-1" />}
                        {asset.status}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-xs font-medium">{asset.cloud || "—"}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-xs text-muted-foreground">
                        {asset.open_ports.length > 0 ? asset.open_ports.join(", ") : "—"}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={cn("text-[10px]", exposureStyles[asset.exposure] ?? "")}>
                        {asset.exposure}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-muted rounded-full overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", asset.risk_score >= 80 ? "bg-destructive" : asset.risk_score >= 60 ? "bg-warning" : asset.risk_score >= 40 ? "bg-info" : "bg-success")}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className={cn("text-xs font-bold font-mono", getRiskColor(asset.risk_score))}>{asset.risk_score}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        onClick={(e) => { e.stopPropagation(); removeMutation.mutate(asset.id); }}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default AssetManagement;
