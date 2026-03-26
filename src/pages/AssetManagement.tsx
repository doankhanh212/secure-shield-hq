import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Search, Globe, Trash2, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getAssets, createAsset, deleteAsset } from "@/services/api";

function getRiskBarColor(score: number): string {
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  return "bg-emerald-500";
}

function getRiskTextColor(score: number): string {
  if (score >= 80) return "text-red-500";
  if (score >= 60) return "text-orange-500";
  if (score >= 40) return "text-yellow-500";
  return "text-emerald-500";
}

function StatusCell({ status }: { status: string }) {
  if (status === "active") {
    return (
      <span className="flex items-center gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0" />
        <span className="text-xs text-emerald-600 font-medium">Active</span>
      </span>
    );
  }
  if (status === "scanning") {
    return (
      <span className="flex items-center gap-1.5">
        <Loader2 className="w-3 h-3 text-[#06b6d4] animate-spin shrink-0" />
        <span className="text-xs text-[#06b6d4] font-medium">Scanning</span>
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5">
      <span className="w-1.5 h-1.5 rounded-full bg-muted-foreground/50 shrink-0" />
      <span className="text-xs text-muted-foreground">{status}</span>
    </span>
  );
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

  const { data: assets = [], isLoading, isError, refetch } = useQuery({
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
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("assets.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {isLoading ? "Đang tải..." : `${assets.length} tài sản đang giám sát`}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0">
              <Plus className="h-4 w-4" />
              {t("assets.addAsset")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Globe className="h-5 w-5 text-[#06b6d4]" />
                {t("assets.addAsset")}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-sm font-medium">{t("assets.domain")}</Label>
                <Input
                  value={newDomain}
                  onChange={(e) => setNewDomain(e.target.value)}
                  placeholder="example.com"
                  className="mt-1.5 font-mono"
                />
              </div>
              <div>
                <Label className="text-sm font-medium">{t("assets.ip")}</Label>
                <Input
                  value={newIp}
                  onChange={(e) => setNewIp(e.target.value)}
                  placeholder="203.0.113.42"
                  className="mt-1.5 font-mono"
                />
              </div>
              <div>
                <Label className="text-sm font-medium">{t("assets.cloud")}</Label>
                <Input
                  value={newCloud}
                  onChange={(e) => setNewCloud(e.target.value)}
                  placeholder="AWS / GCP / Azure"
                  className="mt-1.5"
                />
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
                className="w-full gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0"
                disabled={!newDomain.trim() || addMutation.isPending}
                onClick={() => addMutation.mutate()}
              >
                {addMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin" /> Đang thêm...</>
                ) : (
                  "Thêm tài sản"
                )}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Search */}
      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("common.search")}
            className="pl-9 h-9 bg-muted/40 border text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Error state */}
      {isError && (
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center mb-4">
          <p className="text-sm text-red-600">Đã xảy ra lỗi khi tải tài sản. Vui lòng thử lại.</p>
          <button
            className="mt-2 text-xs text-red-500 underline"
            onClick={() => void refetch()}
          >
            Thử lại
          </button>
        </div>
      )}

      {/* Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/20">
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Tên miền
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Trạng thái
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Cloud
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Công nghệ
                </th>
                <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">
                  Rủi ro
                </th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 4 }).map((_, i) => (
                  <tr key={i} className="border-b border-border">
                    {Array.from({ length: 6 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <Skeleton className="h-4 w-20" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan={6}>
                    {/* Empty state */}
                    <div className="text-center py-16">
                      <div className="w-12 h-12 mx-auto mb-4 bg-muted rounded-xl flex items-center justify-center">
                        <Globe className="w-6 h-6 text-muted-foreground" />
                      </div>
                      <h3 className="text-sm font-semibold mb-1">
                        {assets.length === 0 ? "Chưa có tài sản nào" : "Không tìm thấy kết quả"}
                      </h3>
                      <p className="text-sm text-muted-foreground mb-4">
                        {assets.length === 0
                          ? "Thêm domain hoặc chạy quét để tự động phát hiện"
                          : "Thử thay đổi từ khóa tìm kiếm"}
                      </p>
                      {assets.length === 0 && (
                        <button
                          className="bg-[#06b6d4] text-white px-4 py-2 rounded-lg text-sm hover:bg-[#0891b2] transition-colors"
                          onClick={() => setDialogOpen(true)}
                        >
                          + Thêm Tài sản
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map((asset) => (
                  <tr
                    key={asset.id}
                    className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer"
                  >
                    {/* Domain + IP */}
                    <td className="px-4 py-3">
                      <p className="font-mono text-sm font-medium">{asset.domain}</p>
                      {asset.ip && (
                        <p className="text-xs text-muted-foreground mt-0.5">{asset.ip}</p>
                      )}
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <StatusCell status={asset.status} />
                    </td>

                    {/* Cloud */}
                    <td className="px-4 py-3">
                      <span className="text-xs font-medium">{asset.cloud || "—"}</span>
                    </td>

                    {/* Technologies */}
                    <td className="px-4 py-3">
                      {asset.technologies && asset.technologies.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {asset.technologies.slice(0, 3).map((tech) => (
                            <span
                              key={tech}
                              className="px-2 py-0.5 rounded-full text-[10px] bg-muted text-muted-foreground border border-border"
                            >
                              {tech}
                            </span>
                          ))}
                          {asset.technologies.length > 3 && (
                            <span className="px-2 py-0.5 rounded-full text-[10px] bg-muted text-muted-foreground border border-border">
                              +{asset.technologies.length - 3}
                            </span>
                          )}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>

                    {/* Risk score */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn("h-full rounded-full transition-all", getRiskBarColor(asset.risk_score))}
                            style={{ width: `${asset.risk_score}%` }}
                          />
                        </div>
                        <span className={cn("text-xs font-mono font-semibold", getRiskTextColor(asset.risk_score))}>
                          {asset.risk_score}
                        </span>
                      </div>
                    </td>

                    {/* Delete */}
                    <td className="px-4 py-3">
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation();
                          removeMutation.mutate(asset.id);
                        }}
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
