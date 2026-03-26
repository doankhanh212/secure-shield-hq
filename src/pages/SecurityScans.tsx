import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Radar, Play, Trash2, Check, Clock, CheckCircle2, XCircle, Loader2, Lock } from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getScans, createScan, deleteScan, type Scan } from "@/services/api";

const scanModes = [
  {
    key: "scans.quickScan",
    mode: "quick",
    desc: "Port scan + basic vuln check",
    duration: "~5 phút",
    color: "cyan",
    disabled: false,
  },
  {
    key: "scans.standardScan",
    mode: "standard",
    desc: "OWASP Top 10 + CVE mapping",
    duration: "~30 phút",
    color: "blue",
    disabled: false,
  },
  {
    key: "scans.deepScan",
    mode: "deep",
    desc: "Full crawl + payload injection",
    duration: "~2 giờ",
    color: "violet",
    disabled: true,
  },
];

const modeColorMap: Record<string, string> = {
  quick: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  standard: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  deep: "bg-violet-500/10 text-violet-400 border-violet-500/30",
  full: "bg-orange-500/10 text-orange-400 border-orange-500/30",
};

const modeLabel: Record<string, string> = {
  quick: "Quick",
  standard: "Standard",
  deep: "Deep",
  full: "Full",
};

const cardBorderMap: Record<string, string> = {
  cyan: "border-cyan-500/40 bg-cyan-500/5",
  blue: "border-blue-500/40 bg-blue-500/5",
  violet: "border-violet-500/20 bg-muted/30",
};

const cardSelectedMap: Record<string, string> = {
  cyan: "border-cyan-400 bg-cyan-500/10",
  blue: "border-blue-400 bg-blue-500/10",
  violet: "",
};

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("vi-VN", { day: "2-digit", month: "2-digit", year: "numeric" });
  } catch {
    return iso;
  }
}

function StatusBadge({ status }: { status: string }) {
  if (status === "running" || status === "scanning") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-blue-400">
        <Loader2 className="h-3 w-3 animate-spin" />
        Đang quét
      </span>
    );
  }
  if (status === "queued") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-amber-400">
        <Clock className="h-3 w-3" />
        Chờ xử lý
      </span>
    );
  }
  if (status === "completed") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-emerald-400">
        <CheckCircle2 className="h-3 w-3" />
        Hoàn thành
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-red-400">
        <XCircle className="h-3 w-3" />
        Thất bại
      </span>
    );
  }
  return (
    <span className="text-[11px] text-muted-foreground">{status}</span>
  );
}

const SecurityScans = () => {
  const { t } = useLanguage();
  const queryClient = useQueryClient();
  const [selectedMode, setSelectedMode] = useState<number | null>(null);
  const [target, setTarget] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    refetchInterval: 10_000,
  });

  const startMutation = useMutation({
    mutationFn: () => createScan(target, scanModes[selectedMode!].mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setDialogOpen(false);
      setTarget("");
      setSelectedMode(null);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => deleteScan(scanId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const activeScans = scans.filter(
    (s) => s.status === "running" || s.status === "queued" || s.status === "scanning"
  );

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("scans.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {isLoading
              ? "Đang tải..."
              : `${scans.length} lần quét • ${activeScans.length} đang hoạt động`}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0">
              <Plus className="h-4 w-4" />
              {t("scans.newScan")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Radar className="h-5 w-5 text-[#06b6d4]" />
                {t("scans.newScan")}
              </DialogTitle>
            </DialogHeader>
            <div className="space-y-5 mt-2">
              <div>
                <Label className="text-sm font-medium mb-1.5 block">Target</Label>
                <Input
                  placeholder="example.com hoặc 192.168.1.0/24"
                  className="font-mono text-sm"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">Chế độ quét</Label>
                <div className="grid grid-cols-1 gap-2.5">
                  {scanModes.map((mode, i) => (
                    <button
                      key={i}
                      disabled={mode.disabled}
                      onClick={() => !mode.disabled && setSelectedMode(i)}
                      className={cn(
                        "relative p-3.5 rounded-lg border text-left transition-all",
                        mode.disabled
                          ? "opacity-60 cursor-not-allowed " + cardBorderMap[mode.color]
                          : selectedMode === i
                          ? cardSelectedMap[mode.color] + " " + "border-2"
                          : cardBorderMap[mode.color] + " hover:brightness-110 cursor-pointer"
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="flex-1">
                          <p className="text-sm font-semibold">{t(mode.key)}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{mode.desc}</p>
                          <p className="text-xs font-mono text-muted-foreground mt-1">{mode.duration}</p>
                        </div>
                        <div className="flex flex-col items-end gap-1.5 shrink-0">
                          {mode.disabled ? (
                            <span className="inline-flex items-center gap-1 text-[10px] font-medium bg-muted/80 text-muted-foreground border border-border rounded px-1.5 py-0.5">
                              <Lock className="h-2.5 w-2.5" />
                              Sắp ra mắt
                            </span>
                          ) : (
                            selectedMode === i && (
                              <Check className={cn("h-4 w-4", mode.color === "cyan" ? "text-cyan-400" : "text-blue-400")} />
                            )
                          )}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
              <Button
                className="w-full gap-2 bg-[#06b6d4] hover:bg-[#0891b2] text-white border-0"
                disabled={!target.trim() || selectedMode === null || startMutation.isPending}
                onClick={() => startMutation.mutate()}
              >
                {startMutation.isPending ? (
                  <><Loader2 className="h-4 w-4 animate-spin" /> Đang khởi động...</>
                ) : (
                  <><Play className="h-4 w-4" /> Bắt đầu quét</>
                )}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Active Scan Progress */}
      {activeScans.length > 0 && (
        <div className="mb-6 space-y-3">
          {activeScans.map((scan) => (
            <div key={scan.scan_id} className="relative">
              <ScanProgress
                target={scan.target}
                scanId={scan.scan_id}
                scanMode={scan.mode}
                startedAt={scan.created_at}
              />
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-3 right-3 h-7 text-xs text-muted-foreground hover:text-destructive"
                onClick={() => cancelMutation.mutate(scan.scan_id)}
              >
                Hủy
              </Button>
            </div>
          ))}
        </div>
      )}

      {/* Scan History Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">Mục tiêu</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">Chế độ</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">Trạng thái</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">Tiến trình</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-[11px] uppercase tracking-wider">Ngày</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={i} className="border-b border-border">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="px-4 py-3">
                      <Skeleton className="h-4 w-16" />
                    </td>
                  ))}
                </tr>
              ))
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-16 text-center">
                  <Radar className="h-8 w-8 text-muted-foreground/40 mx-auto mb-3" />
                  <p className="text-muted-foreground text-sm">Chưa có lần quét nào — bắt đầu lần quét đầu tiên</p>
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr
                  key={scan.scan_id}
                  className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                    {scan.scan_id.slice(0, 8)}
                  </td>
                  <td className="px-4 py-3 font-mono font-medium text-sm">{scan.target}</td>
                  <td className="px-4 py-3">
                    <Badge
                      variant="outline"
                      className={cn(
                        "text-[10px] font-semibold px-2 py-0.5",
                        modeColorMap[scan.mode] ?? "bg-muted text-muted-foreground border-border"
                      )}
                    >
                      {modeLabel[scan.mode] ?? scan.mode}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={scan.status} />
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2 min-w-[80px]">
                      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className={cn(
                            "h-full rounded-full transition-all",
                            scan.status === "completed" ? "bg-emerald-500" :
                            scan.status === "failed" ? "bg-red-500" :
                            "bg-[#06b6d4]"
                          )}
                          style={{ width: `${Math.round(scan.progress * 100)}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-muted-foreground w-8 text-right">
                        {Math.round(scan.progress * 100)}%
                      </span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground text-xs">{formatDate(scan.created_at)}</td>
                  <td className="px-4 py-3">
                    {(scan.status === "running" || scan.status === "queued" || scan.status === "scanning") && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        onClick={() => cancelMutation.mutate(scan.scan_id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default SecurityScans;
