import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Radar, Play, Trash2, Check } from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanProgress } from "@/components/scans/ScanProgress";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getScans, createScan, deleteScan, getScan, type Scan } from "@/services/api";

const scanModeKeys = ["quick", "standard", "deep", "full"] as const;
const scanModes = [
  { key: "scans.quickScan", mode: "quick", desc: "Port scan + basic vuln check", duration: "~5 phút" },
  { key: "scans.standardScan", mode: "standard", desc: "OWASP Top 10 + CVE mapping", duration: "~30 phút" },
  { key: "scans.deepScan", mode: "deep", desc: "Full crawl + payload injection", duration: "~2 giờ" },
  { key: "scans.fullScan", mode: "full", desc: "Subdomain + IP + full attack surface", duration: "~6 giờ" },
];

function modeLabel(mode: string): string {
  const map: Record<string, string> = { quick: "Quick Scan", standard: "Standard Scan", deep: "Deep Scan", full: "Full Scan" };
  return map[mode] ?? mode;
}

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString(); } catch { return iso; }
}

const SecurityScans = () => {
  const { t } = useLanguage();
  const queryClient = useQueryClient();
  const [selectedMode, setSelectedMode] = useState(0);
  const [hasSelectedMode, setHasSelectedMode] = useState(false);
  const [target, setTarget] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    refetchInterval: 10_000,
  });

  const startMutation = useMutation({
    mutationFn: () => createScan(target, scanModes[selectedMode].mode),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      setDialogOpen(false);
      setTarget("");
      setHasSelectedMode(false);
    },
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => deleteScan(scanId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["scans"] }),
  });

  const activeScans = scans.filter((s) => s.status === "running" || s.status === "queued" || s.status === "scanning");

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("scans.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">
            {isLoading ? "Loading..." : `${scans.length} scans total • ${activeScans.length} active`}
          </p>
        </div>
        <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2">
              <Plus className="h-4 w-4" />
              {t("scans.newScan")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>{t("scans.newScan")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-sm font-medium">Target</Label>
                <Input
                  placeholder="example.com"
                  className="mt-1.5 font-mono"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">Scan Mode</Label>
                <div className="grid grid-cols-2 gap-2">
                  {scanModes.map((mode, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        setSelectedMode(i);
                        setHasSelectedMode(true);
                      }}
                      className={cn(
                        "p-3 rounded-md border text-left transition-all relative",
                        hasSelectedMode && selectedMode === i
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      {hasSelectedMode && selectedMode === i && (
                        <span className="absolute top-2 right-2 text-blue-600">
                          <Check className="h-4 w-4" />
                        </span>
                      )}
                      <p className="text-sm font-medium">{t(mode.key)}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{mode.desc}</p>
                      <p className="text-xs text-muted-foreground mt-1 font-mono">{mode.duration}</p>
                    </button>
                  ))}
                </div>
              </div>
              <Button
                className={cn(
                  "w-full gap-2",
                  (!target.trim() || !hasSelectedMode) && "bg-muted text-muted-foreground hover:bg-muted"
                )}
                disabled={!target.trim() || !hasSelectedMode || startMutation.isPending}
                onClick={() => startMutation.mutate()}
              >
                <Play className="h-4 w-4" />
                {startMutation.isPending ? "Starting..." : "Start Scan"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Active Scan Progress */}
      {activeScans.length > 0 && (
        <div className="mb-6 space-y-4">
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
                Cancel
              </Button>
            </div>
          ))}
        </div>
      )}

      {/* Scan History */}
      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Mục tiêu</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Chế độ</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Trạng thái</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Tiến trình</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Ngày</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider"></th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 4 }).map((_, i) => (
                <tr key={i} className="border-b border-border">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
                  ))}
                </tr>
              ))
            ) : scans.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                  No scans yet — start your first scan above
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.scan_id} className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer">
                  <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{scan.scan_id.slice(0, 8)}</td>
                  <td className="px-4 py-3 font-mono font-medium">{scan.target}</td>
                  <td className="px-4 py-3 text-muted-foreground">{modeLabel(scan.mode)}</td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={cn(
                      "text-[10px] font-medium",
                      (scan.status === "running" || scan.status === "queued") ? "bg-primary/10 text-primary border-primary/20" :
                      scan.status === "completed" ? "bg-success/10 text-success border-success/20" :
                      scan.status === "failed" ? "bg-destructive/10 text-destructive border-destructive/20" :
                      "bg-muted text-muted-foreground border-border"
                    )}>
                      {scan.status === "running" && (
                        <span className="animate-pulse inline-block w-2 h-2 rounded-full bg-blue-500 mr-1.5" />
                      )}
                      {scan.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary rounded-full transition-all"
                          style={{ width: `${Math.round(scan.progress * 100)}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-muted-foreground">{Math.round(scan.progress * 100)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground text-xs">{formatDate(scan.created_at)}</td>
                  <td className="px-4 py-3">
                    {(scan.status === "running" || scan.status === "queued") && (
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 w-7 p-0 text-muted-foreground hover:text-destructive"
                        onClick={(e) => { e.stopPropagation(); cancelMutation.mutate(scan.scan_id); }}
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
