import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { AssetIntelligencePanel } from "@/components/asset-intelligence/AssetIntelligencePanel";
import { Skeleton } from "@/components/ui/skeleton";
import { AlertTriangle, RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";
import { getScans, getAssetIntelligence, type AssetIntelligenceResponse } from "@/services/api";
import { cn } from "@/lib/utils";

// ── Empty state ───────────────────────────────────────────────────────────────

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-24 text-center">
      <div className="h-16 w-16 rounded-full bg-muted/40 border border-border flex items-center justify-center mb-4">
        <AlertTriangle className="h-7 w-7 text-muted-foreground/50" />
      </div>
      <p className="text-base font-semibold">No Asset Intelligence Data</p>
      <p className="text-sm text-muted-foreground mt-1 max-w-xs">
        Run a Standard or Deep scan to generate asset intelligence with technology fingerprinting and CVE enrichment.
      </p>
    </div>
  );
}

// ── Loading skeleton ──────────────────────────────────────────────────────────

function LoadingSkeleton() {
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-4 gap-3 mb-6">
        {[1, 2, 3, 4].map((i) => (
          <Skeleton key={i} className="h-16 rounded-lg" />
        ))}
      </div>
      <Skeleton className="h-10 w-full rounded-lg" />
      {[1, 2, 3, 4, 5].map((i) => (
        <Skeleton key={i} className="h-20 rounded-lg" />
      ))}
    </div>
  );
}

// ── Scan selector ─────────────────────────────────────────────────────────────

interface ScanSelectorProps {
  scanId: string;
  setScanId: (id: string) => void;
  scans: { scan_id: string; target: string; status: string; mode: string; created_at: string }[];
}

function ScanSelector({ scanId, setScanId, scans }: ScanSelectorProps) {
  const completed = scans.filter((s) => s.status === "completed");
  if (completed.length === 0) return null;

  return (
    <div className="flex items-center gap-2">
      <span className="text-xs text-muted-foreground">Scan:</span>
      <select
        value={scanId}
        onChange={(e) => setScanId(e.target.value)}
        className="h-8 rounded-lg border border-border bg-background px-3 text-xs text-foreground"
      >
        {completed.map((s) => {
          const date = new Date(s.created_at).toLocaleDateString("vi-VN");
          return (
            <option key={s.scan_id} value={s.scan_id}>
              {s.target} — {s.mode} — {date}
            </option>
          );
        })}
      </select>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

const AssetIntelligence = () => {
  const [selectedScanId, setSelectedScanId] = useState<string>("");

  // Load completed scans to populate selector
  const { data: scans = [] } = useQuery({
    queryKey: ["scans"],
    queryFn: getScans,
    staleTime: 60_000,
  });

  const completedScans = scans.filter((s) => s.status === "completed");

  // Auto-pick the most recent completed scan
  const activeScanId =
    selectedScanId ||
    (completedScans[0]?.scan_id ?? "");

  const {
    data,
    isLoading,
    isError,
    refetch,
    isFetching,
  } = useQuery<AssetIntelligenceResponse>({
    queryKey: ["asset-intelligence", activeScanId],
    queryFn: () => getAssetIntelligence(activeScanId),
    enabled: !!activeScanId,
    staleTime: 60_000,
    retry: 1,
  });

  return (
    <DashboardLayout>
      {/* Page header */}
      <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Asset Intelligence</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Per-host risk breakdown with technology fingerprinting and CVE enrichment
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ScanSelector
            scanId={activeScanId}
            setScanId={setSelectedScanId}
            scans={scans}
          />
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 text-xs"
            onClick={() => void refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isFetching && "animate-spin")} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Content */}
      {isLoading ? (
        <LoadingSkeleton />
      ) : isError || !data ? (
        completedScans.length === 0 ? (
          <EmptyState />
        ) : (
          <div className="bg-card rounded-lg border border-border py-16 text-center">
            <AlertTriangle className="h-8 w-8 text-orange-400/60 mx-auto mb-3" />
            <p className="text-sm font-medium">Asset intelligence not available for this scan</p>
            <p className="text-xs text-muted-foreground mt-1">
              This scan may predate the asset intelligence module. Run a new scan to generate data.
            </p>
          </div>
        )
      ) : data.assets.length === 0 ? (
        <EmptyState />
      ) : (
        <AssetIntelligencePanel data={data} />
      )}
    </DashboardLayout>
  );
};

export default AssetIntelligence;
