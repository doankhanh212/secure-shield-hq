import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getDashboardStats,
  getDashboardPosture,
  getDashboardTopRisks,
  getScans,
  type Scan,
} from "@/services/api";

export interface DashboardData {
  totalAssets: number;
  openVulns: number;
  activeScans: number;
  riskScore: number;

  critical: number;
  high: number;
  medium: number;
  low: number;

  domains: number;
  subdomains: number;
  apis: number;
  ips: number;
  exposed: number;

  recentScans: Scan[];

  topRiskAssets: {
    domain: string;
    score: number;
    criticals: number;
    highs: number;
  }[];

  scanActivity: { day: string; scans: number; vulns: number }[];

  postureTrend: { label: string; score: number }[];

  isLoading: boolean;
  isFetching: boolean;
  lastUpdatedAt: number | null;
  refresh: () => Promise<void>;
}

export function useDashboardData(): DashboardData {
  const queryClient = useQueryClient();

  const dashboardQuery = useQuery({
    queryKey: ["dashboard-data"],
    queryFn: async () => {
      const [stats, posture, topRisks, scans] = await Promise.all([
        getDashboardStats(),
        getDashboardPosture(),
        getDashboardTopRisks(),
        getScans(),
      ]);
      return { stats, posture, topRisks, scans };
    },
    refetchInterval: 30_000,
    refetchIntervalInBackground: true,
  });

  useEffect(() => {
    return () => {
      queryClient.cancelQueries({ queryKey: ["dashboard-data"] });
    };
  }, [queryClient]);

  const isLoading = dashboardQuery.isLoading;
  const stats = dashboardQuery.data?.stats;
  const posture = dashboardQuery.data?.posture;
  const topRisks = dashboardQuery.data?.topRisks;
  const scans = dashboardQuery.data?.scans ?? [];

  // Map backend stats fields to DashboardData shape
  const totalAssets = stats?.total_assets ?? 0;
  const openVulns = stats?.open_vulnerabilities ?? 0;
  const activeScans = stats?.active_scans ?? 0;
  const riskScore = stats?.risk_score ?? 0;
  const critical = stats?.critical_count ?? 0;
  const high = stats?.high_count ?? 0;
  const medium = stats?.medium_count ?? 0;
  const low = stats?.low_count ?? 0;
  const domains = stats?.domains ?? 0;
  const subdomains = stats?.subdomains ?? 0;
  const apis = stats?.api_endpoints ?? 0;
  const ips = stats?.ips ?? 0;
  const exposed = stats?.exposed_services ?? 0;

  const topRiskAssets = (topRisks?.assets ?? []).map((a) => ({
    domain: a.domain,
    score: a.score,
    criticals: a.critical_count,
    highs: a.high_count,
  }));

  const postureTrend = posture?.trend ?? [];

  // Scan activity derived from recent scans list (unchanged shape)
  const dayMap = new Map<string, { scans: number; vulns: number }>();
  for (const scan of scans) {
    const day = new Date(scan.created_at).toLocaleDateString("vi-VN", {
      weekday: "short",
    });
    const entry = dayMap.get(day) ?? { scans: 0, vulns: 0 };
    entry.scans++;
    dayMap.set(day, entry);
  }
  const scanActivity = Array.from(dayMap.entries())
    .map(([day, d]) => ({ day, ...d }))
    .slice(0, 7);

  const refresh = async () => {
    await dashboardQuery.refetch();
  };

  return {
    totalAssets,
    openVulns,
    activeScans,
    riskScore,
    critical,
    high,
    medium,
    low,
    domains,
    subdomains,
    apis,
    ips,
    exposed,
    recentScans: scans.slice(0, 5),
    topRiskAssets,
    scanActivity,
    postureTrend,
    isLoading,
    isFetching: dashboardQuery.isFetching,
    lastUpdatedAt: dashboardQuery.dataUpdatedAt || null,
    refresh,
  };
}


