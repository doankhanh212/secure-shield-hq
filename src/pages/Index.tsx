import { useEffect, useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { useDashboardData } from "@/hooks/use-dashboard-data";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { SeverityChart } from "@/components/dashboard/SeverityChart";
import { PostureChart } from "@/components/dashboard/PostureChart";
import { RecentScans } from "@/components/dashboard/RecentScans";
import { AttackSurfaceOverview } from "@/components/dashboard/AttackSurfaceOverview";
import { ScanActivityTimeline } from "@/components/dashboard/ScanActivityTimeline";
import { TopRiskAssets } from "@/components/dashboard/TopRiskAssets";
import { Button } from "@/components/ui/button";
import { Server, ShieldAlert, Radar, TrendingUp, RefreshCcw } from "lucide-react";

const Overview = () => {
  const { t } = useLanguage();
  const dashboard = useDashboardData();
  const [now, setNow] = useState(Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, 1000);

    return () => {
      window.clearInterval(timer);
    };
  }, []);

  const secondsSinceLastUpdate = dashboard.lastUpdatedAt
    ? Math.max(0, Math.floor((now - dashboard.lastUpdatedAt) / 1000))
    : null;

  return (
    <DashboardLayout>
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("dashboard.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">Real-time security monitoring & threat analysis</p>
          <p className="text-xs text-muted-foreground mt-2">
            {secondsSinceLastUpdate === null
              ? "Last updated just now"
              : `Last updated ${secondsSinceLastUpdate} seconds ago`}
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => {
            void dashboard.refresh();
          }}
          disabled={dashboard.isFetching}
          className="shrink-0"
        >
          <RefreshCcw className={`h-4 w-4 mr-2 ${dashboard.isFetching ? "animate-spin" : ""}`} />
          Làm mới
        </Button>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <MetricCard
          title={t("dashboard.totalAssets")}
          value={dashboard.totalAssets}
          changeType="neutral"
          icon={Server}
          isLoading={dashboard.isLoading}
          accentClassName="border-l-primary"
        />
        <MetricCard
          title={t("dashboard.openVulns")}
          value={dashboard.openVulns}
          changeType="neutral"
          icon={ShieldAlert}
          iconColor="bg-destructive/10"
          isLoading={dashboard.isLoading}
          accentClassName="border-l-destructive"
        />
        <MetricCard
          title={t("dashboard.activeScans")}
          value={dashboard.activeScans}
          changeType="neutral"
          icon={Radar}
          iconColor="bg-warning/10"
          isLoading={dashboard.isLoading}
          accentClassName="border-l-success"
        />
        <MetricCard
          title={t("dashboard.riskScore")}
          value={`${dashboard.riskScore}/100`}
          changeType="neutral"
          icon={TrendingUp}
          iconColor="bg-success/10"
          isLoading={dashboard.isLoading}
          accentClassName="border-l-warning"
        />
      </div>

      {/* Attack Surface Overview */}
      <div className="mb-6">
        <AttackSurfaceOverview
          domains={dashboard.domains}
          subdomains={dashboard.subdomains}
          apis={dashboard.apis}
          ips={dashboard.ips}
          exposed={dashboard.exposed}
          isLoading={dashboard.isLoading}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2">
          <PostureChart data={dashboard.postureTrend} isLoading={dashboard.isLoading} />
        </div>
        <SeverityChart
          critical={dashboard.critical}
          high={dashboard.high}
          medium={dashboard.medium}
          low={dashboard.low}
          isLoading={dashboard.isLoading}
        />
      </div>

      {/* Activity & Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2">
          <ScanActivityTimeline data={dashboard.scanActivity} isLoading={dashboard.isLoading} />
        </div>
        <TopRiskAssets assets={dashboard.topRiskAssets} isLoading={dashboard.isLoading} />
      </div>

      {/* Recent Scans */}
      <RecentScans scans={dashboard.recentScans} isLoading={dashboard.isLoading} />
    </DashboardLayout>
  );
};

export default Overview;
