import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { MetricCard } from "@/components/dashboard/MetricCard";
import { SeverityChart } from "@/components/dashboard/SeverityChart";
import { PostureChart } from "@/components/dashboard/PostureChart";
import { RecentScans } from "@/components/dashboard/RecentScans";
import { AttackSurfaceOverview } from "@/components/dashboard/AttackSurfaceOverview";
import { ScanActivityTimeline } from "@/components/dashboard/ScanActivityTimeline";
import { TopRiskAssets } from "@/components/dashboard/TopRiskAssets";
import { Server, ShieldAlert, Radar, TrendingUp } from "lucide-react";

const Overview = () => {
  const { t } = useLanguage();

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("dashboard.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">Real-time security monitoring & threat analysis</p>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-6">
        <MetricCard
          title={t("dashboard.totalAssets")}
          value={248}
          change="+12 tuần này"
          changeType="positive"
          icon={Server}
        />
        <MetricCard
          title={t("dashboard.openVulns")}
          value={236}
          change="-8 so với tuần trước"
          changeType="positive"
          icon={ShieldAlert}
          iconColor="bg-destructive/10"
        />
        <MetricCard
          title={t("dashboard.activeScans")}
          value={2}
          change="3 đang chờ"
          changeType="neutral"
          icon={Radar}
          iconColor="bg-warning/10"
        />
        <MetricCard
          title={t("dashboard.riskScore")}
          value="82/100"
          change="+6 điểm"
          changeType="positive"
          icon={TrendingUp}
          iconColor="bg-success/10"
        />
      </div>

      {/* Attack Surface Overview */}
      <div className="mb-6">
        <AttackSurfaceOverview />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2">
          <PostureChart />
        </div>
        <SeverityChart />
      </div>

      {/* Activity & Risk */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        <div className="lg:col-span-2">
          <ScanActivityTimeline />
        </div>
        <TopRiskAssets />
      </div>

      {/* Recent Scans */}
      <RecentScans />
    </DashboardLayout>
  );
};

export default Overview;
