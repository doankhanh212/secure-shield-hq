import { useState } from "react";
import { Shield, ChevronRight, Bug, AlertTriangle, Cpu, Search, SlidersHorizontal } from "lucide-react";
import { cn } from "@/lib/utils";
import { Input } from "@/components/ui/input";
import { RiskBar, getRiskLevel, RISK_CONFIG } from "./RiskBar";
import { ConfidenceBadge } from "./ConfidenceBadge";
import { AssetDetailDrawer } from "./AssetDetailDrawer";
import type { AssetIntelligenceItem, AssetIntelligenceResponse } from "@/services/api";

// ── Summary strip ─────────────────────────────────────────────────────────────

function GlobalSummary({ data }: { data: AssetIntelligenceResponse }) {
  const stats = [
    {
      label: "Total Assets",
      value: data.total_assets,
      color: "text-foreground",
      bg: "bg-muted/40",
    },
    {
      label: "Critical",
      value: data.critical_assets,
      color: "text-red-400",
      bg: "bg-red-500/10",
    },
    {
      label: "High Risk",
      value: data.high_risk_assets,
      color: "text-orange-400",
      bg: "bg-orange-500/10",
    },
    {
      label: "Total CVEs",
      value: data.total_cves,
      color: "text-yellow-400",
      bg: "bg-yellow-500/10",
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
      {stats.map((s) => (
        <div
          key={s.label}
          className={cn("rounded-lg border border-border px-4 py-3", s.bg)}
        >
          <p className={cn("text-2xl font-bold font-mono", s.color)}>{s.value}</p>
          <p className="text-xs text-muted-foreground mt-0.5">{s.label}</p>
        </div>
      ))}
    </div>
  );
}

// ── Asset row ─────────────────────────────────────────────────────────────────

function AssetRow({
  asset,
  onClick,
}: {
  asset: AssetIntelligenceItem;
  onClick: () => void;
}) {
  const level = getRiskLevel(asset.risk_score);
  const cfg = RISK_CONFIG[level];

  // Count confirmed vulns for quick read
  const confirmed = asset.vulnerabilities.filter((v) => v.confidence === "confirmed").length;
  const criticalVulns = asset.vulnerabilities.filter(
    (v) => v.severity?.toLowerCase() === "critical"
  ).length;
  const highVulns = asset.vulnerabilities.filter(
    (v) => v.severity?.toLowerCase() === "high"
  ).length;

  // Top confidence of any finding for the row-level badge
  const topConfidence = (() => {
    const order = ["confirmed", "high", "medium", "low"];
    return asset.vulnerabilities.reduce<string>((best, v) => {
      const vi = order.indexOf(v.confidence?.toLowerCase());
      const bi = order.indexOf(best);
      return vi !== -1 && vi < bi ? v.confidence.toLowerCase() : best;
    }, "low");
  })();

  return (
    <button
      onClick={onClick}
      className="w-full text-left bg-card border border-border rounded-lg px-5 py-4 hover:border-[#06b6d4]/40 hover:shadow-md transition-all duration-200 group"
    >
      <div className="flex items-center gap-4">
        {/* Risk level indicator */}
        <div
          className={cn(
            "w-1.5 h-12 rounded-full shrink-0",
            level === "critical" && "bg-red-500",
            level === "high" && "bg-orange-500",
            level === "medium" && "bg-yellow-500",
            level === "low" && "bg-green-500"
          )}
        />

        {/* Host + badge */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1.5">
            <span
              className={cn(
                "text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase tracking-wide shrink-0",
                cfg.badge
              )}
            >
              {cfg.label}
            </span>
            <span className="font-mono font-semibold text-sm truncate">{asset.host}</span>
            {confirmed > 0 && (
              <ConfidenceBadge confidence="confirmed" className="shrink-0" />
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-muted-foreground flex-wrap">
            {asset.vulnerabilities.length > 0 && (
              <span className="flex items-center gap-1">
                <Bug className="h-3 w-3" />
                {asset.vulnerabilities.length} vuln{asset.vulnerabilities.length !== 1 ? "s" : ""}
                {criticalVulns > 0 && (
                  <span className="text-red-400 font-semibold ml-1">{criticalVulns}C</span>
                )}
                {highVulns > 0 && (
                  <span className="text-orange-400 font-semibold ml-1">{highVulns}H</span>
                )}
              </span>
            )}
            {asset.cves.length > 0 && (
              <span className="flex items-center gap-1">
                <AlertTriangle className="h-3 w-3" />
                {asset.cves.length} CVE{asset.cves.length !== 1 ? "s" : ""}
              </span>
            )}
            {asset.technologies.length > 0 && (
              <span className="flex items-center gap-1">
                <Cpu className="h-3 w-3" />
                {asset.technologies
                  .slice(0, 3)
                  .map((t) => (t.version ? `${t.name} ${t.version}` : t.name))
                  .join(", ")}
                {asset.technologies.length > 3 && (
                  <span className="text-muted-foreground/60">+{asset.technologies.length - 3}</span>
                )}
              </span>
            )}
          </div>
        </div>

        {/* Risk bar + chevron */}
        <div className="flex items-center gap-3 shrink-0">
          <div className="w-28 hidden sm:block">
            <RiskBar score={asset.risk_score} showLabel={false} />
          </div>
          <ChevronRight className="h-4 w-4 text-muted-foreground group-hover:text-[#06b6d4] transition-colors" />
        </div>
      </div>
    </button>
  );
}

// ── Filter bar ────────────────────────────────────────────────────────────────

type RiskFilter = "all" | "critical" | "high" | "medium" | "low";
type ConfFilter = "all" | "confirmed" | "high" | "medium" | "low";

const RISK_FILTERS: { value: RiskFilter; label: string }[] = [
  { value: "all", label: "All" },
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
];

const CONF_FILTERS: { value: ConfFilter; label: string }[] = [
  { value: "all", label: "All confidence" },
  { value: "confirmed", label: "Confirmed" },
  { value: "high", label: "High conf" },
  { value: "medium", label: "Medium conf" },
  { value: "low", label: "Low conf" },
];

// ── Main panel ────────────────────────────────────────────────────────────────

interface AssetIntelligencePanelProps {
  data: AssetIntelligenceResponse;
}

export function AssetIntelligencePanel({ data }: AssetIntelligencePanelProps) {
  const [selectedAsset, setSelectedAsset] = useState<AssetIntelligenceItem | null>(null);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [confFilter, setConfFilter] = useState<ConfFilter>("all");

  // Sort by risk_score DESC (already should be from backend, but enforce)
  const sorted = [...data.assets].sort((a, b) => b.risk_score - a.risk_score);

  // Apply filters
  const filtered = sorted.filter((asset) => {
    if (search && !asset.host.toLowerCase().includes(search.toLowerCase())) return false;
    if (riskFilter !== "all" && getRiskLevel(asset.risk_score) !== riskFilter) return false;
    if (confFilter !== "all") {
      const hasConf = asset.vulnerabilities.some(
        (v) => v.confidence?.toLowerCase() === confFilter
      );
      if (!hasConf) return false;
    }
    return true;
  });

  return (
    <div>
      <GlobalSummary data={data} />

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3 mb-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search host..."
            className="pl-9 h-9 w-56 bg-muted/40 text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Risk level filter */}
        <div className="flex items-center gap-0.5 bg-muted/40 rounded-lg p-1 border border-border">
          {RISK_FILTERS.map((f) => (
            <button
              key={f.value}
              onClick={() => setRiskFilter(f.value)}
              className={cn(
                "px-3 py-1 rounded-md text-xs font-medium transition-all",
                riskFilter === f.value
                  ? "bg-card shadow-sm text-foreground border border-border"
                  : "text-muted-foreground hover:text-foreground"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>

        {/* Confidence filter */}
        <div className="flex items-center gap-1.5">
          <SlidersHorizontal className="h-3.5 w-3.5 text-muted-foreground" />
          <select
            value={confFilter}
            onChange={(e) => setConfFilter(e.target.value as ConfFilter)}
            className="h-9 rounded-lg border border-border bg-background px-3 text-xs text-muted-foreground"
          >
            {CONF_FILTERS.map((f) => (
              <option key={f.value} value={f.value}>
                {f.label}
              </option>
            ))}
          </select>
        </div>

        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} asset{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Asset list */}
      {filtered.length === 0 ? (
        <div className="bg-card rounded-lg border border-border py-16 text-center">
          <Shield className="h-8 w-8 text-muted-foreground/40 mx-auto mb-3" />
          <p className="text-muted-foreground text-sm">No assets match the current filters</p>
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((asset) => (
            <AssetRow
              key={asset.host}
              asset={asset}
              onClick={() => setSelectedAsset(asset)}
            />
          ))}
        </div>
      )}

      {/* Detail drawer */}
      {selectedAsset && (
        <AssetDetailDrawer
          asset={selectedAsset}
          onClose={() => setSelectedAsset(null)}
        />
      )}
    </div>
  );
}
