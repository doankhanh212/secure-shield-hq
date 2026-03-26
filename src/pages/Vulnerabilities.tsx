import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Search,
  ChevronDown,
  ChevronRight,
  Shield,
  Wrench,
  FileCode,
  Terminal,
  AlertTriangle,
  Info,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getVulnerabilities, patchVulnerability, type Vulnerability } from "@/services/api";

const SEVERITY_TABS = [
  { value: "", label: "Tất cả", color: "text-foreground" },
  { value: "critical", label: "Critical", color: "text-red-400" },
  { value: "high", label: "High", color: "text-orange-400" },
  { value: "medium", label: "Medium", color: "text-yellow-400" },
  { value: "low", label: "Low", color: "text-green-400" },
];

const severityBadgeStyles: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/10 text-green-400 border-green-500/30",
};

const severityLeftBorder: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-green-500",
};

const VULN_DISPLAY_NAMES: Record<string, string> = {
  time_based_sqli: "SQL Injection (Blind – Time Based)",
  sqli_error: "SQL Injection (Error Based)",
  sqli_union: "SQL Injection (UNION Based)",
  sqli: "SQL Injection",
  xss_reflected: "Cross-Site Scripting (Reflected)",
  xss_stored: "Cross-Site Scripting (Stored)",
  xss: "Cross-Site Scripting",
  cmdi: "Command Injection",
  cmdi_basic: "Command Injection (Basic)",
  lfi: "Local File Inclusion",
  path_traversal: "Path Traversal",
  ssrf: "Server-Side Request Forgery",
  open_redirect: "Open Redirect",
  info_disclosure: "Information Disclosure",
};

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-green-500",
  };
  return (
    <span
      className={cn("inline-block w-2 h-2 rounded-full shrink-0", colors[severity?.toLowerCase()] ?? "bg-muted")}
    />
  );
}

function VulnCard({ vuln, expanded, onToggle, onFpToggle, fpPending }: {
  vuln: Vulnerability;
  expanded: boolean;
  onToggle: () => void;
  onFpToggle: () => void;
  fpPending: boolean;
}) {
  const sev = vuln.severity?.toLowerCase() ?? "low";
  const displayName = VULN_DISPLAY_NAMES[vuln.vulnerability_type] ?? vuln.vulnerability_type;

  return (
    <div
      className={cn(
        "bg-card rounded-lg border border-border border-l-4 transition-shadow hover:shadow-sm",
        severityLeftBorder[sev] ?? "border-l-border"
      )}
    >
      {/* Card Header */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3.5 text-left"
        onClick={onToggle}
      >
        <SeverityDot severity={sev} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold">{displayName}</span>
            <Badge
              variant="outline"
              className={cn("text-[10px] font-bold uppercase px-1.5 py-0", severityBadgeStyles[sev])}
            >
              {vuln.severity}
            </Badge>
            {vuln.confidence_label && (
              <Badge variant="outline" className="text-[10px] bg-muted/50 border-border text-muted-foreground px-1.5 py-0">
                {vuln.confidence_label}
              </Badge>
            )}
            {vuln.is_false_positive && (
              <Badge variant="outline" className="text-[10px] bg-muted/50 border-border text-muted-foreground px-1.5 py-0">
                Không hợp lệ
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-2 mt-0.5 text-xs text-muted-foreground font-mono flex-wrap">
            <span className="truncate max-w-[300px]">{vuln.endpoint}</span>
            {vuln.parameter && (
              <>
                <span>•</span>
                <span className="bg-muted/60 px-1.5 rounded border border-border">{vuln.parameter}</span>
              </>
            )}
            {vuln.owasp_category && (
              <>
                <span>•</span>
                <span>{vuln.owasp_category}</span>
              </>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {vuln.cvss_score !== undefined && (
            <span className="text-xs font-mono font-semibold text-muted-foreground">
              CVSS {vuln.cvss_score.toFixed(1)}
            </span>
          )}
          {expanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </button>

      {/* Expanded Detail */}
      {expanded && (
        <div className="border-t border-border px-4 py-4 space-y-4 animate-in fade-in-0 duration-150">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Left Column */}
            <div className="space-y-3">
              {vuln.explanation && (
                <div className="flex items-start gap-2.5">
                  <Shield className="h-4 w-4 text-[#06b6d4] mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Giải thích
                    </p>
                    <p className="text-sm leading-relaxed">{vuln.explanation}</p>
                  </div>
                </div>
              )}
              {vuln.impact && (
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="h-4 w-4 text-orange-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Tác động
                    </p>
                    <p className="text-sm leading-relaxed">{vuln.impact}</p>
                  </div>
                </div>
              )}
              {(vuln.poc || vuln.payload) && (
                <div className="flex items-start gap-2.5">
                  <FileCode className="h-4 w-4 text-yellow-400 mt-0.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      PoC / Payload
                    </p>
                    <pre className="text-xs font-mono bg-muted/60 border border-border rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all">
                      {vuln.poc ?? vuln.payload}
                    </pre>
                  </div>
                </div>
              )}
            </div>

            {/* Right Column */}
            <div className="space-y-3">
              {(vuln.remediation || vuln.fix_recommendation) && (
                <div className="flex items-start gap-2.5">
                  <Wrench className="h-4 w-4 text-green-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Cách khắc phục
                    </p>
                    <p className="text-sm leading-relaxed">{vuln.fix_recommendation ?? vuln.remediation}</p>
                  </div>
                </div>
              )}
              {vuln.evidence && (
                <div className="flex items-start gap-2.5">
                  <Terminal className="h-4 w-4 text-violet-400 mt-0.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Bằng chứng
                    </p>
                    <pre className="text-xs font-mono bg-muted/60 border border-border rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all max-h-32">
                      {vuln.evidence}
                    </pre>
                  </div>
                </div>
              )}
              {vuln.false_positive_likelihood && (
                <div className="flex items-start gap-2.5">
                  <Info className="h-4 w-4 text-blue-400 mt-0.5 shrink-0" />
                  <div>
                    <p className="text-[11px] font-semibold text-muted-foreground uppercase tracking-wider mb-1">
                      Khả năng sai (FP)
                    </p>
                    <p className="text-sm">{vuln.false_positive_likelihood}</p>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 pt-1 border-t border-border/50">
            <Button
              variant="outline"
              size="sm"
              className="text-xs h-7"
              disabled={fpPending}
              onClick={onFpToggle}
            >
              {vuln.is_false_positive ? "Bỏ đánh dấu" : "Đánh dấu không hợp lệ"}
            </Button>
            {vuln.cwe_id && (
              <span className="text-xs text-muted-foreground font-mono ml-auto">{vuln.cwe_id}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const Vulnerabilities = () => {
  const { t } = useLanguage();
  const queryClient = useQueryClient();
  const [expanded, setExpanded] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("");

  const { data, isLoading } = useQuery({
    queryKey: ["vulnerabilities", severityFilter, search],
    queryFn: () =>
      getVulnerabilities({
        severity: severityFilter || undefined,
        endpoint: search || undefined,
        limit: 500,
      }),
    refetchInterval: 30_000,
  });

  const vulnerabilities = data?.items ?? [];

  const fpMutation = useMutation({
    mutationFn: ({ id, fp }: { id: string; fp: boolean }) =>
      patchVulnerability(id, { is_false_positive: fp }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["vulnerabilities"] }),
  });

  return (
    <DashboardLayout>
      <div className="mb-5">
        <h1 className="text-2xl font-bold tracking-tight">{t("vulns.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {isLoading ? "Đang tải..." : `${data?.total ?? 0} lỗ hổng được phát hiện`}
        </p>
      </div>

      {/* Filter Bar */}
      <div className="mb-4 flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Tìm theo endpoint..."
            className="pl-9 h-9 w-72 bg-muted/40 border text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        {/* Severity Tabs */}
        <div className="flex items-center gap-0.5 bg-muted/40 rounded-lg p-1 border border-border">
          {SEVERITY_TABS.map((tab) => (
            <button
              key={tab.value}
              onClick={() => setSeverityFilter(tab.value)}
              className={cn(
                "px-3 py-1 rounded-md text-xs font-medium transition-all",
                severityFilter === tab.value
                  ? "bg-card shadow-sm text-foreground border border-border"
                  : "text-muted-foreground hover:text-foreground",
                tab.value && severityFilter === tab.value ? tab.color : ""
              )}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* Cards */}
      <div className="space-y-2">
        {isLoading ? (
          Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="bg-card rounded-lg border border-border border-l-4 border-l-muted px-4 py-3.5">
              <div className="flex items-center gap-3">
                <Skeleton className="h-2 w-2 rounded-full" />
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-16 ml-2" />
              </div>
              <Skeleton className="h-3 w-64 mt-2 ml-5" />
            </div>
          ))
        ) : vulnerabilities.length === 0 ? (
          <div className="bg-card rounded-lg border border-border py-16 text-center">
            <ShieldAlert className="h-8 w-8 text-muted-foreground/40 mx-auto mb-3" />
            <p className="text-muted-foreground text-sm">Không tìm thấy lỗ hổng nào</p>
          </div>
        ) : (
          vulnerabilities.map((vuln) => (
            <VulnCard
              key={vuln.id}
              vuln={vuln}
              expanded={expanded === vuln.id}
              onToggle={() => setExpanded(expanded === vuln.id ? null : vuln.id)}
              onFpToggle={() => fpMutation.mutate({ id: vuln.id, fp: !vuln.is_false_positive })}
              fpPending={fpMutation.isPending}
            />
          ))
        )}
      </div>
    </DashboardLayout>
  );
};

export default Vulnerabilities;
