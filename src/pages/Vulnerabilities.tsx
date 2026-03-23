import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search, ChevronRight, ChevronDown, ExternalLink, Zap, Shield, Wrench, FileCode } from "lucide-react";
import { cn } from "@/lib/utils";
import { Skeleton } from "@/components/ui/skeleton";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getVulnerabilities, patchVulnerability, type Vulnerability } from "@/services/api";

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive border-destructive/20",
  high: "bg-warning/10 text-warning border-warning/20",
  medium: "bg-info/10 text-info border-info/20",
  low: "bg-muted text-muted-foreground border-border",
};

const statusStyles: Record<string, string> = {
  verified: "bg-success/10 text-success border-success/20",
  open: "bg-primary/10 text-primary border-primary/20",
  false_positive: "bg-muted text-muted-foreground border-border",
};

const VULN_DISPLAY_NAMES: Record<string, string> = {
  time_based_sqli: "SQL Injection (Blind – Time Based)",
  sqli_error: "SQL Injection (Error Based)",
  sqli_union: "SQL Injection (UNION Based)",
  xss_reflected: "Cross-Site Scripting (Reflected)",
  xss_stored: "Cross-Site Scripting (Stored)",
  cmdi: "Command Injection",
  cmdi_basic: "Command Injection (Basic)",
  lfi: "Local File Inclusion",
  ssrf: "Server-Side Request Forgery",
  open_redirect: "Open Redirect",
  info_disclosure: "Information Disclosure",
};

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
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("vulns.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">
          {isLoading ? "Đang tải..." : `${data?.total ?? 0} lỗ hổng được phát hiện`}
        </p>
      </div>

      <div className="mb-4 flex items-center gap-3">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("common.search")}
            className="pl-9 h-9 bg-muted/50 border text-sm"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1.5">
          {["", "critical", "high", "medium", "low"].map((sev) => (
            <Button
              key={sev}
              variant={severityFilter === sev ? "default" : "outline"}
              size="sm"
              className="text-xs h-8"
              onClick={() => setSeverityFilter(sev)}
            >
              {sev || "Tất cả"}
            </Button>
          ))}
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="w-8 px-2 py-3"></th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Vulnerability</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Severity</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Tham số</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Endpoint</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Status</th>
            </tr>
          </thead>
          <tbody>
            {isLoading ? (
              Array.from({ length: 5 }).map((_, i) => (
                <tr key={i} className="border-b border-border">
                  {Array.from({ length: 7 }).map((_, j) => (
                    <td key={j} className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
                  ))}
                </tr>
              ))
            ) : vulnerabilities.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                  Không tìm thấy lỗ hổng nào
                </td>
              </tr>
            ) : (
              vulnerabilities.map((vuln) => (
                <>
                  <tr
                    key={vuln.id}
                    onClick={() => setExpanded(expanded === vuln.id ? null : vuln.id)}
                    className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer"
                  >
                    <td className="px-2 py-3 text-center">
                      {expanded === vuln.id ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs font-medium">{vuln.id.slice(0, 12)}</td>
                    <td className="px-4 py-3">
                      <p className="font-medium text-sm">
                        {VULN_DISPLAY_NAMES[vuln.vulnerability_type] ?? vuln.vulnerability_type}
                      </p>
                      {(vuln.owasp_category || VULN_DISPLAY_NAMES[vuln.vulnerability_type]) && (
                        <div className="text-xs text-muted-foreground font-mono mt-0.5 flex items-center gap-1.5 flex-wrap">
                          {vuln.owasp_category && <span>{vuln.cwe_id} • {vuln.owasp_category}</span>}
                          {VULN_DISPLAY_NAMES[vuln.vulnerability_type] && (
                            <span className="text-[10px] bg-muted/60 border border-border rounded px-1.5 py-0.5 text-muted-foreground font-mono">
                              {vuln.vulnerability_type}
                            </span>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <Badge variant="outline" className={cn("text-[10px] font-bold uppercase", severityStyles[vuln.severity?.toLowerCase()] ?? "")}>
                        {vuln.severity}
                      </Badge>
                    </td>
                    <td className="px-4 py-3">
                      {(vuln as Vulnerability & { parameter?: string }).parameter ? (
                        <span className="font-mono text-xs bg-muted/50 px-1.5 py-0.5 rounded border border-border">
                          {(vuln as Vulnerability & { parameter?: string }).parameter}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-xs">—</span>
                      )}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs max-w-[200px] truncate">{vuln.endpoint}</td>
                    <td className="px-4 py-3">
                      <Badge
                        variant="outline"
                        className={cn(
                          "text-[10px]",
                          vuln.is_false_positive
                            ? statusStyles.false_positive
                            : statusStyles[vuln.status ?? "open"] ?? statusStyles.open
                        )}
                      >
                        {vuln.is_false_positive ? "Không hợp lệ" : vuln.status ?? "open"}
                      </Badge>
                    </td>
                  </tr>
                  {expanded === vuln.id && (
                    <tr key={`${vuln.id}-detail`} className="border-b border-border bg-muted/10">
                      <td colSpan={7} className="px-6 py-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
                          <div className="space-y-3">
                            {vuln.explanation && (
                              <div className="flex items-start gap-2">
                                <Shield className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                                <div>
                                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Giải thích</p>
                                  <p className="text-sm mt-1">{vuln.explanation}</p>
                                </div>
                              </div>
                            )}
                            {vuln.poc && (
                              <div className="flex items-start gap-2">
                                <FileCode className="h-4 w-4 text-warning mt-0.5 shrink-0" />
                                <div>
                                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("vulns.poc")}</p>
                                  <p className="text-sm mt-1 font-mono bg-muted/50 rounded px-2 py-1 text-xs">{vuln.poc}</p>
                                </div>
                              </div>
                            )}
                          </div>
                          <div className="space-y-3">
                            {vuln.remediation && (
                              <div className="flex items-start gap-2">
                                <Wrench className="h-4 w-4 text-success mt-0.5 shrink-0" />
                                <div>
                                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("vulns.fix")}</p>
                                  <p className="text-sm mt-1">{vuln.remediation}</p>
                                </div>
                              </div>
                            )}
                            <div className="flex gap-2 mt-3">
                              <Button
                                variant="outline"
                                size="sm"
                                className="text-xs"
                                disabled={fpMutation.isPending}
                                onClick={() => fpMutation.mutate({ id: vuln.id, fp: !vuln.is_false_positive })}
                              >
                                {vuln.is_false_positive ? "Bỏ đánh dấu" : "Đánh dấu không hợp lệ"}
                              </Button>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))
            )}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default Vulnerabilities;
