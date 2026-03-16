import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Search, ChevronRight, ChevronDown, ExternalLink, Zap, Shield, Wrench, FileCode } from "lucide-react";
import { cn } from "@/lib/utils";

interface Vuln {
  id: string;
  title: string;
  severity: string;
  owasp: string;
  cwe: string;
  target: string;
  status: string;
  aiConfidence: number;
  exploitability: "High" | "Medium" | "Low";
  attackVector: string;
  poc: string;
  fix: string;
}

const vulnerabilities: Vuln[] = [
  { id: "CVE-2024-1234", title: "SQL Injection in login endpoint", severity: "critical", owasp: "A03:2021", cwe: "CWE-89", target: "api.example.com", status: "verified", aiConfidence: 95, exploitability: "High", attackVector: "Network", poc: "POST /api/login with payload: ' OR 1=1--", fix: "Use parameterized queries. Replace string concatenation in auth_controller.py line 42." },
  { id: "CVE-2024-1235", title: "Cross-Site Scripting (Stored XSS)", severity: "high", owasp: "A07:2021", cwe: "CWE-79", target: "example.com", status: "verified", aiConfidence: 88, exploitability: "Medium", attackVector: "Network", poc: "Inject <script>alert(1)</script> in comment field", fix: "Sanitize user input with DOMPurify. Encode output in templates." },
  { id: "CVE-2024-1236", title: "Broken Access Control - IDOR", severity: "critical", owasp: "A01:2021", cwe: "CWE-639", target: "admin.example.com", status: "verified", aiConfidence: 92, exploitability: "High", attackVector: "Network", poc: "GET /api/users/2 while authenticated as user 1", fix: "Implement proper authorization checks. Verify resource ownership in middleware." },
  { id: "CVE-2024-1237", title: "Server-Side Request Forgery", severity: "high", owasp: "A10:2021", cwe: "CWE-918", target: "api.example.com", status: "open", aiConfidence: 76, exploitability: "Medium", attackVector: "Network", poc: "POST /api/fetch?url=http://169.254.169.254/metadata", fix: "Whitelist allowed URLs. Block internal IP ranges in outbound requests." },
  { id: "CVE-2024-1238", title: "Insecure Deserialization", severity: "medium", owasp: "A08:2021", cwe: "CWE-502", target: "staging.example.com", status: "false_positive", aiConfidence: 34, exploitability: "Low", attackVector: "Network", poc: "N/A - False positive detected by AI analysis", fix: "N/A" },
  { id: "CVE-2024-1239", title: "Missing Rate Limiting on Auth API", severity: "medium", owasp: "A04:2021", cwe: "CWE-307", target: "api.example.com", status: "open", aiConfidence: 81, exploitability: "Medium", attackVector: "Network", poc: "Brute force /api/login with 1000 requests/min - no blocking", fix: "Implement rate limiting (e.g., 5 attempts per minute). Add CAPTCHA after 3 failures." },
  { id: "CVE-2024-1240", title: "Information Disclosure via Error Messages", severity: "low", owasp: "A05:2021", cwe: "CWE-209", target: "example.com", status: "verified", aiConfidence: 97, exploitability: "Low", attackVector: "Network", poc: "GET /api/nonexistent returns stack trace with framework version", fix: "Configure production error handler. Remove debug info from responses." },
];

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

const exploitStyles: Record<string, string> = {
  High: "text-destructive",
  Medium: "text-warning",
  Low: "text-muted-foreground",
};

const Vulnerabilities = () => {
  const { t } = useLanguage();
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("vulns.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">{vulnerabilities.length} vulnerabilities detected</p>
      </div>

      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t("common.search")} className="pl-9 h-9 bg-muted/50 border text-sm" />
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="w-8 px-2 py-3"></th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">CVE ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Vulnerability</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Severity</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Target</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">{t("vulns.exploitability")}</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Status</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">AI</th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map((vuln) => (
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
                  <td className="px-4 py-3 font-mono text-xs font-medium">{vuln.id}</td>
                  <td className="px-4 py-3">
                    <p className="font-medium text-sm">{vuln.title}</p>
                    <p className="text-xs text-muted-foreground font-mono mt-0.5">{vuln.cwe} • {vuln.owasp}</p>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={cn("text-[10px] font-bold uppercase", severityStyles[vuln.severity])}>
                      {vuln.severity}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 font-mono text-xs">{vuln.target}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      <Zap className={cn("h-3.5 w-3.5", exploitStyles[vuln.exploitability])} />
                      <span className={cn("text-xs font-semibold", exploitStyles[vuln.exploitability])}>{vuln.exploitability}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant="outline" className={cn("text-[10px]", statusStyles[vuln.status])}>
                      {vuln.status === "false_positive" ? "False Positive" : vuln.status}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    <span className={cn(
                      "text-xs font-bold font-mono",
                      vuln.aiConfidence >= 80 ? "text-success" : vuln.aiConfidence >= 50 ? "text-warning" : "text-muted-foreground"
                    )}>
                      {vuln.aiConfidence}%
                    </span>
                  </td>
                </tr>
                {expanded === vuln.id && (
                  <tr key={`${vuln.id}-detail`} className="border-b border-border bg-muted/10">
                    <td colSpan={8} className="px-6 py-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-fade-in">
                        <div className="space-y-3">
                          <div className="flex items-start gap-2">
                            <Shield className="h-4 w-4 text-primary mt-0.5 shrink-0" />
                            <div>
                              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("vulns.attackVector")}</p>
                              <p className="text-sm mt-1">{vuln.attackVector}</p>
                            </div>
                          </div>
                          <div className="flex items-start gap-2">
                            <FileCode className="h-4 w-4 text-warning mt-0.5 shrink-0" />
                            <div>
                              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("vulns.poc")}</p>
                              <p className="text-sm mt-1 font-mono bg-muted/50 rounded px-2 py-1 text-xs">{vuln.poc}</p>
                            </div>
                          </div>
                        </div>
                        <div className="flex items-start gap-2">
                          <Wrench className="h-4 w-4 text-success mt-0.5 shrink-0" />
                          <div>
                            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{t("vulns.fix")}</p>
                            <p className="text-sm mt-1">{vuln.fix}</p>
                          </div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default Vulnerabilities;
