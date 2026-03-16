import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Search, ChevronRight } from "lucide-react";
import { cn } from "@/lib/utils";

const vulnerabilities = [
  { id: "CVE-2024-1234", title: "SQL Injection in login endpoint", severity: "critical", owasp: "A03:2021", cwe: "CWE-89", target: "api.example.com", status: "verified", aiConfidence: 95 },
  { id: "CVE-2024-1235", title: "Cross-Site Scripting (Stored XSS)", severity: "high", owasp: "A07:2021", cwe: "CWE-79", target: "example.com", status: "verified", aiConfidence: 88 },
  { id: "CVE-2024-1236", title: "Broken Access Control - IDOR", severity: "critical", owasp: "A01:2021", cwe: "CWE-639", target: "admin.example.com", status: "verified", aiConfidence: 92 },
  { id: "CVE-2024-1237", title: "Server-Side Request Forgery", severity: "high", owasp: "A10:2021", cwe: "CWE-918", target: "api.example.com", status: "open", aiConfidence: 76 },
  { id: "CVE-2024-1238", title: "Insecure Deserialization", severity: "medium", owasp: "A08:2021", cwe: "CWE-502", target: "staging.example.com", status: "false_positive", aiConfidence: 34 },
  { id: "CVE-2024-1239", title: "Missing Rate Limiting on Auth API", severity: "medium", owasp: "A04:2021", cwe: "CWE-307", target: "api.example.com", status: "open", aiConfidence: 81 },
  { id: "CVE-2024-1240", title: "Information Disclosure via Error Messages", severity: "low", owasp: "A05:2021", cwe: "CWE-209", target: "example.com", status: "verified", aiConfidence: 97 },
];

const severityStyles: Record<string, string> = {
  critical: "bg-destructive/10 text-destructive",
  high: "bg-warning/10 text-warning",
  medium: "bg-info/10 text-info",
  low: "bg-muted text-muted-foreground",
};

const statusStyles: Record<string, string> = {
  verified: "bg-success/10 text-success",
  open: "bg-primary/10 text-primary",
  false_positive: "bg-muted text-muted-foreground",
};

const Vulnerabilities = () => {
  const { t } = useLanguage();

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("vulns.title")}</h1>
      </div>

      <div className="mb-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input placeholder={t("common.search")} className="pl-9 h-9 bg-card border text-sm" />
        </div>
      </div>

      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/50">
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">CVE ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">Vulnerability</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">Severity</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">OWASP</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">Target</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">Status</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground">AI</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {vulnerabilities.map((vuln) => (
              <tr key={vuln.id} className="border-b border-border last:border-0 hover:bg-muted/30 transition-colors cursor-pointer">
                <td className="px-4 py-3 font-mono text-xs font-medium">{vuln.id}</td>
                <td className="px-4 py-3">
                  <p className="font-medium text-sm">{vuln.title}</p>
                  <p className="text-xs text-muted-foreground font-mono">{vuln.cwe}</p>
                </td>
                <td className="px-4 py-3">
                  <Badge variant="secondary" className={cn("text-xs font-semibold uppercase", severityStyles[vuln.severity])}>
                    {vuln.severity}
                  </Badge>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{vuln.owasp}</td>
                <td className="px-4 py-3 font-mono text-xs">{vuln.target}</td>
                <td className="px-4 py-3">
                  <Badge variant="secondary" className={cn("text-xs", statusStyles[vuln.status])}>
                    {vuln.status === "false_positive" ? "False Positive" : vuln.status}
                  </Badge>
                </td>
                <td className="px-4 py-3">
                  <span className={cn(
                    "text-xs font-semibold font-mono",
                    vuln.aiConfidence >= 80 ? "text-success" : vuln.aiConfidence >= 50 ? "text-warning" : "text-muted-foreground"
                  )}>
                    {vuln.aiConfidence}%
                  </span>
                </td>
                <td className="px-4 py-3">
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default Vulnerabilities;
