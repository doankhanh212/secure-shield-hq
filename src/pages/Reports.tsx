import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FileText, Download } from "lucide-react";

const reports = [
  { id: "RPT-001", title: "Security Assessment - example.com", date: "2024-01-15", type: "Full Report", pages: 42, status: "ready" },
  { id: "RPT-002", title: "Vulnerability Report - Q1 2024", date: "2024-01-14", type: "Quarterly", pages: 28, status: "ready" },
  { id: "RPT-003", title: "API Security Audit - api.example.com", date: "2024-01-13", type: "API Audit", pages: 15, status: "generating" },
  { id: "RPT-004", title: "Compliance Report - OWASP Top 10", date: "2024-01-12", type: "Compliance", pages: 35, status: "ready" },
];

const Reports = () => {
  const { t } = useLanguage();

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("reports.title")}</h1>
      </div>

      <div className="grid gap-4">
        {reports.map((report) => (
          <div key={report.id} className="bg-card rounded-lg border border-border p-5 flex items-center gap-4 hover:bg-muted/30 transition-colors animate-fade-in">
            <div className="p-3 rounded-md bg-primary/10">
              <FileText className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1">
              <p className="font-medium">{report.title}</p>
              <p className="text-xs text-muted-foreground mt-1">
                <span className="font-mono">{report.id}</span> • {report.type} • {report.pages} pages • {report.date}
              </p>
            </div>
            {report.status === "generating" ? (
              <Badge variant="secondary" className="bg-primary/10 text-primary text-xs">
                <span className="h-1.5 w-1.5 rounded-full bg-primary animate-scan-pulse mr-1.5" />
                Generating...
              </Badge>
            ) : (
              <div className="flex gap-2">
                {["PDF", "JSON", "CSV", "HTML"].map((fmt) => (
                  <Button key={fmt} variant="outline" size="sm" className="text-xs gap-1.5 h-8">
                    <Download className="h-3 w-3" />
                    {fmt}
                  </Button>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </DashboardLayout>
  );
};

export default Reports;
