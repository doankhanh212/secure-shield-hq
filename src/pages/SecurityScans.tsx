import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Plus, Radar, Play } from "lucide-react";
import { cn } from "@/lib/utils";
import { ScanProgress } from "@/components/scans/ScanProgress";

const scanModes = [
  { key: "scans.quickScan", desc: "Port scan + basic vuln check", duration: "~5 min" },
  { key: "scans.standardScan", desc: "OWASP Top 10 + CVE mapping", duration: "~30 min" },
  { key: "scans.deepScan", desc: "Full crawl + payload injection", duration: "~2 hrs" },
  { key: "scans.fullScan", desc: "Subdomain + IP + full attack surface", duration: "~6 hrs" },
];

const scanHistory = [
  { id: "SCN-001", target: "example.com", mode: "Deep Scan", status: "completed", vulns: 19, duration: "1h 42m", date: "2024-01-15" },
  { id: "SCN-002", target: "api.example.com", mode: "Quick Scan", status: "completed", vulns: 3, duration: "4m", date: "2024-01-14" },
  { id: "SCN-003", target: "staging.example.com", mode: "Standard Scan", status: "scanning", vulns: 8, duration: "—", date: "2024-01-15" },
  { id: "SCN-004", target: "admin.example.com", mode: "Full Scan", status: "completed", vulns: 27, duration: "5h 12m", date: "2024-01-13" },
];

const SecurityScans = () => {
  const { t } = useLanguage();
  const [selectedMode, setSelectedMode] = useState(0);

  const activeScans = scanHistory.filter(s => s.status === "scanning");

  return (
    <DashboardLayout>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">{t("scans.title")}</h1>
          <p className="text-sm text-muted-foreground mt-1">{scanHistory.length} scans total • {activeScans.length} active</p>
        </div>
        <Dialog>
          <DialogTrigger asChild>
            <Button size="sm" className="gap-2">
              <Plus className="h-4 w-4" />
              {t("scans.newScan")}
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg">
            <DialogHeader>
              <DialogTitle>{t("scans.newScan")}</DialogTitle>
            </DialogHeader>
            <div className="space-y-4 mt-2">
              <div>
                <Label className="text-sm font-medium">Target</Label>
                <Input placeholder="example.com" className="mt-1.5 font-mono" />
              </div>
              <div>
                <Label className="text-sm font-medium mb-2 block">Scan Mode</Label>
                <div className="grid grid-cols-2 gap-2">
                  {scanModes.map((mode, i) => (
                    <button
                      key={i}
                      onClick={() => setSelectedMode(i)}
                      className={cn(
                        "p-3 rounded-md border text-left transition-all",
                        selectedMode === i
                          ? "border-primary bg-primary/5 glow-primary"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      <p className="text-sm font-medium">{t(mode.key)}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{mode.desc}</p>
                      <p className="text-xs text-muted-foreground mt-1 font-mono">{mode.duration}</p>
                    </button>
                  ))}
                </div>
              </div>
              <div className="space-y-3">
                <Label className="text-sm font-medium">Options</Label>
                {["Subdomain scanning", "Public IP scanning", "API scanning", "Technology detection", "CVE mapping", "AI analysis"].map((opt) => (
                  <div key={opt} className="flex items-center justify-between">
                    <span className="text-sm">{opt}</span>
                    <Switch defaultChecked={opt !== "AI analysis"} />
                  </div>
                ))}
              </div>
              <Button className="w-full gap-2">
                <Play className="h-4 w-4" />
                Start Scan
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {/* Active Scan Progress */}
      {activeScans.length > 0 && (
        <div className="mb-6 space-y-4">
          {activeScans.map(scan => (
            <ScanProgress key={scan.id} target={scan.target} />
          ))}
        </div>
      )}

      {/* Scan History */}
      <div className="bg-card rounded-lg border border-border overflow-hidden animate-fade-in">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/30">
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">ID</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Target</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Mode</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Status</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Vulns</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Duration</th>
              <th className="text-left px-4 py-3 font-semibold text-muted-foreground text-xs uppercase tracking-wider">Date</th>
            </tr>
          </thead>
          <tbody>
            {scanHistory.map((scan) => (
              <tr key={scan.id} className="border-b border-border last:border-0 hover:bg-muted/20 transition-colors cursor-pointer">
                <td className="px-4 py-3 font-mono text-xs text-muted-foreground">{scan.id}</td>
                <td className="px-4 py-3 font-mono font-medium">{scan.target}</td>
                <td className="px-4 py-3 text-muted-foreground">{scan.mode}</td>
                <td className="px-4 py-3">
                  <Badge variant="outline" className={cn(
                    "text-[10px] font-medium",
                    scan.status === "scanning" ? "bg-primary/10 text-primary border-primary/20" : "bg-success/10 text-success border-success/20"
                  )}>
                    {scan.status === "scanning" && <span className="h-1.5 w-1.5 rounded-full bg-primary animate-scan-pulse mr-1.5" />}
                    {scan.status}
                  </Badge>
                </td>
                <td className="px-4 py-3 font-mono text-sm font-semibold">{scan.vulns}</td>
                <td className="px-4 py-3 text-muted-foreground text-xs font-mono">{scan.duration}</td>
                <td className="px-4 py-3 text-muted-foreground text-xs">{scan.date}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </DashboardLayout>
  );
};

export default SecurityScans;
