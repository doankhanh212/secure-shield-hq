import { useLanguage } from "@/hooks/use-language";
import { cn } from "@/lib/utils";
import { Search, Globe, Code, Zap, Brain, FileText, CheckCircle2 } from "lucide-react";

interface ScanStage {
  key: string;
  icon: typeof Search;
  status: "completed" | "active" | "pending";
  progress?: number;
  details?: string;
}

interface ScanProgressProps {
  target: string;
  stages?: ScanStage[];
}

const defaultStages: ScanStage[] = [
  { key: "scans.stage.discovery", icon: Globe, status: "completed", progress: 100, details: "87 subdomains found" },
  { key: "scans.stage.crawling", icon: Code, status: "active", progress: 67, details: "342/512 endpoints crawled" },
  { key: "scans.stage.injection", icon: Zap, status: "pending", details: "Waiting..." },
  { key: "scans.stage.aiAnalysis", icon: Brain, status: "pending", details: "Waiting..." },
  { key: "scans.stage.reporting", icon: FileText, status: "pending", details: "Waiting..." },
];

export function ScanProgress({ target, stages = defaultStages }: ScanProgressProps) {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <div className="flex items-center justify-between mb-5">
        <div>
          <h3 className="text-sm font-semibold">{t("scans.progress")}</h3>
          <p className="text-xs text-muted-foreground font-mono mt-0.5">{target}</p>
        </div>
        <div className="flex items-center gap-2 px-2.5 py-1 rounded-md bg-primary/10 border border-primary/20">
          <span className="h-2 w-2 rounded-full bg-primary animate-scan-pulse" />
          <span className="text-xs font-medium text-primary">{t("common.scanning")}</span>
        </div>
      </div>

      <div className="space-y-1">
        {stages.map((stage, i) => (
          <div key={stage.key} className="flex items-center gap-3">
            {/* Timeline connector */}
            <div className="flex flex-col items-center w-8">
              <div className={cn(
                "h-8 w-8 rounded-full flex items-center justify-center border-2 transition-all",
                stage.status === "completed" && "bg-success/10 border-success text-success",
                stage.status === "active" && "bg-primary/10 border-primary text-primary animate-glow",
                stage.status === "pending" && "bg-muted border-border text-muted-foreground"
              )}>
                {stage.status === "completed" ? (
                  <CheckCircle2 className="h-4 w-4" />
                ) : (
                  <stage.icon className="h-4 w-4" />
                )}
              </div>
              {i < stages.length - 1 && (
                <div className={cn(
                  "w-0.5 h-6",
                  stage.status === "completed" ? "bg-success/50" : "bg-border"
                )} />
              )}
            </div>

            {/* Content */}
            <div className="flex-1 pb-6">
              <div className="flex items-center justify-between">
                <p className={cn(
                  "text-sm font-medium",
                  stage.status === "active" && "text-primary",
                  stage.status === "pending" && "text-muted-foreground"
                )}>
                  {t(stage.key)}
                </p>
                {stage.progress !== undefined && stage.status !== "pending" && (
                  <span className="text-xs font-mono font-bold">
                    {stage.progress}%
                  </span>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">{stage.details}</p>
              {stage.status === "active" && stage.progress !== undefined && (
                <div className="w-full h-1.5 bg-muted rounded-full mt-2 overflow-hidden">
                  <div
                    className="h-full bg-primary rounded-full progress-striped"
                    style={{ width: `${stage.progress}%` }}
                  />
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
