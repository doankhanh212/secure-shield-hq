import { cn } from "@/lib/utils";

export type RiskLevel = "critical" | "high" | "medium" | "low";

export function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}

const RISK_CONFIG: Record<RiskLevel, { label: string; bar: string; badge: string; text: string }> = {
  critical: {
    label: "Critical",
    bar: "bg-red-500",
    badge: "bg-red-500/15 border-red-500/40 text-red-400",
    text: "text-red-400",
  },
  high: {
    label: "High",
    bar: "bg-orange-500",
    badge: "bg-orange-500/15 border-orange-500/40 text-orange-400",
    text: "text-orange-400",
  },
  medium: {
    label: "Medium",
    bar: "bg-yellow-500",
    badge: "bg-yellow-500/15 border-yellow-500/40 text-yellow-400",
    text: "text-yellow-400",
  },
  low: {
    label: "Low",
    bar: "bg-green-500",
    badge: "bg-green-500/15 border-green-500/40 text-green-400",
    text: "text-green-400",
  },
};

interface RiskBarProps {
  score: number;
  showLabel?: boolean;
  showScore?: boolean;
  className?: string;
}

export function RiskBar({ score, showLabel = true, showScore = true, className }: RiskBarProps) {
  const level = getRiskLevel(score);
  const cfg = RISK_CONFIG[level];
  const clamped = Math.min(100, Math.max(0, score));

  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden min-w-[48px]">
        <div
          className={cn("h-full rounded-full transition-all duration-500", cfg.bar)}
          style={{ width: `${clamped}%` }}
        />
      </div>
      {showScore && (
        <span className={cn("text-xs font-bold font-mono w-7 text-right shrink-0", cfg.text)}>
          {score}
        </span>
      )}
      {showLabel && (
        <span
          className={cn(
            "text-[10px] font-semibold px-1.5 py-0.5 rounded border uppercase tracking-wide shrink-0",
            cfg.badge
          )}
        >
          {cfg.label}
        </span>
      )}
    </div>
  );
}

export { RISK_CONFIG };
