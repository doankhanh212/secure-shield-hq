import { cn } from "@/lib/utils";

const CONFIDENCE_CONFIG: Record<
  string,
  { label: string; classes: string; dot: string }
> = {
  confirmed: {
    label: "CONFIRMED",
    classes: "bg-red-500/15 text-red-400 border-red-500/40",
    dot: "bg-red-500",
  },
  high: {
    label: "HIGH",
    classes: "bg-orange-500/15 text-orange-400 border-orange-500/40",
    dot: "bg-orange-500",
  },
  medium: {
    label: "MEDIUM",
    classes: "bg-yellow-500/15 text-yellow-400 border-yellow-500/40",
    dot: "bg-yellow-500",
  },
  low: {
    label: "LOW",
    classes: "bg-muted/60 text-muted-foreground border-border",
    dot: "bg-muted-foreground",
  },
};

interface ConfidenceBadgeProps {
  confidence: string;
  className?: string;
}

export function ConfidenceBadge({ confidence, className }: ConfidenceBadgeProps) {
  const key = confidence?.toLowerCase() ?? "low";
  const cfg = CONFIDENCE_CONFIG[key] ?? CONFIDENCE_CONFIG.low;

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px] font-bold tracking-wider uppercase",
        cfg.classes,
        className
      )}
    >
      <span className={cn("w-1.5 h-1.5 rounded-full shrink-0", cfg.dot)} />
      {cfg.label}
    </span>
  );
}
