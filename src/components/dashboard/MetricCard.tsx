import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: "positive" | "negative" | "neutral";
  icon: LucideIcon;
  iconColor?: string;
  isLoading?: boolean;
  accentClassName?: string;
}

export function MetricCard({
  title,
  value,
  change,
  changeType = "neutral",
  icon: Icon,
  iconColor,
  isLoading,
  accentClassName,
}: MetricCardProps) {
  return (
    <div className={cn(
      "bg-card rounded-lg border border-border border-l-4 p-5 animate-fade-in hover:border-primary/30 transition-all duration-300 group",
      accentClassName
    )}>
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
          {isLoading ? (
            <div className="animate-pulse mt-2 space-y-2">
              <div className="h-9 w-24 rounded-md bg-muted" />
              <div className="h-4 w-20 rounded-md bg-muted" />
            </div>
          ) : (
            <>
              <p className="text-3xl font-bold mt-2 tracking-tight font-mono">{value}</p>
              {change && (
                <p className={cn(
                  "text-xs mt-2 font-medium",
                  changeType === "positive" && "text-success",
                  changeType === "negative" && "text-destructive",
                  changeType === "neutral" && "text-muted-foreground"
                )}>
                  {change}
                </p>
              )}
            </>
          )}
        </div>
        <div className={cn(
          "p-2.5 rounded-lg transition-colors",
          iconColor || "bg-primary/10 group-hover:bg-primary/20"
        )}>
          <Icon className={cn("h-5 w-5", iconColor ? "text-card-foreground" : "text-primary")} />
        </div>
      </div>
    </div>
  );
}
