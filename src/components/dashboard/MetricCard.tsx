import { cn } from "@/lib/utils";
import { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: "positive" | "negative" | "neutral";
  icon: LucideIcon;
  iconColor?: string;
}

export function MetricCard({ title, value, change, changeType = "neutral", icon: Icon, iconColor }: MetricCardProps) {
  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in hover:border-primary/30 transition-all duration-300 group">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{title}</p>
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
