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
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="text-3xl font-bold mt-1 tracking-tight">{value}</p>
          {change && (
            <p className={cn(
              "text-xs mt-1 font-medium",
              changeType === "positive" && "text-success",
              changeType === "negative" && "text-destructive",
              changeType === "neutral" && "text-muted-foreground"
            )}>
              {change}
            </p>
          )}
        </div>
        <div className={cn("p-2.5 rounded-md", iconColor || "bg-primary/10")}>
          <Icon className={cn("h-5 w-5", iconColor ? "text-card-foreground" : "text-primary")} />
        </div>
      </div>
    </div>
  );
}
