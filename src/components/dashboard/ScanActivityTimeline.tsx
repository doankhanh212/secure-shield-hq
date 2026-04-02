import { useLanguage } from "@/hooks/use-language";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { Skeleton } from "@/components/ui/skeleton";

interface ScanActivityTimelineProps {
  data: { day: string; scans: number; vulns: number }[];
  isLoading?: boolean;
}

export function ScanActivityTimeline({ data, isLoading }: ScanActivityTimelineProps) {
  const { t } = useLanguage();

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <h3 className="text-sm font-semibold mb-4">{t("dashboard.scanActivity")}</h3>
      <div className="h-52">
        {isLoading ? (
          <Skeleton className="h-full w-full" />
        ) : data.length === 0 ? (
          <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
            No activity data
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} barGap={2}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="day" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" allowDecimals={false} tickCount={4} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
              />
              <Bar dataKey="scans" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
              <Bar dataKey="vulns" fill="hsl(var(--destructive))" radius={[3, 3, 0, 0]} opacity={0.7} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
      <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm bg-primary" />
          Scans
        </div>
        <div className="flex items-center gap-1.5">
          <span className="h-2.5 w-2.5 rounded-sm bg-destructive opacity-70" />
          Vulns Found
        </div>
      </div>
    </div>
  );
}
