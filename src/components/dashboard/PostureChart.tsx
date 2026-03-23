import { useLanguage } from "@/hooks/use-language";
import { XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart } from "recharts";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Shield } from "lucide-react";
import { useNavigate } from "react-router-dom";

interface PostureChartProps {
  data: { label: string; score: number }[];
  isLoading?: boolean;
}

export function PostureChart({ data, isLoading }: PostureChartProps) {
  const { t } = useLanguage();
  const navigate = useNavigate();
  const currentScore = data.length > 0 ? data[data.length - 1].score : 0;
  const prevScore = data.length > 1 ? data[data.length - 2].score : 0;
  const diff = currentScore - prevScore;

  return (
    <div className="bg-card rounded-lg border border-border p-5 animate-fade-in">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold">{t("dashboard.securityPosture")}</h3>
        {isLoading ? (
          <Skeleton className="h-6 w-16" />
        ) : (
          <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-success/10 border border-success/20">
            <span className="text-xs font-bold text-success font-mono">{currentScore}</span>
            {diff !== 0 && (
              <span className="text-[10px] text-success">
                {diff > 0 ? "↑" : "↓"} {diff > 0 ? "+" : ""}{diff}
              </span>
            )}
          </div>
        )}
      </div>
      <div className="h-52">
        {isLoading ? (
          <Skeleton className="h-full w-full" />
        ) : data.length === 0 ? (
          <div className="h-full flex items-center justify-center">
            <div className="max-w-sm w-full text-center">
              <div className="mx-auto mb-4 h-20 w-20 rounded-full border border-border bg-muted/40 flex items-center justify-center">
                <Shield className="h-8 w-8 text-muted-foreground" />
              </div>
              <p className="text-sm text-muted-foreground mb-4">Chưa có dữ liệu quét</p>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  navigate("/scans");
                }}
              >
                Bắt đầu quét ngay
              </Button>
            </div>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data}>
              <defs>
                <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
              <XAxis dataKey="label" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
              <YAxis tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" domain={[0, 100]} />
              <Tooltip
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
              />
              <Area
                type="monotone"
                dataKey="score"
                stroke="hsl(var(--primary))"
                strokeWidth={2}
                fill="url(#scoreGradient)"
                dot={{ r: 4, fill: "hsl(var(--primary))", strokeWidth: 2, stroke: "hsl(var(--card))" }}
                activeDot={{ r: 6 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
