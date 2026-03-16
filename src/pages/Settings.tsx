import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Button } from "@/components/ui/button";

const SettingsPage = () => {
  const { t, lang, setLang } = useLanguage();

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("settings.title")}</h1>
      </div>

      <div className="max-w-2xl space-y-6">
        <div className="bg-card rounded-lg border border-border p-6 space-y-4 animate-fade-in">
          <h3 className="font-semibold">General</h3>
          <div className="grid gap-4">
            <div>
              <Label>Platform Name</Label>
              <Input defaultValue="HQG Security Platform" className="mt-1.5" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <Label>Language / Ngôn ngữ</Label>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {lang === "vi" ? "Tiếng Việt" : "English"}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => setLang(lang === "vi" ? "en" : "vi")}>
                {lang === "vi" ? "Switch to English" : "Chuyển sang Tiếng Việt"}
              </Button>
            </div>
          </div>
        </div>

        <div className="bg-card rounded-lg border border-border p-6 space-y-4 animate-fade-in">
          <h3 className="font-semibold">Scan Configuration</h3>
          <div className="space-y-3">
            {[
              { label: "Auto-schedule daily scans", desc: "Run quick scans daily at midnight" },
              { label: "AI vulnerability analysis", desc: "Enable AI-powered analysis for all scans" },
              { label: "Distributed scanning", desc: "Use multiple workers for parallel scanning" },
              { label: "Email notifications", desc: "Send alerts for critical findings" },
            ].map((opt) => (
              <div key={opt.label} className="flex items-center justify-between py-2">
                <div>
                  <p className="text-sm font-medium">{opt.label}</p>
                  <p className="text-xs text-muted-foreground">{opt.desc}</p>
                </div>
                <Switch defaultChecked />
              </div>
            ))}
          </div>
        </div>

        <div className="bg-card rounded-lg border border-border p-6 space-y-4 animate-fade-in">
          <h3 className="font-semibold">API Configuration</h3>
          <div className="grid gap-4">
            <div>
              <Label>API Gateway URL</Label>
              <Input defaultValue="https://api.hqg-security.local" className="mt-1.5 font-mono text-sm" />
            </div>
            <div>
              <Label>Scan Workers</Label>
              <Input type="number" defaultValue="4" className="mt-1.5 w-24" />
            </div>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default SettingsPage;
