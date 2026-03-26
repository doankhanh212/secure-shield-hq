import { useState } from "react";
import { useLanguage } from "@/hooks/use-language";
import { DashboardLayout } from "@/components/layout/DashboardLayout";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";

function SettingToggle({
  label,
  description,
  checked,
  onChange,
}: {
  label: string;
  description: string;
  checked: boolean;
  onChange: () => void;
}) {
  return (
    <div className="flex items-center justify-between py-2.5">
      <div>
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
      </div>
      <button
        type="button"
        onClick={onChange}
        className={`relative w-11 h-6 rounded-full transition-colors shrink-0 ml-6 ${
          checked ? "bg-[#06b6d4]" : "bg-muted"
        }`}
      >
        <span
          className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-5" : "translate-x-0"
          }`}
        />
      </button>
    </div>
  );
}

const SettingsPage = () => {
  const { t, lang, setLang } = useLanguage();

  const [toggles, setToggles] = useState({
    dailyScans: true,
    aiAnalysis: true,
    distributedScanning: false,
    emailNotifications: true,
  });

  const toggle = (key: keyof typeof toggles) =>
    setToggles((prev) => ({ ...prev, [key]: !prev[key] }));

  return (
    <DashboardLayout>
      <div className="mb-6">
        <h1 className="text-2xl font-bold tracking-tight">{t("settings.title")}</h1>
        <p className="text-sm text-muted-foreground mt-1">Cấu hình nền tảng HQG Security</p>
      </div>

      <div className="max-w-2xl space-y-5">
        {/* General */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-base font-semibold mb-5">Chung</h2>
          <div className="space-y-5">
            <div>
              <Label className="text-sm font-medium mb-1.5 block">Tên nền tảng</Label>
              <Input
                defaultValue="HQG Security Platform"
                className="max-w-md"
              />
            </div>
            <div className="flex items-center justify-between max-w-md">
              <div>
                <p className="text-sm font-medium">Ngôn ngữ</p>
                <p className="text-xs text-muted-foreground mt-0.5">
                  {lang === "vi" ? "Tiếng Việt" : "English"}
                </p>
              </div>
              <button
                type="button"
                className="px-3 py-1.5 rounded-lg border border-border text-xs font-medium text-muted-foreground hover:bg-muted/50 transition-colors"
                onClick={() => setLang(lang === "vi" ? "en" : "vi")}
              >
                {lang === "vi" ? "Switch to English" : "Chuyển sang Tiếng Việt"}
              </button>
            </div>
          </div>
        </div>

        {/* Scan Configuration */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-base font-semibold mb-4">Cấu hình Quét</h2>
          <div className="divide-y divide-border/50">
            <SettingToggle
              label="Tự động quét hàng ngày"
              description="Chạy quét nhanh hàng ngày lúc nửa đêm"
              checked={toggles.dailyScans}
              onChange={() => toggle("dailyScans")}
            />
            <SettingToggle
              label="AI phân tích lỗ hổng"
              description="Bật phân tích AI cho tất cả quét"
              checked={toggles.aiAnalysis}
              onChange={() => toggle("aiAnalysis")}
            />
            <SettingToggle
              label="Quét phân tán"
              description="Sử dụng nhiều workers để quét song song"
              checked={toggles.distributedScanning}
              onChange={() => toggle("distributedScanning")}
            />
            <SettingToggle
              label="Thông báo email"
              description="Gửi cảnh báo khi phát hiện lỗ hổng Critical"
              checked={toggles.emailNotifications}
              onChange={() => toggle("emailNotifications")}
            />
          </div>
        </div>

        {/* API Configuration */}
        <div className="bg-card rounded-xl border border-border p-6">
          <h2 className="text-base font-semibold mb-5">API</h2>
          <div className="space-y-5">
            <div>
              <Label className="text-sm font-medium mb-1.5 block">API Gateway URL</Label>
              <Input
                defaultValue="https://api.hqg-security.local"
                className="max-w-lg font-mono text-sm"
              />
            </div>
            <div>
              <Label className="text-sm font-medium mb-1.5 block">Scan Workers</Label>
              <Input
                type="number"
                defaultValue="4"
                className="w-20"
              />
            </div>
            <div>
              <Label className="text-sm font-medium mb-1.5 block">NVD API Key</Label>
              <Input
                type="password"
                className="max-w-lg font-mono text-sm"
                placeholder="Nhập NVD API key..."
              />
              <p className="text-xs text-muted-foreground mt-1.5">
                Đăng ký tại nvd.nist.gov/developers/request-an-api-key
              </p>
            </div>
          </div>
        </div>

        {/* Save button */}
        <div className="flex justify-end">
          <button
            type="button"
            className="bg-[#06b6d4] hover:bg-[#0891b2] text-white px-5 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            Lưu thay đổi
          </button>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default SettingsPage;
