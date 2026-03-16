import { useLanguage } from "@/hooks/use-language";
import { Search, Bell, Globe } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function TopBar() {
  const { lang, setLang, t } = useLanguage();

  return (
    <header className="h-14 border-b border-border bg-card flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="relative w-80">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={t("common.search")}
          className="pl-9 h-9 bg-muted border-none text-sm"
        />
      </div>

      <div className="flex items-center gap-3">
        {/* Scan status indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-muted text-sm">
          <span className="h-2 w-2 rounded-full bg-success animate-scan-pulse" />
          <span className="text-muted-foreground">2 {t("common.scanning")}</span>
        </div>

        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          <Badge className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-[10px]">
            5
          </Badge>
        </Button>

        <Button
          variant="ghost"
          size="sm"
          onClick={() => setLang(lang === "vi" ? "en" : "vi")}
          className="gap-1.5 text-sm font-medium"
        >
          <Globe className="h-4 w-4" />
          {lang === "vi" ? "VI" : "EN"}
        </Button>
      </div>
    </header>
  );
}
