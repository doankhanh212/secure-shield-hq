import { useLanguage } from "@/hooks/use-language";
import { useTheme } from "@/hooks/use-theme";
import { Search, Bell, Globe, Moon, Sun, Activity } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

export function TopBar() {
  const { lang, setLang, t } = useLanguage();
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="h-14 border-b border-border bg-card/80 backdrop-blur-md flex items-center justify-between px-6 sticky top-0 z-30">
      <div className="relative w-80">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder={t("common.search")}
          className="pl-9 h-9 bg-muted/50 border-border text-sm"
        />
      </div>

      <div className="flex items-center gap-2">
        {/* Live scan indicator */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-success/10 border border-success/20 text-sm">
          <Activity className="h-3.5 w-3.5 text-success animate-scan-pulse" />
          <span className="text-success font-medium text-xs">2 {t("common.scanning")}</span>
        </div>

        <Button variant="ghost" size="icon" className="relative">
          <Bell className="h-4 w-4" />
          <Badge className="absolute -top-1 -right-1 h-4 w-4 p-0 flex items-center justify-center text-[10px] bg-destructive text-destructive-foreground">
            5
          </Badge>
        </Button>

        {/* Theme toggle */}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleTheme}
          className="text-muted-foreground hover:text-foreground"
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
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
