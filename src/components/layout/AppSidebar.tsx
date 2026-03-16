import { useLanguage } from "@/hooks/use-language";
import { useLocation, Link } from "react-router-dom";
import {
  LayoutDashboard,
  Server,
  Radar,
  ShieldAlert,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  Shield,
} from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";

const navItems = [
  { key: "nav.overview", icon: LayoutDashboard, path: "/" },
  { key: "nav.assets", icon: Server, path: "/assets" },
  { key: "nav.scans", icon: Radar, path: "/scans" },
  { key: "nav.vulnerabilities", icon: ShieldAlert, path: "/vulnerabilities" },
  { key: "nav.reports", icon: FileText, path: "/reports" },
  { key: "nav.settings", icon: Settings, path: "/settings" },
];

export function AppSidebar() {
  const { t } = useLanguage();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={cn(
        "fixed left-0 top-0 z-40 h-screen bg-navy text-navy-foreground flex flex-col transition-all duration-200",
        collapsed ? "w-16" : "w-60"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-14 border-b border-sidebar-border">
        <Shield className="h-7 w-7 text-sidebar-primary shrink-0" />
        {!collapsed && (
          <span className="text-lg font-bold tracking-tight text-sidebar-accent-foreground">
            HQG Security
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 space-y-1 px-2 overflow-y-auto scrollbar-thin">
        {navItems.map((item) => {
          const isActive =
            item.path === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.path);
          return (
            <Link
              key={item.key}
              to={item.path}
              className={cn(
                "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              )}
            >
              <item.icon className="h-5 w-5 shrink-0" />
              {!collapsed && <span>{t(item.key)}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="flex items-center justify-center h-10 border-t border-sidebar-border text-sidebar-muted hover:text-sidebar-accent-foreground transition-colors"
      >
        {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
      </button>
    </aside>
  );
}
