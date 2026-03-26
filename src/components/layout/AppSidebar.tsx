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
        "fixed left-0 top-0 z-40 h-screen bg-sidebar text-sidebar-foreground flex flex-col transition-all duration-300 border-r border-sidebar-border",
        collapsed ? "w-16" : "w-60"
      )}
    >
      {/* Logo */}
      <div className="flex items-center gap-3 px-4 h-14 border-b border-sidebar-border">
        <div className="relative">
          <Shield className="h-7 w-7 text-primary shrink-0" />
          <div className="absolute inset-0 h-7 w-7 bg-primary/20 rounded-full blur-md" />
        </div>
        {!collapsed && (
          <div className="flex flex-col">
            <span className="text-sm font-bold tracking-tight text-sidebar-accent-foreground">
              HQG Security
            </span>
            <span className="text-[10px] text-sidebar-muted font-mono uppercase tracking-widest">
              SOC Platform
            </span>
          </div>
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
                "flex items-center gap-3 px-3 py-2.5 rounded-md text-sm font-medium transition-all duration-200 group",
                isActive
                  ? "bg-[#06b6d4]/10 text-[#06b6d4] border border-[#06b6d4]/20 border-l-2 border-l-[#06b6d4]"
                  : "text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground border border-transparent border-l-2 border-l-transparent"
              )}
            >
              <item.icon className={cn("h-5 w-5 shrink-0 transition-colors", isActive && "text-[#06b6d4]")} />
              {!collapsed && <span>{t(item.key)}</span>}
              {isActive && !collapsed && (
                <div className="ml-auto h-1.5 w-1.5 rounded-full bg-[#06b6d4] animate-pulse" />
              )}
            </Link>
          );
        })}
      </nav>

      {/* Status bar */}
      {!collapsed && (
        <div className="px-3 py-3 border-t border-sidebar-border">
          <div className="flex items-center gap-2 text-[11px] text-sidebar-muted">
            <span className="h-2 w-2 rounded-full bg-success animate-scan-pulse" />
            <span>System Online</span>
          </div>
        </div>
      )}

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
