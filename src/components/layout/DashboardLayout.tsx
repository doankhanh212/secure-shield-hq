import { ReactNode } from "react";
import { AppSidebar } from "./AppSidebar";
import { TopBar } from "./TopBar";

export function DashboardLayout({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-screen bg-background">
      <AppSidebar />
      <div className="pl-60 transition-all duration-200">
        <TopBar />
        <main className="p-6">{children}</main>
      </div>
    </div>
  );
}
