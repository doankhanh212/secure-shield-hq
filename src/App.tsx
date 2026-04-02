import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { type ReactNode } from "react";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { LanguageProvider } from "@/hooks/use-language";
import { ThemeProvider } from "@/hooks/use-theme";
import Index from "./pages/Index.tsx";
import AssetManagement from "./pages/AssetManagement.tsx";
import SecurityScans from "./pages/SecurityScans.tsx";
import Vulnerabilities from "./pages/Vulnerabilities.tsx";
import Reports from "./pages/Reports.tsx";
import SettingsPage from "./pages/Settings.tsx";
import AssetIntelligence from "./pages/AssetIntelligence.tsx";
import NotFound from "./pages/NotFound.tsx";
import Login from "./pages/Login.tsx";
import { isAuthenticated } from "@/services/api";

const ProtectedRoute = ({ children }: { children: ReactNode }) => {
  if (!isAuthenticated()) return <Navigate to="/login" replace />;
  return <>{children}</>;
};

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
      <LanguageProvider>
        <TooltipProvider>
          <Toaster />
          <Sonner />
          <BrowserRouter>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<ProtectedRoute><Index /></ProtectedRoute>} />
              <Route path="/assets" element={<ProtectedRoute><AssetManagement /></ProtectedRoute>} />
              <Route path="/scans" element={<ProtectedRoute><SecurityScans /></ProtectedRoute>} />
              <Route path="/vulnerabilities" element={<ProtectedRoute><Vulnerabilities /></ProtectedRoute>} />
              <Route path="/asset-intelligence" element={<ProtectedRoute><AssetIntelligence /></ProtectedRoute>} />
              <Route path="/reports" element={<ProtectedRoute><Reports /></ProtectedRoute>} />
              <Route path="/settings" element={<ProtectedRoute><SettingsPage /></ProtectedRoute>} />
              <Route path="*" element={<NotFound />} />
            </Routes>
          </BrowserRouter>
        </TooltipProvider>
      </LanguageProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
