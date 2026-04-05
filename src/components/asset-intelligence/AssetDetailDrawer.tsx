import { useState } from "react";
import {
  X,
  ChevronDown,
  ChevronRight,
  FileCode,
  AlertTriangle,
  Cpu,
  Link2,
  ShieldCheck,
  Bug,
  ExternalLink,
  Crosshair,
  Flame,
  Wrench,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ConfidenceBadge } from "./ConfidenceBadge";
import type {
  AssetIntelligenceItem,
  AssetVulnerability,
  AssetCVE,
} from "@/services/api";

// ── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-green-500/10 text-green-400 border-green-500/30",
  unscored: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
};

const SEVERITY_LEFT: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-green-500",
  unscored: "border-l-zinc-500",
};

const VULN_NAMES: Record<string, string> = {
  sqli: "SQL Injection",
  time_based_sqli: "SQL Injection (Time-Based)",
  sqli_error: "SQL Injection (Error-Based)",
  xss: "Cross-Site Scripting",
  xss_reflected: "XSS (Reflected)",
  xss_stored: "XSS (Stored)",
  cmdi: "Command Injection",
  lfi: "Local File Inclusion",
  path_traversal: "Path Traversal",
  ssrf: "Server-Side Request Forgery",
  open_redirect: "Open Redirect",
  info_disclosure: "Information Disclosure",
};

// ── Vuln Card ─────────────────────────────────────────────────────────────────

interface VulnCardProps {
  vuln: AssetVulnerability;
  selected: boolean;
  onSelect: () => void;
}

function VulnCard({ vuln, selected, onSelect }: VulnCardProps) {
  const sev = vuln.severity?.toLowerCase() ?? "low";
  const displayName = VULN_NAMES[vuln.type] ?? vuln.type;

  return (
    <div
      className={cn(
        "rounded-lg border border-l-4 transition-all duration-150",
        SEVERITY_LEFT[sev] ?? "border-l-border",
        selected
          ? "bg-muted/60 border-border shadow-sm ring-1 ring-[#06b6d4]/30"
          : "bg-background/60 border-border hover:bg-muted/30"
      )}
    >
      {/* Row — always clickable */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left"
        onClick={onSelect}
      >
        {/* Severity dot */}
        <span
          className={cn(
            "w-2 h-2 rounded-full shrink-0",
            sev === "critical" && "bg-red-500",
            sev === "high" && "bg-orange-500",
            sev === "medium" && "bg-yellow-500",
            sev === "low" && "bg-green-500"
          )}
        />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold">{displayName}</span>
            <span
              className={cn(
                "text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border",
                SEVERITY_STYLES[sev]
              )}
            >
              {vuln.severity}
            </span>
            <ConfidenceBadge confidence={vuln.confidence} />
            {vuln.cwe_id && (
              <span className="text-[10px] font-mono text-muted-foreground">{vuln.cwe_id}</span>
            )}
          </div>
          <p className="text-xs font-mono text-muted-foreground mt-0.5 truncate max-w-[340px]">
            {vuln.endpoint}
            {vuln.parameter && (
              <span className="ml-2 bg-muted/60 px-1.5 rounded border border-border">{vuln.parameter}</span>
            )}
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          {vuln.owasp_category && (
            <span className="text-[10px] font-mono text-[#06b6d4]">
              {vuln.owasp_category.split(" ")[0]}
            </span>
          )}
          {vuln.cvss_score != null && vuln.cvss_score > 0 && (
            <span className="text-xs font-mono font-semibold text-muted-foreground">
              CVSS {vuln.cvss_score.toFixed(1)}
            </span>
          )}
          {selected ? (
            <ChevronDown className="h-4 w-4 text-[#06b6d4]" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </div>
      </button>

      {/* Detail panel — only when selected */}
      {selected && (
        <div className="border-t border-border divide-y divide-border/50 animate-in fade-in-0 slide-in-from-top-1 duration-150">

          {/* ── 1. Attack Summary ─────────────────────────────────────────── */}
          <div className="px-4 py-3.5 space-y-2">
            <div className="flex items-center gap-2 mb-1">
              <Crosshair className="h-3.5 w-3.5 text-[#06b6d4]" />
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Attack Summary</span>
            </div>
            {(vuln.owasp_category || vuln.cwe_id || (vuln.cvss_score != null && vuln.cvss_score > 0) || vuln.detection_method) && (
              <div className="flex flex-wrap gap-2">
                {vuln.owasp_category && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#06b6d4]/10 text-[#06b6d4] border border-[#06b6d4]/30">
                    {vuln.owasp_category}
                  </span>
                )}
                {vuln.owasp_source && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/40 text-muted-foreground border border-border">
                    src: {vuln.owasp_source}
                  </span>
                )}
                {vuln.cwe_id && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border">
                    {vuln.cwe_id}
                  </span>
                )}
                {vuln.cvss_score != null && vuln.cvss_score > 0 ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/60 text-foreground border border-border">
                    CVSS {vuln.cvss_score.toFixed(1)}
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">
                    Unscored
                  </span>
                )}
                {vuln.detection_method && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-muted/60 text-muted-foreground border border-border">
                    via {vuln.detection_method}
                  </span>
                )}
              </div>
            )}
            <p className="text-xs text-foreground/80 leading-relaxed">
              {vuln.explanation?.trim() || "Not available"}
            </p>
          </div>

          {/* ── 2. Proof of Exploit ───────────────────────────────────────── */}
          <div className="px-4 py-3.5 space-y-2">
            <div className="flex items-center gap-2 mb-1">
              <FileCode className="h-3.5 w-3.5 text-yellow-400" />
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Proof of Exploit</span>
            </div>
            {vuln.payload || vuln.evidence ? (
              <>
                {vuln.payload && (
                  <div>
                    <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide font-medium">Payload</p>
                    <pre className="text-xs font-mono bg-[#06b6d4]/5 border border-[#06b6d4]/20 rounded px-3 py-2 overflow-x-auto break-all whitespace-pre-wrap text-foreground/90">
                      {vuln.payload}
                    </pre>
                  </div>
                )}
                {vuln.evidence && (
                  <div>
                    <p className="text-[10px] text-muted-foreground mb-1 uppercase tracking-wide font-medium">Response / Evidence</p>
                    <pre className="text-xs font-mono bg-muted/60 border border-border rounded px-3 py-2 overflow-x-auto whitespace-pre-wrap break-all max-h-32 text-foreground/80">
                      {vuln.evidence}
                    </pre>
                  </div>
                )}
              </>
            ) : (
              <p className="text-xs text-muted-foreground">
                Not available —{" "}
                <span className="text-foreground/60">
                  detected via {vuln.detection_method || "automated scanner"}
                  {vuln.confidence ? ` with ${vuln.confidence} confidence` : ""}
                </span>
              </p>
            )}
          </div>

          {/* ── 3. Impact ─────────────────────────────────────────────────── */}
          <div className="px-4 py-3.5 space-y-1">
            <div className="flex items-center gap-2 mb-1">
              <Flame className="h-3.5 w-3.5 text-red-400" />
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Impact</span>
            </div>
            <p className="text-xs text-foreground/80 leading-relaxed">
              {vuln.impact?.trim() || "Not available"}
            </p>
          </div>

          {/* ── 4. Affected Endpoint ──────────────────────────────────────── */}
          <div className="px-4 py-3.5 space-y-1">
            <div className="flex items-center gap-2 mb-1">
              <Link2 className="h-3.5 w-3.5 text-[#06b6d4]" />
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Affected Endpoint</span>
            </div>
            <p className="text-xs font-mono break-all text-foreground/90">{vuln.endpoint}</p>
            {vuln.parameter && (
              <p className="text-xs font-mono text-muted-foreground mt-0.5">
                Parameter:{" "}
                <span className="bg-muted/80 px-1.5 rounded border border-border">{vuln.parameter}</span>
              </p>
            )}
          </div>

          {/* ── 5. Recommended Fix ────────────────────────────────────────── */}
          <div className="px-4 py-3.5 space-y-1">
            <div className="flex items-center gap-2 mb-1">
              <Wrench className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Recommended Fix</span>
            </div>
            <p className="text-xs text-foreground/80 leading-relaxed">
              {vuln.remediation?.trim() || "Not available"}
            </p>
          </div>

          {/* ── 6. Verification Details ───────────────────────────────────── */}
          {vuln.verification_steps && vuln.verification_steps.length > 0 && (
            <div className="px-4 py-3.5 space-y-1">
              <div className="flex items-center gap-2 mb-1">
                <ShieldCheck className="h-3.5 w-3.5 text-[#06b6d4]" />
                <span className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">Verification Details</span>
              </div>
              <ol className="space-y-1">
                {vuln.verification_steps.map((step, i) => (
                  <li key={i} className="text-xs text-foreground/80 flex gap-2">
                    <span className="text-muted-foreground shrink-0 font-mono">{i + 1}.</span>
                    <span className="leading-relaxed">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── CVE Row ───────────────────────────────────────────────────────────────────

function CveRow({ cve }: { cve: AssetCVE }) {
  const sev = cve.severity?.toLowerCase() ?? "low";
  return (
    <div className="flex items-center gap-3 py-2 border-b border-border/40 last:border-0">
      <span className="font-mono text-xs text-[#06b6d4] font-semibold w-36 shrink-0">{cve.id}</span>
      <div className="flex-1 min-w-0">
        {cve.summary && (
          <p className="text-xs text-muted-foreground truncate">{cve.summary}</p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        {cve.is_actively_exploited && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 uppercase tracking-wide">
            KEV
          </span>
        )}
        <span className="text-xs font-mono font-semibold text-muted-foreground">
          {cve.cvss.toFixed(1)}
        </span>
        <span
          className={cn(
            "text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase",
            SEVERITY_STYLES[sev]
          )}
        >
          {cve.severity}
        </span>
      </div>
    </div>
  );
}

// ── Main Drawer ───────────────────────────────────────────────────────────────

interface AssetDetailDrawerProps {
  asset: AssetIntelligenceItem;
  onClose: () => void;
}

export function AssetDetailDrawer({ asset, onClose }: AssetDetailDrawerProps) {
  // Derive priority badge from real signals
  const hasKev = asset.has_kev ?? asset.cves.some((c) => c.is_actively_exploited);
  const maxCvss = asset.max_cvss ?? (asset.cves.length > 0 ? Math.max(...asset.cves.map((c) => c.cvss)) : null);
  const confirmedCount = asset.confirmed_vuln_count ?? asset.vulnerabilities.filter((v) => v.confidence.toLowerCase() === "confirmed" || v.confidence.toLowerCase() === "high").length;

  const priorityLabel = hasKev ? "KEV" : maxCvss !== null && maxCvss >= 9.0 ? "Critical" : maxCvss !== null && maxCvss >= 7.0 ? "High" : confirmedCount > 0 ? "Medium" : "Low";
  const priorityBadge = hasKev
    ? "bg-red-500/15 border-red-500/40 text-red-400"
    : maxCvss !== null && maxCvss >= 9.0
      ? "bg-red-500/15 border-red-500/40 text-red-400"
      : maxCvss !== null && maxCvss >= 7.0
        ? "bg-orange-500/15 border-orange-500/40 text-orange-400"
        : confirmedCount > 0
          ? "bg-yellow-500/15 border-yellow-500/40 text-yellow-400"
          : "bg-green-500/15 border-green-500/40 text-green-400";

  // Group vulns by type
  const vulnGroups = asset.vulnerabilities.reduce<Record<string, AssetVulnerability[]>>(
    (acc, v) => {
      const key = VULN_NAMES[v.type] ?? v.type;
      if (!acc[key]) acc[key] = [];
      acc[key].push(v);
      return acc;
    },
    {}
  );

  // Sort groups: confirmed first, then by count
  const sortedGroups = Object.entries(vulnGroups).sort(([, a], [, b]) => {
    const aConfirmed = a.filter((v) => v.confidence === "confirmed").length;
    const bConfirmed = b.filter((v) => v.confidence === "confirmed").length;
    if (bConfirmed !== aConfirmed) return bConfirmed - aConfirmed;
    return b.length - a.length;
  });

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm animate-in fade-in-0 duration-200"
        onClick={onClose}
      />

      {/* Panel */}
      <div className="fixed right-0 top-0 z-50 h-screen w-full max-w-2xl bg-card border-l border-border flex flex-col animate-in slide-in-from-right-full duration-300 shadow-2xl">
        {/* Header */}
        <div className="flex items-start gap-4 px-6 py-5 border-b border-border shrink-0">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span
                className={cn(
                  "text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide",
                  priorityBadge
                )}
              >
                {priorityLabel}
              </span>
              <h2 className="text-lg font-mono font-bold truncate">{asset.host}</h2>
            </div>
            {maxCvss !== null && (
              <div className="mt-2 flex items-center gap-2 text-xs">
                <span className="text-muted-foreground">Max CVSS</span>
                <span className="font-mono font-bold">{maxCvss.toFixed(1)}</span>
                {hasKev && (
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 uppercase tracking-wide">
                    KEV
                  </span>
                )}
              </div>
            )}
            <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
              <span>{asset.vulnerabilities.length} vulnerabilities</span>
              <span>•</span>
              <span>{asset.cves.length} CVEs</span>
              <span>•</span>
              <span>{asset.technologies.length} technologies</span>
              <span>•</span>
              <span>{asset.endpoints.length} endpoints</span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-md hover:bg-muted/50 text-muted-foreground hover:text-foreground transition-colors shrink-0"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-6 py-5 space-y-7">

          {/* Section A: Technologies */}
          {asset.technologies.length > 0 && (
            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold mb-3">
                <Cpu className="h-4 w-4 text-[#06b6d4]" />
                Technologies
              </h3>
              <div className="flex flex-wrap gap-2">
                {asset.technologies.map((tech) => (
                  <div
                    key={tech.name}
                    className="flex items-center gap-2 bg-muted/40 border border-border rounded-lg px-3 py-2"
                  >
                    <span className="text-sm font-medium">{tech.name}</span>
                    {tech.version && (
                      <span className="text-[10px] font-mono bg-[#06b6d4]/10 text-[#06b6d4] border border-[#06b6d4]/30 px-1.5 py-0.5 rounded">
                        {tech.version}
                      </span>
                    )}
                    {tech.categories && tech.categories.length > 0 && (
                      <span className="text-[10px] text-muted-foreground">
                        {tech.categories[0]}
                      </span>
                    )}
                    {tech.confidence < 1 && (
                      <span className="text-[10px] text-muted-foreground/60">
                        {Math.round(tech.confidence * 100)}%
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Section B: Vulnerabilities grouped by type */}
          {sortedGroups.length > 0 && (
            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold mb-3">
                <Bug className="h-4 w-4 text-orange-400" />
                Vulnerabilities
                <span className="text-xs font-normal text-muted-foreground">
                  ({asset.vulnerabilities.length} total)
                </span>
              </h3>
              <div className="space-y-4">
                {sortedGroups.map(([typeName, vulns]) => (
                  <VulnGroup key={typeName} typeName={typeName} vulns={vulns} />
                ))}
              </div>
            </section>
          )}

          {/* Section C: CVEs */}
          {asset.cves.length > 0 && (
            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold mb-3">
                <AlertTriangle className="h-4 w-4 text-red-400" />
                CVE Intelligence
                <span className="text-xs font-normal text-muted-foreground">
                  ({asset.cves.length} CVEs)
                </span>
              </h3>
              <div className="bg-muted/20 border border-border rounded-lg overflow-hidden">
                <div className="px-4 py-1">
                  {asset.cves
                    .slice()
                    .sort((a, b) => b.cvss - a.cvss)
                    .map((cve) => (
                      <CveRow key={cve.id} cve={cve} />
                    ))}
                </div>
              </div>
            </section>
          )}

          {/* Section D: Endpoints */}
          {asset.endpoints.length > 0 && (
            <section>
              <h3 className="flex items-center gap-2 text-sm font-semibold mb-3">
                <Link2 className="h-4 w-4 text-muted-foreground" />
                Endpoints
                <span className="text-xs font-normal text-muted-foreground">
                  ({asset.endpoints.length})
                </span>
              </h3>
              <div className="bg-muted/20 border border-border rounded-lg max-h-48 overflow-y-auto">
                {asset.endpoints.map((ep) => (
                  <div
                    key={ep}
                    className="flex items-center gap-2 px-4 py-2 border-b border-border/40 last:border-0 group"
                  >
                    <span className="text-xs font-mono text-muted-foreground flex-1 truncate">{ep}</span>
                    <a
                      href={ep}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <ExternalLink className="h-3 w-3 text-muted-foreground hover:text-foreground" />
                    </a>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      </div>
    </>
  );
}

// ── Vuln Group (collapsible, owns selection state) ───────────────────────────

function VulnGroup({
  typeName,
  vulns,
}: {
  typeName: string;
  vulns: AssetVulnerability[];
}) {
  const [open, setOpen] = useState(true);
  // selectedKey = "<type>|<endpoint>|<parameter>" — unique enough for dedup'd vulns
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const confirmedCount = vulns.filter((v) => v.confidence === "confirmed").length;
  const highestSev = vulns.reduce<string>((acc, v) => {
    const order = ["critical", "high", "medium", "low", "unscored"];
    const accIdx = order.indexOf(acc);
    const vIdx = order.indexOf(v.severity?.toLowerCase() ?? "unscored");
    return vIdx >= 0 && vIdx < accIdx ? v.severity.toLowerCase() : acc;
  }, "unscored");

  const sorted = vulns.slice().sort((a, b) => {
    const confOrder = ["confirmed", "high", "medium", "low"];
    return confOrder.indexOf(a.confidence) - confOrder.indexOf(b.confidence);
  });

  function vulnKey(v: AssetVulnerability, i: number) {
    return `${v.type}|${v.endpoint}|${v.parameter ?? ""}|${i}`;
  }

  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-2.5 bg-muted/30 hover:bg-muted/50 transition-colors text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <span
          className={cn(
            "text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase",
            SEVERITY_STYLES[highestSev]
          )}
        >
          {highestSev}
        </span>
        <span className="text-sm font-semibold flex-1">{typeName}</span>
        <span className="text-xs text-muted-foreground">{vulns.length} finding{vulns.length !== 1 ? "s" : ""}</span>
        {confirmedCount > 0 && (
          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
            {confirmedCount} confirmed
          </span>
        )}
        {open ? (
          <ChevronDown className="h-4 w-4 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
        )}
      </button>
      {open && (
        <div className="p-3 space-y-2 bg-card/50">
          {sorted.map((vuln, i) => {
            const key = vulnKey(vuln, i);
            return (
              <VulnCard
                key={key}
                vuln={vuln}
                selected={selectedKey === key}
                onSelect={() => setSelectedKey(selectedKey === key ? null : key)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}
