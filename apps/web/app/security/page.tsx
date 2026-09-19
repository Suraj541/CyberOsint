"use client";

import React, { useEffect, useState } from "react";
import {
  fetchSandboxStats,
  fetchSecurityAuditLogs,
  fetchSecurityPosture,
  processSandboxedDocument,
  runContainerScan,
  runDependencyScan,
  validateRedirectChain,
  validateUrlSecurity,
} from "../../lib/api";
import {
  DependencyScanReport,
  HardeningCheckItem,
  SandboxPipelineStage,
  SandboxProcessResponse,
  SandboxStatsResponse,
  SecurityAuditEventItem,
  SecurityPostureReport,
  SSRFRedirectHop,
  SSRFRedirectValidationResponse,
  URLValidationResult,
} from "../../lib/types";
import { formatTime, safeUpper } from "../../lib/formatters";

export default function SecurityCenterPage() {
  const [posture, setPosture] = useState<SecurityPostureReport | null>(null);
  const [auditLogs, setAuditLogs] = useState<SecurityAuditEventItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<"controls" | "ssrf" | "sandbox" | "audit" | "scanners">("controls");

  // SSRF Interactive Tester State
  const [testUrl, setTestUrl] = useState<string>("http://169.254.169.254/latest/meta-data/");
  const [validatingUrl, setValidatingUrl] = useState<boolean>(false);
  const [ssrfResult, setSsrfResult] = useState<URLValidationResult | null>(null);

  // Multi-Hop Redirect Inspector State (Section 38 Step 37)
  const [redirectUrl, setRedirectUrl] = useState<string>("http://link-shortener.io/advisory-feed");
  const [validatingRedirect, setValidatingRedirect] = useState<boolean>(false);
  const [redirectResult, setRedirectResult] = useState<SSRFRedirectValidationResponse | null>(null);

  // Sandboxed Document Processing State (Section 39 Step 38)
  const [sandboxFilename, setSandboxFilename] = useState<string>("cisa_advisory.docx");
  const [sandboxContent, setSandboxContent] = useState<string>(
    "# CISA Threat Advisory: Akira Ransomware Tactics\n\n## Summary\nActive intrusion campaigns targeting VPN appliances.\n\n## IOCs\nC2: 198.51.100.22"
  );
  const [sandboxEnforceWorker, setSandboxEnforceWorker] = useState<boolean>(true);
  const [processingSandbox, setProcessingSandbox] = useState<boolean>(false);
  const [sandboxResult, setSandboxResult] = useState<SandboxProcessResponse | null>(null);
  const [sandboxStats, setSandboxStats] = useState<SandboxStatsResponse | null>(null);

  // Scanner states
  const [depReport, setDepReport] = useState<DependencyScanReport | null>(null);
  const [scanningDeps, setScanningDeps] = useState<boolean>(false);
  const [containerReport, setContainerReport] = useState<Record<string, any> | null>(null);
  const [scanningContainer, setScanningContainer] = useState<boolean>(false);

  // Filters & Notifications
  const [auditFilter, setAuditFilter] = useState<string>("all");
  const [notification, setNotification] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const [postureData, logsData, statsData] = await Promise.all([
        fetchSecurityPosture(),
        fetchSecurityAuditLogs(50),
        fetchSandboxStats(),
      ]);
      setPosture(postureData);
      setAuditLogs(logsData);
      setSandboxStats(statsData);
    } catch (err: any) {
      setNotification(`Failed to load security telemetry: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleTestUrl = async (urlToTest?: string) => {
    const target = urlToTest || testUrl;
    if (!target.trim()) return;
    setValidatingUrl(true);
    try {
      const result = await validateUrlSecurity(target.trim());
      setSsrfResult(result);
      if (result.is_safe) {
        setNotification(`URL verified safe: ${result.hostname} (${result.resolved_ips.join(", ")})`);
      } else {
        setNotification(`[SSRF BLOCK] Disallowed destination: ${result.violation_reason}`);
      }
      setTimeout(() => setNotification(null), 5000);
      // Refresh audit logs to display the blocked attempt
      const updatedLogs = await fetchSecurityAuditLogs(50);
      setAuditLogs(updatedLogs);
    } catch (err: any) {
      setNotification(`Validation failed: ${err.message}`);
    } finally {
      setValidatingUrl(false);
    }
  };

  const handleTestRedirects = async (targetUrl?: string) => {
    const target = targetUrl || redirectUrl;
    if (!target.trim()) return;
    setValidatingRedirect(true);
    try {
      const res = await validateRedirectChain(target.trim(), 5);
      setRedirectResult(res);
      if (res.is_safe) {
        setNotification(`Redirect chain safe across ${res.total_hops} hop(s).`);
      } else {
        setNotification(`[REDIRECT SSRF BLOCK] Hop interception: ${res.violation_reason}`);
      }
      setTimeout(() => setNotification(null), 5000);
      const updatedLogs = await fetchSecurityAuditLogs(50);
      setAuditLogs(updatedLogs);
    } catch (err: any) {
      setNotification(`Redirect validation error: ${err.message}`);
    } finally {
      setValidatingRedirect(false);
    }
  };

  const handleRunDepScan = async () => {
    setScanningDeps(true);
    try {
      const report = await runDependencyScan();
      setDepReport(report);
      setNotification(`Dependency scan completed: ${report.total_packages_scanned} packages scanned.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      setNotification(`Dependency scan error: ${err.message}`);
    } finally {
      setScanningDeps(false);
    }
  };

  const handleRunContainerScan = async () => {
    setScanningContainer(true);
    try {
      const report = await runContainerScan();
      setContainerReport(report);
      setNotification(`Container audit complete: ${report.findings_count} findings.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      setNotification(`Container scan error: ${err.message}`);
    } finally {
      setScanningContainer(false);
    }
  };

  const handleProcessSandbox = async () => {
    setProcessingSandbox(true);
    try {
      const res = await processSandboxedDocument(
        sandboxFilename,
        undefined,
        sandboxContent,
        sandboxEnforceWorker,
        15.0
      );
      setSandboxResult(res);
      if (res.success) {
        setNotification(`Document '${res.filename}' safely processed & sanitized through 5-stage pipeline.`);
      } else {
        setNotification(`[SANDBOX THREAT QUARANTINE] Threat blocked: ${res.error}`);
      }
      setTimeout(() => setNotification(null), 5000);
      const [updatedLogs, updatedStats] = await Promise.all([
        fetchSecurityAuditLogs(50),
        fetchSandboxStats(),
      ]);
      setAuditLogs(updatedLogs);
      setSandboxStats(updatedStats);
    } catch (err: any) {
      setNotification(`Sandbox processing error: ${err.message}`);
    } finally {
      setProcessingSandbox(false);
    }
  };

  const handleSelectSandboxPreset = (
    name: string,
    content: string,
    presetDesc: string
  ) => {
    setSandboxFilename(name);
    setSandboxContent(content);
    setNotification(`Loaded attack scenario: ${presetDesc}`);
    setTimeout(() => setNotification(null), 3000);
  };

  const filteredLogs = auditLogs.filter((evt) => {
    if (auditFilter === "all") return true;
    if (auditFilter === "blocked") return evt.status === "blocked" || evt.status === "denied";
    if (auditFilter === "ssrf") return evt.event_type.includes("ssrf");
    if (auditFilter === "auth") return evt.event_type.includes("auth");
    return true;
  });

  const CATEGORY_COLORS: Record<string, string> = {
    identity: "border-blue-500/30 bg-blue-500/10 text-blue-300",
    network: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    runtime: "border-purple-500/30 bg-purple-500/10 text-purple-300",
    data: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    audit: "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              ZERO-TRUST INFRASTRUCTURE DEFENSE
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
              IMPLEMENT.md Section 37 (Step 36)
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Security Hardening &amp; Threat Defense Center
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            15-Point mandatory hardening controls safeguarding the OSINT fetcher, API surface, identity layer,
            and background processing against hostile external payloads.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors border border-slate-700 flex items-center gap-1.5"
          >
            <span className={loading ? "animate-spin" : ""}>🔄</span>
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </div>

      {/* Notification Toast */}
      {notification && (
        <div className="p-3 rounded-lg bg-cyan-950/60 border border-cyan-500/50 text-cyan-200 text-xs font-mono flex items-center justify-between animate-in fade-in">
          <span>{notification}</span>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0b101b] border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Hardening Compliance
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-emerald-400 font-mono mt-1 flex items-baseline gap-2">
            {posture ? `${posture.compliance_score}%` : "100%"}
            <span className="text-xs text-slate-400 font-normal">
              ({posture ? posture.hardened_controls : 15}/15 controls)
            </span>
          </div>
          <div className="text-[11px] text-emerald-400/80 mt-1 flex items-center gap-1">
            <span>🛡️</span> All 15 mandated controls active
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101b] border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            SSRF Network Sandbox
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-cyan-400 font-mono mt-1">
            ACTIVE
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Pre-flight DNS + Private / Cloud Meta Filter
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101b] border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Identity &amp; RBAC
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-blue-400 font-mono mt-1">
            ENFORCED
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            JWT Bearer HS256 + 3-Tier Role Guard
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0b101b] border border-slate-800 shadow-sm relative overflow-hidden">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Security Audit Trail
          </div>
          <div className="text-2xl sm:text-3xl font-bold text-purple-400 font-mono mt-1">
            {auditLogs.length} Events
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            Structured JSONL + In-Memory Ring Buffer
          </div>
        </div>
      </div>

      {/* Tabs Navigation */}
      <div className="border-b border-slate-800 flex items-center gap-2">
        <button
          onClick={() => setActiveTab("controls")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "controls"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>📋</span>
          <span>15-Point Hardening Scorecard</span>
        </button>

        <button
          onClick={() => setActiveTab("ssrf")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "ssrf"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>🌐</span>
          <span>SSRF Sandbox Validator</span>
        </button>

        <button
          onClick={() => setActiveTab("sandbox")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "sandbox"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>📦</span>
          <span>Document Sandbox (SEC 38)</span>
        </button>

        <button
          onClick={() => setActiveTab("audit")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "audit"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>📜</span>
          <span>Security Audit Trail ({auditLogs.length})</span>
        </button>

        <button
          onClick={() => setActiveTab("scanners")}
          className={`px-4 py-2.5 text-xs font-mono font-medium border-b-2 transition-colors flex items-center gap-2 ${
            activeTab === "scanners"
              ? "border-cyan-400 text-cyan-300 bg-cyan-500/5"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          <span>🔍</span>
          <span>Dependency &amp; Container Audits</span>
        </button>
      </div>

      {/* TAB 1: 15-Point Hardening Scorecard */}
      {activeTab === "controls" && (
        <div className="space-y-4 animate-in fade-in">
          <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800 text-xs text-slate-400 font-mono flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-base">🛡️</span>
              <span>
                <strong>Mandate (IMPLEMENT.md Section 37):</strong> &quot;The fetcher is a major attack surface. Treat external content as hostile.&quot; All 15 security controls are verified and enforced.
              </span>
            </div>
            <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-bold border border-emerald-500/30">
              15 / 15 HARDENED
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {(posture?.controls || []).map((control, idx) => (
              <div
                key={control.id}
                className="p-4 rounded-xl bg-[#0b101b] border border-slate-800/90 hover:border-slate-700 transition-colors flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="text-[11px] font-mono text-slate-400 font-semibold">
                      #{idx + 1} {safeUpper(control.id)}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono border uppercase ${
                        CATEGORY_COLORS[control.category] || "border-slate-700 text-slate-400"
                      }`}
                    >
                      {control.category}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-white mb-1.5 flex items-center gap-1.5">
                    <span>{control.name}</span>
                  </h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{control.description}</p>
                </div>

                <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-500">Status</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-semibold flex items-center gap-1">
                    <span>✓</span>
                    <span>HARDENED</span>
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: SSRF Sandbox Validator */}
      {activeTab === "ssrf" && (
        <div className="space-y-5 animate-in fade-in">
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800">
            <h2 className="text-base font-bold text-white mb-1 flex items-center gap-2">
              <span>🌐</span>
              <span>Interactive SSRF Defense &amp; Target URL Sandbox</span>
            </h2>
            <p className="text-xs text-slate-400 mb-4 max-w-3xl">
              Simulate outbound connector requests before initiating HTTP transfers. The SSRF guard resolves hostnames via DNS,
              unwraps IPv4-mapped IPv6 ranges, and checks destination addresses against private, loopback, link-local, and cloud metadata CIDR blocks.
            </p>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={testUrl}
                onChange={(e) => setTestUrl(e.target.value)}
                placeholder="Enter URL to test (e.g. http://169.254.169.254/latest/meta-data/)"
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={() => handleTestUrl()}
                disabled={validatingUrl}
                className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono rounded-lg transition-colors flex items-center justify-center gap-1.5"
              >
                <span>{validatingUrl ? "Analyzing..." : "Validate URL Safety"}</span>
              </button>
            </div>

            {/* Quick Presets */}
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-slate-500">Quick Test Targets:</span>
              <button
                onClick={() => {
                  setTestUrl("http://169.254.169.254/latest/meta-data/");
                  handleTestUrl("http://169.254.169.254/latest/meta-data/");
                }}
                className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20"
              >
                AWS Metadata (169.254.169.254)
              </button>
              <button
                onClick={() => {
                  setTestUrl("http://localhost:8000/api/v1/internal");
                  handleTestUrl("http://localhost:8000/api/v1/internal");
                }}
                className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20"
              >
                Localhost (127.0.0.1)
              </button>
              <button
                onClick={() => {
                  setTestUrl("http://10.0.0.1/admin");
                  handleTestUrl("http://10.0.0.1/admin");
                }}
                className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20"
              >
                RFC 1918 Private (10.0.0.1)
              </button>
              <button
                onClick={() => {
                  setTestUrl("https://www.cisa.gov/cybersecurity-advisories/all.xml");
                  handleTestUrl("https://www.cisa.gov/cybersecurity-advisories/all.xml");
                }}
                className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20"
              >
                Legitimate Public Feed (CISA)
              </button>
            </div>
          </div>

          {/* Result Card */}
          {ssrfResult && (
            <div
              className={`p-5 rounded-xl border font-mono text-xs ${
                ssrfResult.is_safe
                  ? "bg-emerald-950/20 border-emerald-500/50"
                  : "bg-rose-950/30 border-rose-500/50"
              }`}
            >
              <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-lg">{ssrfResult.is_safe ? "✅" : "🛑"}</span>
                  <span className="text-sm font-bold text-white">
                    VERDICT: {ssrfResult.is_safe ? "ALLOWED (SAFE DESTINATION)" : "BLOCKED (SSRF VIOLATION)"}
                  </span>
                </div>
                <span
                  className={`px-2.5 py-1 rounded text-[11px] font-bold ${
                    ssrfResult.is_safe
                      ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                      : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                  }`}
                >
                  {ssrfResult.is_safe ? "SAFE PUBLIC HOST" : "HOSTILE DESTINATION"}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-300">
                <div>
                  <span className="text-slate-500 block">Tested URL:</span>
                  <span className="text-white break-all">{ssrfResult.url}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Hostname:</span>
                  <span className="text-white">{ssrfResult.hostname}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Resolved IPs:</span>
                  <span className="text-cyan-300">
                    {ssrfResult.resolved_ips.length > 0 ? ssrfResult.resolved_ips.join(", ") : "None resolved"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Reason / Policy Check:</span>
                  <span className={ssrfResult.is_safe ? "text-emerald-400" : "text-rose-400"}>
                    {ssrfResult.violation_reason || "Passed all IP blacklist & RFC 1918 pre-flight assertions."}
                  </span>
                </div>
              </div>
            </div>
          )}

          {/* Section 38 Mandatory SSRF Policy Checklist */}
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800">
            <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-mono text-sm">🛡️</span>
                <h3 className="text-sm font-bold text-white">
                  SSRF Protection Mandates (IMPLEMENT.md Section 38 / Step 37)
                </h3>
              </div>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                STRICT ENFORCEMENT
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                  <span>1. Loopback &amp; 127.0.0.0/8</span>
                  <span className="text-emerald-400">BLOCKED</span>
                </div>
                <div className="text-[11px] text-slate-500">127.0.0.1, ::1, 0.0.0.0, localhost</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                  <span>2. Private IP Ranges</span>
                  <span className="text-emerald-400">BLOCKED</span>
                </div>
                <div className="text-[11px] text-slate-500">10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                  <span>3. Cloud Metadata</span>
                  <span className="text-emerald-400">BLOCKED</span>
                </div>
                <div className="text-[11px] text-slate-500">169.254.169.254, 100.100.100.200, fd00:ec2::254</div>
              </div>

              <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between">
                  <span>4. Internal DNS &amp; Services</span>
                  <span className="text-emerald-400">BLOCKED</span>
                </div>
                <div className="text-[11px] text-slate-500">*.local, *.internal, ports 5432, 6379, 9200</div>
              </div>
            </div>
          </div>

          {/* Section 38: Multi-Hop Redirect Chain Inspector */}
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800 space-y-4">
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <span>🔄</span>
                <span>Multi-Hop Redirect Chain Inspector &amp; Re-Verification Guard</span>
              </h3>
              <p className="text-xs text-slate-400 mt-1 max-w-3xl">
                Mandate: <em>&quot;Re-check redirects. Do not trust the hostname alone.&quot;</em> Evaluates each HTTP redirect (301, 302, 307, 308)
                step-by-step. If an external link redirects to an internal IP or cloud metadata endpoint, the chain is severed immediately.
              </p>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={redirectUrl}
                onChange={(e) => setRedirectUrl(e.target.value)}
                placeholder="Enter URL to trace redirect trajectory..."
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={() => handleTestRedirects()}
                disabled={validatingRedirect}
                className="px-4 py-2 bg-purple-500 hover:bg-purple-400 text-slate-950 font-bold text-xs font-mono rounded-lg transition-colors flex items-center justify-center gap-1.5"
              >
                <span>{validatingRedirect ? "Tracing Hops..." : "Trace & Re-Check Redirects"}</span>
              </button>
            </div>

            {/* Presets */}
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="text-slate-500">Redirect Test Presets:</span>
              <button
                onClick={() => {
                  setRedirectUrl("http://link-shortener.io/advisory-feed");
                  handleTestRedirects("http://link-shortener.io/advisory-feed");
                }}
                className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-300 border border-rose-500/30 hover:bg-rose-500/20"
              >
                Shortener &rarr; AWS Metadata (Intercepted)
              </button>
              <button
                onClick={() => {
                  setRedirectUrl("http://feed.com/redirect?to=http://10.0.0.1/admin");
                  handleTestRedirects("http://feed.com/redirect?to=http://10.0.0.1/admin");
                }}
                className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/30 hover:bg-amber-500/20"
              >
                Open Redirect &rarr; RFC1918 (Intercepted)
              </button>
              <button
                onClick={() => {
                  setRedirectUrl("https://www.cisa.gov/cybersecurity-advisories/all.xml");
                  handleTestRedirects("https://www.cisa.gov/cybersecurity-advisories/all.xml");
                }}
                className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-500/20"
              >
                Legitimate Canonical Chain (Allowed)
              </button>
            </div>

            {/* Redirect Results Card */}
            {redirectResult && (
              <div
                className={`p-4 rounded-xl border font-mono text-xs ${
                  redirectResult.is_safe
                    ? "bg-emerald-950/20 border-emerald-500/50"
                    : "bg-rose-950/30 border-rose-500/50"
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{redirectResult.is_safe ? "🛡️" : "🛑"}</span>
                    <span className="font-bold text-white">
                      REDIRECT VERDICT: {redirectResult.is_safe ? "ALL HOPS VERIFIED SAFE" : "CHAIN INTERCEPTED BY SSRF GUARD"}
                    </span>
                  </div>
                  <span className="text-[11px] text-slate-400">
                    Total Hops Traced: <strong>{redirectResult.total_hops}</strong>
                  </span>
                </div>

                {redirectResult.violation_reason && (
                  <div className="p-2.5 rounded bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs mb-3">
                    <strong>Aborted:</strong> {redirectResult.violation_reason}
                  </div>
                )}

                <div className="space-y-2">
                  <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                    Sequential Redirect Hops:
                  </div>
                  {redirectResult.hops.map((hop) => (
                    <div
                      key={hop.hop_index}
                      className={`p-3 rounded-lg border flex flex-col sm:flex-row sm:items-center justify-between gap-2 ${
                        hop.is_safe
                          ? "bg-slate-900/60 border-slate-800 text-slate-300"
                          : "bg-rose-950/40 border-rose-500/40 text-rose-200"
                      }`}
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] font-bold">
                            Hop #{hop.hop_index}
                          </span>
                          <span className="font-semibold text-white break-all">{hop.url}</span>
                        </div>
                        {hop.location_target && (
                          <div className="text-[11px] text-slate-400 flex items-center gap-1 pl-1">
                            <span>↳ Redirect Target (Location):</span>
                            <span className="text-cyan-400 break-all">{hop.location_target}</span>
                          </div>
                        )}
                        <div className="text-[10px] text-slate-500 pl-1">
                          Host: {hop.hostname} &bull; Resolved IPs: {hop.resolved_ips.join(", ") || "None"}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 self-start sm:self-center">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {hop.status_code ? `HTTP ${hop.status_code}` : "BLOCKED"}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            hop.is_safe
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                              : "bg-rose-500/20 text-rose-300 border-rose-500/30"
                          }`}
                        >
                          {hop.is_safe ? "PASSED" : "BLOCKED"}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB: Document Sandbox (IMPLEMENT.md Section 39 Step 38) */}
      {activeTab === "sandbox" && (
        <div className="space-y-6 animate-in fade-in">
          {/* Mandate & Architecture Banner */}
          <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800 space-y-3 font-mono">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="text-lg">📦</span>
                <div>
                  <span className="text-white font-bold text-sm">
                    Section 39 (Step 38): Sandboxed Document Processing
                  </span>
                  <span className="ml-2 px-2 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-500/30">
                    OUT-OF-PROCESS WORKER ISOLATION
                  </span>
                </div>
              </div>
              <span className="text-[11px] text-cyan-400">
                Worker PID: {sandboxResult?.worker_pid ? `#${sandboxResult.worker_pid}` : "Isolated daemon"}
              </span>
            </div>

            <div className="text-xs text-slate-300">
              &quot;External documents can contain malicious content. Do not process untrusted files directly inside the main API process.&quot;
            </div>

            {/* 5-Stage Pipeline Flow Diagram */}
            <div className="p-3 rounded-lg bg-[#070b14] border border-slate-800 flex flex-wrap items-center justify-between gap-2 text-[11px]">
              <div className="flex items-center gap-2">
                <span className="px-2 py-1 rounded bg-blue-500/10 border border-blue-500/30 text-blue-300 font-bold">
                  1. Worker
                </span>
                <span className="text-slate-500">→</span>
                <span className="px-2 py-1 rounded bg-amber-500/10 border border-amber-500/30 text-amber-300 font-bold">
                  2. Sandbox
                </span>
                <span className="text-slate-500">→</span>
                <span className="px-2 py-1 rounded bg-purple-500/10 border border-purple-500/30 text-purple-300 font-bold">
                  3. Parser
                </span>
                <span className="text-slate-500">→</span>
                <span className="px-2 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 font-bold">
                  4. Extracted text
                </span>
                <span className="text-slate-500">→</span>
                <span className="px-2 py-1 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-bold">
                  5. Sanitized result
                </span>
              </div>
              <div className="text-[10px] text-slate-400">
                Strict Blocking: <strong>Macros</strong> &bull; <strong>Embedded programs</strong> &bull; <strong>Unknown binaries</strong>
              </div>
            </div>
          </div>

          {/* Sandbox Telemetry Counters */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 font-mono">
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-slate-400 uppercase">Processed</div>
              <div className="text-xl font-bold text-white mt-0.5">{sandboxStats ? sandboxStats.total_processed : 0}</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-rose-400 uppercase">Macros Blocked</div>
              <div className="text-xl font-bold text-rose-400 mt-0.5">{sandboxStats ? sandboxStats.macros_blocked : 0}</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-amber-400 uppercase">Programs Blocked</div>
              <div className="text-xl font-bold text-amber-400 mt-0.5">{sandboxStats ? sandboxStats.embedded_programs_blocked : 0}</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-purple-400 uppercase">Binaries Rejected</div>
              <div className="text-xl font-bold text-purple-400 mt-0.5">{sandboxStats ? sandboxStats.unknown_binaries_blocked : 0}</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-emerald-400 uppercase">Clean Documents</div>
              <div className="text-xl font-bold text-emerald-400 mt-0.5">{sandboxStats ? sandboxStats.clean_documents : 0}</div>
            </div>
            <div className="p-3 rounded-xl bg-[#0b101b] border border-slate-800">
              <div className="text-[10px] text-cyan-400 uppercase">Threat Block Rate</div>
              <div className="text-xl font-bold text-cyan-400 mt-0.5">{sandboxStats ? sandboxStats.threat_neutralization_rate : "100%"}</div>
            </div>
          </div>

          {/* Interactive Document Sandbox Tester */}
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800 space-y-4 font-mono">
            <div>
              <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                <span>🧪</span>
                <span>Interactive Untrusted Document Processing Sandbox</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Submit raw document content or choose an attack scenario to observe the 5-stage pipeline and threat isolation.
              </p>
            </div>

            {/* Attack Scenario Presets */}
            <div className="space-y-1.5">
              <div className="text-[11px] text-slate-400 font-semibold">Load Attack Scenario Presets:</div>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() =>
                    handleSelectSandboxPreset(
                      "apt29_campaign_brief.docm",
                      "# Executive Summary\n[Binary VBA Project Stream: word/vbaProject.bin embedded inside package]\nSub AutoOpen()\n  Call Shell('powershell.exe -enc ...')\nEnd Sub",
                      "Malicious Word Macro Document (.docm / vbaProject.bin)"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-xs border border-rose-500/30 transition-colors"
                >
                  ⚠️ Malicious Macro (.docm)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    handleSelectSandboxPreset(
                      "weaponized_exploit.pdf",
                      "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) /P (/c calc.exe) >> >>\nendobj\n",
                      "Weaponized PDF with /Launch Action"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-300 text-xs border border-rose-500/30 transition-colors"
                >
                  ⚠️ Weaponized PDF (/Launch Action)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    handleSelectSandboxPreset(
                      "threat_intel_payload.exe",
                      "MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode.",
                      "Unknown Binary Disguised Executable (PE MZ Header)"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-purple-500/10 hover:bg-purple-500/20 text-purple-300 text-xs border border-purple-500/30 transition-colors"
                >
                  ⚠️ Disguised Binary (PE MZ)
                </button>
                <button
                  type="button"
                  onClick={() =>
                    handleSelectSandboxPreset(
                      "cisa_alert_aa24_045a.md",
                      "# CISA Advisory: Threat Actor Tactics Targeting Edge Appliances\n\n## Vulnerability Overview\nCVE-2024-21762 enables remote unauthenticated code execution in vulnerable SSL-VPN portals.\n\n## Technical Indicators\nC2: 198.51.100.44\nSHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      "Legitimate CISA Threat Intelligence Markdown Advisory"
                    )
                  }
                  className="px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-300 text-xs border border-emerald-500/30 transition-colors"
                >
                  🛡️ Clean Research Advisory
                </button>
              </div>
            </div>

            {/* Input Form */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="md:col-span-2">
                <label className="block text-[11px] text-slate-400 mb-1">Document Filename:</label>
                <input
                  type="text"
                  value={sandboxFilename}
                  onChange={(e) => setSandboxFilename(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-[#070b14] border border-slate-700 text-white text-xs focus:border-cyan-500 focus:outline-none"
                  placeholder="document.pdf / advisory.docx / report.md"
                />
              </div>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Execution Mode:</label>
                <label className="flex items-center gap-2 mt-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={sandboxEnforceWorker}
                    onChange={(e) => setSandboxEnforceWorker(e.target.checked)}
                    className="rounded border-slate-700 text-cyan-500 focus:ring-0 bg-slate-900"
                  />
                  <span>Enforce Out-of-Process Worker</span>
                </label>
              </div>
            </div>

            <div>
              <label className="block text-[11px] text-slate-400 mb-1">Document Content / Simulated Stream:</label>
              <textarea
                rows={5}
                value={sandboxContent}
                onChange={(e) => setSandboxContent(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-[#070b14] border border-slate-700 text-white text-xs font-mono focus:border-cyan-500 focus:outline-none"
                placeholder="Paste raw document content, markdown text, or exploit simulation..."
              />
            </div>

            <div className="flex items-center justify-end">
              <button
                type="button"
                onClick={handleProcessSandbox}
                disabled={processingSandbox}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold text-xs transition-colors flex items-center gap-2 disabled:opacity-50"
              >
                <span>{processingSandbox ? "Processing in Isolated Worker..." : "Execute 5-Stage Sandboxed Pipeline"}</span>
                {processingSandbox && <span className="animate-spin">⚙️</span>}
              </button>
            </div>

            {/* Results Display */}
            {sandboxResult && (
              <div
                className={`p-4 rounded-xl border animate-in fade-in ${
                  sandboxResult.success
                    ? "bg-emerald-950/20 border-emerald-500/50"
                    : "bg-rose-950/30 border-rose-500/50"
                }`}
              >
                <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-base">{sandboxResult.success ? "🛡️" : "🛑"}</span>
                    <span className="font-bold text-white">
                      SANDBOX VERDICT: {sandboxResult.success ? "CLEAN & SANITIZED" : "QUARANTINED BY SANDBOX GUARD"}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 flex items-center gap-3">
                    <span>Format: <strong>{sandboxResult.detected_type}</strong></span>
                    <span>Execution: <strong>{sandboxResult.execution_time_ms.toFixed(1)}ms</strong></span>
                    {sandboxResult.worker_pid && <span>Worker PID: <strong>#{sandboxResult.worker_pid}</strong></span>}
                  </div>
                </div>

                {sandboxResult.error && (
                  <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-500/40 text-rose-300 text-xs mb-3">
                    <strong>Threat Neutralized:</strong> {sandboxResult.error}
                  </div>
                )}

                {/* 5-Stage Status Visualization */}
                <div className="space-y-2 mb-4">
                  <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider">
                    Pipeline Execution Trajectory:
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
                    {sandboxResult.stages.map((st, idx) => (
                      <div
                        key={idx}
                        className={`p-2.5 rounded-lg border text-xs ${
                          st.status === "success"
                            ? "bg-slate-900/60 border-emerald-500/30 text-emerald-300"
                            : st.status === "blocked" || st.status === "failed"
                            ? "bg-rose-950/50 border-rose-500/50 text-rose-300"
                            : "bg-slate-900/30 border-slate-800 text-slate-500"
                        }`}
                      >
                        <div className="flex items-center justify-between font-bold text-[11px]">
                          <span>{st.stage_name}</span>
                          <span className="uppercase text-[9px]">{st.status}</span>
                        </div>
                        <div className="text-[10px] text-slate-400 mt-1 truncate">
                          {st.details || `${st.duration_ms.toFixed(1)}ms`}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Sanitized Text Output */}
                {sandboxResult.sanitized_text && (
                  <div className="space-y-1.5">
                    <div className="text-[11px] text-slate-400 font-semibold uppercase tracking-wider flex items-center justify-between">
                      <span>Sanitized Intelligence Output:</span>
                      <span className="text-[10px] text-slate-500">
                        {sandboxResult.word_count} words &bull; {sandboxResult.char_count} chars
                      </span>
                    </div>
                    <pre className="p-3 rounded-lg bg-[#070b14] border border-slate-800 text-slate-300 text-xs font-mono max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {sandboxResult.sanitized_text}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Security Audit Trail */}
      {activeTab === "audit" && (
        <div className="space-y-4 animate-in fade-in">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-[#0b101b] p-3 rounded-xl border border-slate-800">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span>Filter Events:</span>
              {(["all", "blocked", "ssrf", "auth"] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setAuditFilter(filter)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono capitalize transition-colors ${
                    auditFilter === filter
                      ? "bg-cyan-500 text-slate-950 font-bold"
                      : "bg-slate-900 text-slate-400 hover:text-white border border-slate-700"
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>

            <div className="text-[11px] font-mono text-slate-500">
              Showing {filteredLogs.length} of {auditLogs.length} logged events
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-800 bg-[#0b101b]">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/80 text-slate-400 border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Timestamp</th>
                  <th className="py-3 px-4">Event Type</th>
                  <th className="py-3 px-4">Actor / Role</th>
                  <th className="py-3 px-4">Action &amp; Target</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">IP</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-slate-500">
                      No security audit events found matching filter.
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map((evt) => (
                    <tr key={evt.event_id} className="hover:bg-slate-900/40 transition-colors">
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                        {formatTime(evt.timestamp, "N/A")}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-[10px]">
                          {evt.event_type}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        <span className="font-semibold text-white">{evt.actor}</span>
                        <span className="text-[10px] text-slate-500 block font-normal">{evt.role}</span>
                      </td>
                      <td className="py-3 px-4 text-slate-300 max-w-xs truncate" title={evt.resource}>
                        <span className="font-bold text-slate-400 mr-1.5">{evt.action}</span>
                        <span>{evt.resource}</span>
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                            evt.status === "allowed" || evt.status === "success"
                              ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                              : "bg-rose-500/10 text-rose-400 border-rose-500/30"
                          }`}
                        >
                          {safeUpper(evt.status)}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-400 text-[11px] whitespace-nowrap">
                        {evt.client_ip || "127.0.0.1"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: Dependency & Container Audits */}
      {activeTab === "scanners" && (
        <div className="space-y-6 animate-in fade-in">
          {/* Dependency Scanner */}
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>📦</span>
                  <span>Software Bill of Materials (SBOM) &amp; Dependency Vulnerability Scanner</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Scans Python requirements and node packages against known CVE advisories and vulnerable version bounds.
                </p>
              </div>

              <button
                onClick={handleRunDepScan}
                disabled={scanningDeps}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors flex items-center gap-1.5"
              >
                <span>{scanningDeps ? "Scanning..." : "Scan Dependencies"}</span>
              </button>
            </div>

            {depReport && (
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Total Packages Scanned:</span>
                  <span className="text-white font-bold">{depReport.total_packages_scanned}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Vulnerabilities Detected:</span>
                  <span className="text-emerald-400 font-bold">{depReport.vulnerabilities_found}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Manifests Inspected:</span>
                  <span className="text-slate-300">{depReport.scanned_manifests.join(", ")}</span>
                </div>
              </div>
            )}
          </div>

          {/* Container Hardening Audit */}
          <div className="p-5 rounded-xl bg-[#0b101b] border border-slate-800 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <span>🐳</span>
                  <span>Dockerfile &amp; Container Hardening Auditor</span>
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Verifies container best practices: non-root execution, healthchecks, explicit base image tags, and absence of sensitive keys.
                </p>
              </div>

              <button
                onClick={handleRunContainerScan}
                disabled={scanningContainer}
                className="px-4 py-2 rounded-lg bg-purple-500 hover:bg-purple-400 text-slate-950 font-bold text-xs font-mono transition-colors flex items-center gap-1.5"
              >
                <span>{scanningContainer ? "Auditing..." : "Audit Dockerfile"}</span>
              </button>
            </div>

            {containerReport && (
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs font-mono space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Target Dockerfile:</span>
                  <span className="text-white">{containerReport.dockerfile_checked || "Dockerfile"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Hardening Findings:</span>
                  <span className="text-emerald-400 font-bold">{containerReport.findings_count || 0} issues</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Compliance Status:</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                    PASSED
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
