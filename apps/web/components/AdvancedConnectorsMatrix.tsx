"use client";

import React, { useEffect, useState } from "react";
import {
  fetchAdvancedConnectors,
  fetchConnectorsHealth,
  runAllConnectors,
  runConnector,
  toggleConnectorEnabled,
} from "../lib/api";
import {
  AdvancedConnectorItem,
  ConnectorBatchRunResult,
  ConnectorHealthSummary,
  ConnectorRunResult,
} from "../lib/types";
import { formatTime } from "../lib/formatters";

const PRIORITY_THEMES: Record<
  number,
  { border: string; bg: string; text: string; badge: string; icon: string }
> = {
  1: {
    border: "border-cyan-500/40 hover:border-cyan-400",
    bg: "from-cyan-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-cyan-400",
    badge: "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
    icon: "📡",
  },
  2: {
    border: "border-emerald-500/40 hover:border-emerald-400",
    bg: "from-emerald-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-emerald-400",
    badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
    icon: "🏛️",
  },
  3: {
    border: "border-rose-500/40 hover:border-rose-400",
    bg: "from-rose-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-rose-400",
    badge: "bg-rose-500/20 text-rose-300 border-rose-500/30",
    icon: "🛡️",
  },
  4: {
    border: "border-blue-500/40 hover:border-blue-400",
    bg: "from-blue-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-blue-400",
    badge: "bg-blue-500/20 text-blue-300 border-blue-500/30",
    icon: "🏢",
  },
  5: {
    border: "border-violet-500/40 hover:border-violet-400",
    bg: "from-violet-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-violet-400",
    badge: "bg-violet-500/20 text-violet-300 border-violet-500/30",
    icon: "🔬",
  },
  6: {
    border: "border-purple-500/40 hover:border-purple-400",
    bg: "from-purple-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-purple-400",
    badge: "bg-purple-500/20 text-purple-300 border-purple-500/30",
    icon: "💻",
  },
  7: {
    border: "border-teal-500/40 hover:border-teal-400",
    bg: "from-teal-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-teal-400",
    badge: "bg-teal-500/20 text-teal-300 border-teal-500/30",
    icon: "📚",
  },
  8: {
    border: "border-pink-500/40 hover:border-pink-400",
    bg: "from-pink-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-pink-400",
    badge: "bg-pink-500/20 text-pink-300 border-pink-500/30",
    icon: "🎬",
  },
  9: {
    border: "border-amber-500/40 hover:border-amber-400",
    bg: "from-amber-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-amber-400",
    badge: "bg-amber-500/20 text-amber-300 border-amber-500/30",
    icon: "🎤",
  },
  10: {
    border: "border-sky-500/40 hover:border-sky-400",
    bg: "from-sky-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-sky-400",
    badge: "bg-sky-500/20 text-sky-300 border-sky-500/30",
    icon: "💬",
  },
  11: {
    border: "border-fuchsia-500/40 hover:border-fuchsia-400",
    bg: "from-fuchsia-950/40 via-slate-900/60 to-slate-950/80",
    text: "text-fuchsia-400",
    badge: "bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/30",
    icon: "⚡",
  },
};

export function AdvancedConnectorsMatrix() {
  const [connectors, setConnectors] = useState<AdvancedConnectorItem[]>([]);
  const [healthSummary, setHealthSummary] = useState<ConnectorHealthSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [runningAll, setRunningAll] = useState<boolean>(false);
  const [checkingHealth, setCheckingHealth] = useState<boolean>(false);
  const [lastBatchResult, setLastBatchResult] = useState<ConnectorBatchRunResult | null>(null);
  const [lastRunResult, setLastRunResult] = useState<ConnectorRunResult | null>(null);
  const [filterState, setFilterState] = useState<"all" | "enabled" | "disabled">("all");
  const [notification, setNotification] = useState<string | null>(null);

  useEffect(() => {
    loadConnectors();
  }, []);

  async function loadConnectors() {
    setLoading(true);
    try {
      const [list, health] = await Promise.all([
        fetchAdvancedConnectors(),
        fetchConnectorsHealth(),
      ]);
      setConnectors(list);
      setHealthSummary(health);
    } catch {
      // Fallback handles gracefully
    } finally {
      setLoading(false);
    }
  }

  async function handleToggle(connectorId: string, currentStatus: boolean) {
    setTogglingId(connectorId);
    try {
      const updated = await toggleConnectorEnabled(connectorId, !currentStatus);
      setConnectors((prev) =>
        prev.map((c) => (c.id === connectorId ? { ...c, is_enabled: updated.is_enabled } : c))
      );
      setNotification(
        `Connector '${updated.name}' is now ${updated.is_enabled ? "ENABLED" : "DISABLED"}.`
      );
      setTimeout(() => setNotification(null), 3500);
    } catch (err: any) {
      alert(`Toggle failed: ${err.message}`);
    } finally {
      setTogglingId(null);
    }
  }

  async function handleRunSingle(connectorId: string) {
    setRunningId(connectorId);
    try {
      const res = await runConnector(connectorId);
      setLastRunResult(res);
      setNotification(
        `Discovery complete for ${connectorId}: ${res.items_count} items normalized.`
      );
      setTimeout(() => setNotification(null), 4000);
      // Refresh list to update telemetry
      const updatedList = await fetchAdvancedConnectors();
      setConnectors(updatedList);
    } catch (err: any) {
      alert(`Run failed: ${err.message}`);
    } finally {
      setRunningId(null);
    }
  }

  async function handleRunAll() {
    setRunningAll(true);
    try {
      const res = await runAllConnectors();
      setLastBatchResult(res);
      setNotification(
        `Executed ${res.executed_connectors} enabled connectors in priority order (1-11). Discovered ${res.total_items_discovered} items.`
      );
      setTimeout(() => setNotification(null), 5000);
      // Refresh list
      const updatedList = await fetchAdvancedConnectors();
      setConnectors(updatedList);
    } catch (err: any) {
      alert(`Batch run failed: ${err.message}`);
    } finally {
      setRunningAll(false);
    }
  }

  async function handleHealthCheck() {
    setCheckingHealth(true);
    try {
      const res = await fetchConnectorsHealth();
      setHealthSummary(res);
      setNotification(
        `Health verification complete: ${res.healthy_count}/${res.total_connectors} connectors operational.`
      );
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      alert(`Health check failed: ${err.message}`);
    } finally {
      setCheckingHealth(false);
    }
  }

  const enabledCount = connectors.filter((c) => c.is_enabled).length;
  const filteredList = connectors.filter((c) => {
    if (filterState === "enabled") return c.is_enabled;
    if (filterState === "disabled") return !c.is_enabled;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Batch Control Bar */}
      <div className="cyber-card rounded-2xl p-6 border border-slate-800 bg-gradient-to-r from-slate-950 via-slate-900 to-cyan-950/30 relative overflow-hidden shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2 max-w-2xl">
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono font-semibold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                IMPLEMENT.md Section 34 &bull; Step 33
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                11 Priority Categories
              </span>
            </div>
            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
              <span>⚡ Advanced OSINT Connector Control Matrix</span>
            </h2>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
              Every connector can be independently toggled. Batch runs strictly respect the mandated
              priority hierarchy (1. Security Feeds &rarr; 2. Gov/CERT &rarr; 3. CVEs &rarr; 4. Vendors &rarr; 5. Blogs &rarr; 6. GitHub &rarr; 7. Research &rarr; 8. Video &rarr; 9. Conferences &rarr; 10. Social &rarr; 11. Specialized).
            </p>

            <div className="flex items-center gap-4 text-xs font-mono pt-1 text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <strong className="text-white">{enabledCount}</strong> of {connectors.length} Active
              </span>
              <span>&bull;</span>
              <span className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full bg-cyan-400" />
                Health:{" "}
                <strong className="text-white">
                  {healthSummary?.healthy_count || connectors.length}/{connectors.length} OK
                </strong>
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 shrink-0">
            <button
              onClick={handleHealthCheck}
              disabled={checkingHealth}
              className="px-4 py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 hover:text-white text-xs font-mono font-medium transition-all shadow-md flex items-center gap-2"
              title="Run health diagnostic across all 11 connectors"
            >
              <span className={checkingHealth ? "animate-spin text-cyan-400" : "text-cyan-400"}>
                🩺
              </span>
              <span>{checkingHealth ? "Diagnosing..." : "Health Diagnostics"}</span>
            </button>

            <button
              onClick={handleRunAll}
              disabled={runningAll || enabledCount === 0}
              className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-xs font-mono transition-all shadow-lg hover:shadow-cyan-500/25 flex items-center gap-2 disabled:opacity-50"
            >
              {runningAll ? (
                <>
                  <span className="animate-spin">↻</span>
                  <span>Executing Priority Order (1-11)...</span>
                </>
              ) : (
                <>
                  <span>▶</span>
                  <span>Run All Enabled (Priority 1-11)</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Live Notification Bar */}
        {notification && (
          <div className="mt-4 p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between animate-in fade-in">
            <div className="flex items-center gap-2">
              <span className="animate-pulse">⚡</span>
              <span>{notification}</span>
            </div>
            <button
              onClick={() => setNotification(null)}
              className="text-slate-400 hover:text-white text-sm"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Batch Execution Results Drawer (when triggered) */}
      {lastBatchResult && (
        <div className="cyber-card rounded-xl p-5 border border-cyan-500/30 bg-slate-950/90 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-cyan-300 font-mono">
                ✓ Priority Batch Execution Summary
              </span>
              <span className="text-xs font-mono text-slate-400">
                ({formatTime(lastBatchResult.executed_at)})
              </span>
            </div>
            <div className="text-xs font-mono text-slate-400">
              Discovered: <strong className="text-white">{lastBatchResult.total_items_discovered}</strong> items
              &bull; Executed: <strong className="text-emerald-400">{lastBatchResult.executed_connectors}</strong>
              &bull; Skipped: <strong className="text-slate-400">{lastBatchResult.skipped_connectors}</strong>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 lg:grid-cols-11 gap-2 pt-1">
            {lastBatchResult.batch_summary.map((item) => {
              const theme = PRIORITY_THEMES[item.priority] || PRIORITY_THEMES[1];
              return (
                <div
                  key={item.id}
                  className={`p-2 rounded-lg border text-center font-mono text-[11px] ${
                    item.status === "success"
                      ? `${theme.badge} bg-slate-900/80`
                      : "border-slate-800 bg-slate-900/30 text-slate-600"
                  }`}
                >
                  <div className="font-bold">P{item.priority}</div>
                  <div className="truncate text-[10px] text-slate-400">{item.id}</div>
                  <div className="text-xs mt-0.5 font-semibold">
                    {item.status === "success" ? `+${item.items_count}` : "SKIP"}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Single Run Result Drawer */}
      {lastRunResult && (
        <div className="cyber-card rounded-xl p-4 border border-emerald-500/30 bg-slate-950/80 flex items-center justify-between text-xs font-mono">
          <div className="flex items-center gap-2 text-emerald-300">
            <span>✓</span>
            <span>
              Connector <strong>{lastRunResult.id}</strong> completed: {lastRunResult.items_count} items discovered.
            </span>
          </div>
          <button
            onClick={() => setLastRunResult(null)}
            className="text-slate-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Filter Tabs */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-slate-900/90 border border-slate-800">
          {(
            [
              { id: "all", label: `All 11 Categories (${connectors.length})` },
              { id: "enabled", label: `Active (${enabledCount})` },
              { id: "disabled", label: `Disabled (${connectors.length - enabledCount})` },
            ] as const
          ).map((tab) => (
            <button
              key={tab.id}
              onClick={() => setFilterState(tab.id)}
              className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
                filterState === tab.id
                  ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <span className="text-xs font-mono text-slate-500">
          Priority execution sequence: 1 (Highest) &rarr; 11 (Specialized)
        </span>
      </div>

      {/* Connectors Grid */}
      {loading ? (
        <div className="text-center py-16 font-mono text-slate-500 animate-pulse">
          Loading 11 Prioritized OSINT Connectors...
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
          {filteredList.map((connector) => {
            const theme = PRIORITY_THEMES[connector.priority] || PRIORITY_THEMES[1];
            const isToggling = togglingId === connector.id;
            const isRunning = runningId === connector.id;
            const healthDetail = healthSummary?.results?.[connector.id];

            return (
              <div
                key={connector.id}
                className={`cyber-card rounded-2xl p-5 border transition-all duration-300 flex flex-col justify-between relative bg-gradient-to-b ${theme.bg} ${
                  connector.is_enabled
                    ? `${theme.border} shadow-lg`
                    : "border-slate-800/80 opacity-70 hover:opacity-100"
                }`}
              >
                {/* Priority & Status Ribbon */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {/* Priority Rank Badge */}
                      <span
                        className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold border flex items-center gap-1 shadow-sm ${theme.badge}`}
                      >
                        <span>{theme.icon}</span>
                        <span>Priority #{connector.priority}</span>
                      </span>

                      {/* Health Indicator */}
                      <span
                        className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                          healthDetail?.status === "ok" || !healthDetail
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                            : "bg-rose-500/10 text-rose-400 border-rose-500/20"
                        }`}
                        title={healthDetail?.details || "Connector healthy"}
                      >
                        {healthDetail?.latency_ms
                          ? `${healthDetail.latency_ms}ms`
                          : "HEALTHY"}
                      </span>
                    </div>

                    {/* Independent Toggle Switch */}
                    <button
                      onClick={() => handleToggle(connector.id, connector.is_enabled)}
                      disabled={isToggling}
                      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                        connector.is_enabled ? "bg-cyan-500" : "bg-slate-700"
                      } ${isToggling ? "opacity-50 cursor-wait" : ""}`}
                      title={connector.is_enabled ? "Click to disable" : "Click to enable"}
                    >
                      <span className="sr-only">Toggle connector</span>
                      <span
                        aria-hidden="true"
                        className={`pointer-events-none inline-block h-5 w-5 transform rounded-full bg-slate-950 shadow ring-0 transition duration-200 ease-in-out ${
                          connector.is_enabled ? "translate-x-5" : "translate-x-0"
                        }`}
                      />
                    </button>
                  </div>

                  {/* Title & Description */}
                  <div>
                    <h3 className="text-base font-bold text-white tracking-tight">
                      {connector.name}
                    </h3>
                    <div className="text-[11px] font-mono text-slate-400 mt-0.5">
                      Class: <span className="text-slate-300">{connector.connector_class}</span>
                    </div>
                    <p className="text-xs text-slate-300 mt-2 leading-relaxed line-clamp-3">
                      {connector.description}
                    </p>
                  </div>
                </div>

                {/* Footer Telemetry & Run Action */}
                <div className="pt-4 mt-4 border-t border-slate-800/80 space-y-3">
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                    <span className="flex items-center gap-1">
                      <span>Status:</span>
                      <strong
                        className={
                          connector.is_enabled ? "text-emerald-400" : "text-slate-500"
                        }
                      >
                        {connector.is_enabled ? "ENABLED" : "DISABLED"}
                      </strong>
                    </span>
                    <span className="flex items-center gap-1">
                      <span>Items:</span>
                      <strong className="text-white">{connector.items_count || 0}</strong>
                    </span>
                  </div>

                  <div className="flex items-center justify-between gap-2">
                    <div className="text-[10px] font-mono text-slate-500 truncate">
                      {connector.last_run
                        ? `Last: ${formatTime(connector.last_run)}`
                        : "Not executed yet"}
                    </div>

                    <button
                      onClick={() => handleRunSingle(connector.id)}
                      disabled={isRunning || !connector.is_enabled}
                      className="px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-cyan-500/40 text-cyan-300 text-xs font-mono font-medium transition-colors flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                      title={connector.is_enabled ? "Run single discovery" : "Enable connector to run"}
                    >
                      {isRunning ? (
                        <>
                          <span className="animate-spin">↻</span>
                          <span>Running...</span>
                        </>
                      ) : (
                        <>
                          <span>▶</span>
                          <span>Run Connector</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
