'use client';

/**
 * Admin Monitoring Dashboard — Section 41 (Step 40): Observability
 * Moved to /admin/monitoring to live under the Admin Panel umbrella.
 * Displays all 9 mandated platform metrics with live auto-refresh.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { formatDateTime, formatTime } from '@/lib/formatters';

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';
const METRICS_URL = `${API_BASE}/api/v1/admin/metrics`;
const REFRESH_INTERVAL_MS = 10_000;

interface LatencyHistogram {
  count: number; sum_ms: number; mean_ms: number;
  p50_ms: number; p95_ms: number; p99_ms: number; max_ms: number;
}
interface MetricsSnapshot {
  connector_success_total: number; connector_failure_total: number;
  items_discovered_total: number; items_ingested_total: number;
  duplicates_detected_total: number; API_errors: number; queue_depth: number;
  processing_latency: LatencyHistogram; search_latency: LatencyHistogram;
  connector_success_by_name: Record<string, number>;
  connector_failure_by_name: Record<string, number>;
  API_errors_by_status_code: Record<string, number>;
  collector_started_at: string; snapshot_at: string;
}

function fmt(n: number | undefined | null): string {
  if (n == null || n < 0) return '—';
  return n.toLocaleString();
}
function fmtMs(ms: number): string {
  if (ms <= 0) return '0 ms';
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms.toFixed(1)} ms`;
}
function timeSince(iso: string): string {
  try {
    const delta = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (delta < 60) return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    return `${Math.floor(delta / 3600)}h ago`;
  } catch { return '—'; }
}

const ACCENT: Record<string, { border: string; glow: string; icon: string }> = {
  cyan:    { border: 'border-cyan-500/25 hover:border-cyan-400/50',    glow: 'hover:shadow-cyan-500/10',    icon: 'text-cyan-400 bg-cyan-500/10' },
  emerald: { border: 'border-emerald-500/25 hover:border-emerald-400/50', glow: 'hover:shadow-emerald-500/10', icon: 'text-emerald-400 bg-emerald-500/10' },
  amber:   { border: 'border-amber-500/25 hover:border-amber-400/50',   glow: 'hover:shadow-amber-500/10',   icon: 'text-amber-400 bg-amber-500/10' },
  rose:    { border: 'border-rose-500/25 hover:border-rose-400/50',     glow: 'hover:shadow-rose-500/10',    icon: 'text-rose-400 bg-rose-500/10' },
  violet:  { border: 'border-violet-500/25 hover:border-violet-400/50', glow: 'hover:shadow-violet-500/10',  icon: 'text-violet-400 bg-violet-500/10' },
  indigo:  { border: 'border-indigo-500/25 hover:border-indigo-400/50', glow: 'hover:shadow-indigo-500/10',  icon: 'text-indigo-400 bg-indigo-500/10' },
};

function MetricCard({ id, label, value, subtitle, accent, icon }: { id: string; label: string; value: string; subtitle?: string; accent: string; icon: string }) {
  const s = ACCENT[accent];
  return (
    <div id={id} className={`cyber-card rounded-2xl p-5 border transition-all duration-300 hover:shadow-xl ${s.border} ${s.glow}`}>
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">{label}</span>
        <span className={`w-9 h-9 rounded-xl flex items-center justify-center text-lg font-bold ${s.icon}`}>{icon}</span>
      </div>
      <span className="text-3xl font-extrabold tracking-tight text-white font-mono">{value}</span>
      {subtitle && <p className="mt-1.5 text-xs text-slate-500 font-mono">{subtitle}</p>}
    </div>
  );
}

function LatencyCard({ id, label, histogram, accent, icon }: { id: string; label: string; histogram: LatencyHistogram; accent: string; icon: string }) {
  const s = ACCENT[accent];
  return (
    <div id={id} className={`cyber-card rounded-2xl p-5 border transition-all duration-300 hover:shadow-xl ${s.border} ${s.glow}`}>
      <div className="flex items-start justify-between mb-4">
        <div>
          <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">{label}</span>
          <p className="text-xs text-slate-600 font-mono mt-0.5">{fmt(histogram.count)} observations</p>
        </div>
        <span className={`w-9 h-9 rounded-xl flex items-center justify-center text-lg ${s.icon}`}>{icon}</span>
      </div>
      <div className="grid grid-cols-3 gap-3 mt-2">
        {[{ l: 'p50', v: fmtMs(histogram.p50_ms) }, { l: 'p95', v: fmtMs(histogram.p95_ms) }, { l: 'p99', v: fmtMs(histogram.p99_ms) }].map(({ l, v }) => (
          <div key={l} className="rounded-lg bg-slate-800/60 px-3 py-2 text-center">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{l}</div>
            <div className="text-base font-bold font-mono text-white mt-0.5">{v}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 flex justify-between text-xs text-slate-600 font-mono">
        <span>mean {fmtMs(histogram.mean_ms)}</span>
        <span>max {fmtMs(histogram.max_ms)}</span>
      </div>
    </div>
  );
}

export default function MonitoringDashboard() {
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMetrics = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setRefreshing(true);
    try {
      const res = await fetch(METRICS_URL, { cache: 'no-store' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setMetrics(await res.json());
      setError(null);
      setLastRefreshed(new Date());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setLoading(false); setRefreshing(false); }
  }, []);

  useEffect(() => {
    fetchMetrics(false);
    timerRef.current = setInterval(() => fetchMetrics(true), REFRESH_INTERVAL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [fetchMetrics]);

  const connectorNames = Array.from(new Set([
    ...Object.keys(metrics?.connector_success_by_name ?? {}),
    ...Object.keys(metrics?.connector_failure_by_name ?? {}),
  ])).sort();

  const errorCodes = Object.entries(metrics?.API_errors_by_status_code ?? {}).sort(([a], [b]) => Number(a) - Number(b));
  const totalRuns = (metrics?.connector_success_total ?? 0) + (metrics?.connector_failure_total ?? 0);
  const successRate = totalRuns > 0 ? `${((metrics!.connector_success_total / totalRuns) * 100).toFixed(1)}%` : '—';

  if (loading && !metrics) {
    return (
      <div className="min-h-screen bg-[#080c14] flex items-center justify-center">
        <div className="text-center space-y-4">
          <div className="w-12 h-12 rounded-full border-2 border-cyan-500/40 border-t-cyan-400 animate-spin mx-auto" />
          <p className="text-slate-400 text-sm font-mono">Loading metrics…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200 font-sans">
      <header className="cyber-glass sticky top-0 z-30 px-6 py-4">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <a href="/admin" className="text-slate-500 hover:text-slate-300 transition-colors text-xs font-mono">← Admin</a>
            <div className="w-px h-4 bg-slate-700" />
            <div>
              <h1 className="text-sm font-bold tracking-tight text-white">Observability Monitoring</h1>
              <p className="text-[10px] text-slate-500 font-mono uppercase tracking-wider">Section 41 · Step 40 · /admin/monitoring</p>
            </div>
          </div>
          <div className="flex items-center gap-4 text-xs font-mono text-slate-500">
            {error && <span className="text-rose-400 bg-rose-500/10 px-2 py-1 rounded-md border border-rose-500/20">⚠ {error}</span>}
            {lastRefreshed && <span className="text-slate-600">refreshed {formatTime(lastRefreshed)}</span>}
            {metrics?.collector_started_at && <span className="text-slate-600">uptime {timeSince(metrics.collector_started_at)}</span>}
            <button id="btn-refresh-metrics" onClick={() => fetchMetrics(false)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors disabled:opacity-50">
              <span className={refreshing ? 'animate-spin' : ''}>↺</span> Refresh
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-screen-2xl mx-auto px-6 py-8 space-y-10">
        <section id="section-counters">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">Platform Counters</h2>
          <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-4">
            <MetricCard id="metric-connector-success"  label="Connector Successes"  value={fmt(metrics?.connector_success_total)}  subtitle={`Success rate: ${successRate}`} accent="emerald" icon="✓" />
            <MetricCard id="metric-connector-failure"  label="Connector Failures"   value={fmt(metrics?.connector_failure_total)}  subtitle={`Total runs: ${fmt(totalRuns)}`} accent="rose"    icon="✕" />
            <MetricCard id="metric-items-discovered"   label="Items Discovered"     value={fmt(metrics?.items_discovered_total)}   subtitle="Raw items from connectors" accent="cyan"    icon="⊕" />
            <MetricCard id="metric-items-ingested"     label="Items Ingested"       value={fmt(metrics?.items_ingested_total)}     subtitle="Persisted to database"     accent="indigo"  icon="⟶" />
            <MetricCard id="metric-duplicates"         label="Duplicates Detected"  value={fmt(metrics?.duplicates_detected_total)} subtitle="Rejected by deduplication" accent="amber"   icon="≡" />
            <MetricCard id="metric-api-errors"         label="API Errors (4xx/5xx)" value={fmt(metrics?.API_errors)}              subtitle={errorCodes.length > 0 ? errorCodes.map(([c, n]) => `${c}: ${n}`).join(' · ') : 'No errors'} accent="rose" icon="⚠" />
            <MetricCard id="metric-queue-depth"        label="Queue Depth"          value={metrics?.queue_depth != null && metrics.queue_depth >= 0 ? fmt(metrics.queue_depth) : '—'} subtitle="Pending ingestion tasks" accent="violet" icon="≋" />
            <MetricCard id="metric-ingest-efficiency"  label="Ingest Efficiency"    value={metrics && metrics.items_discovered_total > 0 ? `${((metrics.items_ingested_total / metrics.items_discovered_total) * 100).toFixed(1)}%` : '—'} subtitle={`${fmt(metrics?.duplicates_detected_total)} dupes filtered`} accent="emerald" icon="η" />
          </div>
        </section>

        <section id="section-latency">
          <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">Latency Histograms</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {metrics?.processing_latency && <LatencyCard id="metric-processing-latency" label="Processing Latency" histogram={metrics.processing_latency} accent="cyan"   icon="⏱" />}
            {metrics?.search_latency     && <LatencyCard id="metric-search-latency"     label="Search Latency"    histogram={metrics.search_latency}     accent="violet" icon="⌕" />}
          </div>
        </section>

        {connectorNames.length > 0 && (
          <section id="section-connectors">
            <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">Per-Connector Breakdown</h2>
            <div className="cyber-card rounded-2xl border border-slate-800/60 overflow-hidden">
              <table className="w-full text-sm" id="table-connector-breakdown">
                <thead><tr className="border-b border-slate-800/60">
                  {['Connector','Successes','Failures','Total','Rate'].map(h => <th key={h} className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wider text-slate-500">{h}</th>)}
                </tr></thead>
                <tbody className="divide-y divide-slate-800/40">
                  {connectorNames.map(name => {
                    const s = metrics?.connector_success_by_name?.[name] ?? 0;
                    const f = metrics?.connector_failure_by_name?.[name] ?? 0;
                    const t = s + f;
                    return (
                      <tr key={name} id={`row-connector-${name.replace(/[^a-z0-9]/gi,'-').toLowerCase()}`} className="hover:bg-slate-800/20">
                        <td className="px-5 py-3 font-mono text-slate-300 text-xs truncate max-w-[220px]">{name}</td>
                        <td className="px-5 py-3 text-right font-mono text-emerald-400 font-semibold">{fmt(s)}</td>
                        <td className="px-5 py-3 text-right font-mono text-rose-400 font-semibold">{fmt(f)}</td>
                        <td className="px-5 py-3 text-right font-mono text-slate-400">{fmt(t)}</td>
                        <td className="px-5 py-3 text-right font-mono text-cyan-400 font-semibold">{t > 0 ? `${((s/t)*100).toFixed(1)}%` : '—'}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {metrics?.snapshot_at && (
          <p className="text-xs font-mono text-slate-700 text-right pb-8">
            Last snapshot: {formatDateTime(metrics.snapshot_at)} · auto-refreshes every {REFRESH_INTERVAL_MS / 1000}s
          </p>
        )}
      </main>
    </div>
  );
}
