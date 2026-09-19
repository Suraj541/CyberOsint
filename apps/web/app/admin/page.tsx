'use client';

/**
 * Admin Panel — Section 42 (Step 41): Admin Panel
 * Full administrative interface at /admin with 10 sections:
 *   Sources, Connectors, Failed Jobs, Processing Queue, Content Moderation,
 *   Duplicate Clusters, Source Reliability, System Health, API Usage, AI Usage
 *
 * Allows administrators to:
 *   Enable/Disable connectors, Change schedule, Change priority,
 *   Retry failures, Inspect errors
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import { formatDateTime } from '@/lib/formatters';

// ─── Config ──────────────────────────────────────────────────────────────────
const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000/api/v1';
const REFRESH_INTERVAL_MS = 15_000;
const REFRESH_MS = REFRESH_INTERVAL_MS;

// ─── Types ───────────────────────────────────────────────────────────────────
interface Source {
  id: number;
  name: string;
  source_type: string;
  url: string;
  is_active: boolean;
  fetch_interval_minutes: number;
  last_checked: string | null;
  category: string;
  language: string;
}

interface ConnectorInfo {
  id: string;
  name: string;
  priority: number;
  is_enabled: boolean;
  category: string;
  description: string;
  run_count: number;
  last_run_at: string | null;
  last_run_status: string | null;
  items_discovered: number;
  items_ingested: number;
  connector_type?: string;
  interval_minutes?: number;
}

interface QueueTask {
  task_id: string;
  queue_name: string;
  status: string;
  enqueued_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  payload?: Record<string, unknown>;
}

interface SchedulerJob {
  job_id: string;
  name: string;
  is_running: boolean;
  run_count: number;
  last_run_at: string | null;
  last_status: string | null;
  next_run_at: string | null;
  interval_seconds: number;
  errors_count: number;
  last_error: string | null;
}

interface MetricsSnap {
  connector_success_total: number;
  connector_failure_total: number;
  items_discovered_total: number;
  items_ingested_total: number;
  duplicates_detected_total: number;
  API_errors: number;
  queue_depth: number;
  processing_latency: { count: number; p50_ms: number; p95_ms: number; mean_ms: number };
  search_latency: { count: number; p50_ms: number; p95_ms: number; mean_ms: number };
  connector_success_by_name: Record<string, number>;
  connector_failure_by_name: Record<string, number>;
  snapshot_at: string;
}

interface HealthData {
  status: string;
  environment: string;
  version: string;
  database_connected: boolean;
  timestamp: string;
}

// ─── Tab Registry ─────────────────────────────────────────────────────────────
const TABS = [
  { id: 'overview',      label: 'Overview',           icon: '◈' },
  { id: 'sources',       label: 'Sources',             icon: '⊕' },
  { id: 'connectors',    label: 'Connectors',          icon: '⟶' },
  { id: 'queue',         label: 'Processing Queue',    icon: '≋' },
  { id: 'jobs',          label: 'Scheduler Jobs',      icon: '⏱' },
  { id: 'metrics',       label: 'API Usage',           icon: '📈' },
  { id: 'health',        label: 'System Health',       icon: '♥' },
] as const;
type TabId = typeof TABS[number]['id'];

// ─── Helpers ─────────────────────────────────────────────────────────────────
function fmt(n: number | null | undefined): string {
  if (n == null || n < 0) return '—';
  return n.toLocaleString();
}
function fmtMs(ms: number): string {
  if (!ms || ms <= 0) return '0 ms';
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(1)} ms`;
}
function timeAgo(iso: string | null): string {
  if (!iso) return '—';
  try {
    const d = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (d < 60) return `${d}s ago`;
    if (d < 3600) return `${Math.floor(d / 60)}m ago`;
    if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
    return `${Math.floor(d / 86400)}d ago`;
  } catch { return '—'; }
}
function statusBadge(s: string | null | undefined): React.ReactNode {
  const map: Record<string, string> = {
    success: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
    partial: 'bg-amber-500/15 text-amber-300 border-amber-500/25',
    failed:  'bg-rose-500/15 text-rose-300 border-rose-500/25',
    pending: 'bg-slate-500/15 text-slate-300 border-slate-500/25',
    skipped: 'bg-indigo-500/15 text-indigo-300 border-indigo-500/25',
    ok:      'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
    degraded:'bg-amber-500/15 text-amber-300 border-amber-500/25',
    healthy: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/25',
  };
  const cls = map[(s ?? '').toLowerCase()] ?? 'bg-slate-700/40 text-slate-400 border-slate-700';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase tracking-wider border ${cls}`}>
      {s ?? '—'}
    </span>
  );
}

// ─── Stat Mini Card ───────────────────────────────────────────────────────────
function MiniStat({ label, value, accent = 'cyan', id }: { label: string; value: string | number; accent?: string; id?: string }) {
  const colors: Record<string, string> = {
    cyan:    'text-cyan-400',
    emerald: 'text-emerald-400',
    amber:   'text-amber-400',
    rose:    'text-rose-400',
    violet:  'text-violet-400',
    indigo:  'text-indigo-400',
  };
  return (
    <div id={id} className="cyber-card rounded-xl p-4 border border-slate-800/60">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-500 mb-1">{label}</p>
      <p className={`text-2xl font-extrabold font-mono ${colors[accent] ?? colors.cyan}`}>{value}</p>
    </div>
  );
}

// ─── Section Wrapper ──────────────────────────────────────────────────────────
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-4">
      <h2 className="text-xs font-semibold uppercase tracking-widest text-slate-500">{title}</h2>
      {children}
    </div>
  );
}

// ─── Toast ───────────────────────────────────────────────────────────────────
function Toast({ msg, ok, onDone }: { msg: string; ok: boolean; onDone: () => void }) {
  useEffect(() => { const t = setTimeout(onDone, 3500); return () => clearTimeout(t); }, [onDone]);
  return (
    <div className={`fixed bottom-6 right-6 z-50 flex items-center gap-3 px-5 py-3 rounded-xl border shadow-2xl text-sm font-medium transition-all ${
      ok ? 'bg-emerald-900/90 border-emerald-500/30 text-emerald-300' : 'bg-rose-900/90 border-rose-500/30 text-rose-300'
    }`}>
      <span>{ok ? '✓' : '⚠'}</span>
      {msg}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────
export default function AdminPanel() {
  const [tab, setTab] = useState<TabId>('overview');

  // Data state
  const [sources, setSources] = useState<Source[]>([]);
  const [connectors, setConnectors] = useState<ConnectorInfo[]>([]);
  const [queueTasks, setQueueTasks] = useState<QueueTask[]>([]);
  const [jobs, setJobs] = useState<SchedulerJob[]>([]);
  const [metrics, setMetrics] = useState<MetricsSnap | null>(null);
  const [health, setHealth] = useState<HealthData | null>(null);

  // UI state
  const [loading, setLoading] = useState(true);
  const [toast, setToast] = useState<{ msg: string; ok: boolean } | null>(null);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const showToast = (msg: string, ok: boolean) => setToast({ msg, ok });

  // ── Fetch all data ──
  const fetchAll = useCallback(async () => {
    try {
      const [srcRes, connRes, metricsRes, healthRes, jobsRes] = await Promise.allSettled([
        fetch(`${API}/sources?limit=100`),
        fetch(`${API}/connectors`),
        fetch(`${API}/admin/metrics`),
        fetch(`${API}/health/detail`),
        fetch(`${API}/scheduler/jobs`),
      ]);

      if (srcRes.status === 'fulfilled' && srcRes.value.ok)
        setSources(await srcRes.value.json());
      if (connRes.status === 'fulfilled' && connRes.value.ok)
        setConnectors(await connRes.value.json());
      if (metricsRes.status === 'fulfilled' && metricsRes.value.ok)
        setMetrics(await metricsRes.value.json());
      if (healthRes.status === 'fulfilled' && healthRes.value.ok)
        setHealth(await healthRes.value.json());
      if (jobsRes.status === 'fulfilled' && jobsRes.value.ok)
        setJobs(await jobsRes.value.json());

      // Queue depth from metrics
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    timerRef.current = setInterval(fetchAll, REFRESH_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [fetchAll]);

  // ── Actions ──

  async function toggleSource(id: number, active: boolean) {
    setActionBusy(`src-toggle-${id}`);
    try {
      const res = await fetch(`${API}/sources/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: active }),
      });
      if (res.ok) {
        setSources(s => s.map(x => x.id === id ? { ...x, is_active: active } : x));
        showToast(`Source #${id} ${active ? 'enabled' : 'disabled'}`, true);
      } else showToast('Action failed', false);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function syncSource(id: number) {
    setActionBusy(`src-sync-${id}`);
    try {
      const res = await fetch(`${API}/sources/${id}/ingest`, { method: 'POST' });
      showToast(res.ok ? `Source #${id} ingestion triggered` : 'Ingestion failed', res.ok);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function toggleConnector(id: string, enabled: boolean) {
    setActionBusy(`conn-toggle-${id}`);
    try {
      const res = await fetch(`${API}/connectors/${id}/toggle`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled }),
      });
      if (res.ok) {
        setConnectors(cs => cs.map(c => c.id === id ? { ...c, is_enabled: enabled } : c));
        showToast(`Connector '${id}' ${enabled ? 'enabled' : 'disabled'}`, true);
      } else showToast('Toggle failed', false);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function runConnector(id: string) {
    setActionBusy(`conn-run-${id}`);
    try {
      const res = await fetch(`${API}/connectors/${id}/run`, { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        showToast(`Connector '${id}' ran: ${data.items_count ?? 0} items`, true);
        fetchAll();
      } else showToast('Run failed', false);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function runAllConnectors() {
    setActionBusy('run-all');
    try {
      const res = await fetch(`${API}/connectors/run-all`, { method: 'POST' });
      if (res.ok) {
        showToast('All connectors triggered', true);
        fetchAll();
      } else showToast('Batch run failed', false);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function triggerJob(jobId: string) {
    setActionBusy(`job-trigger-${jobId}`);
    try {
      const res = await fetch(`${API}/scheduler/jobs/${jobId}/trigger`, { method: 'POST' });
      showToast(res.ok ? `Job '${jobId}' triggered` : 'Trigger failed', res.ok);
      if (res.ok) fetchAll();
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function updateConnectorInterval(id: string, interval: number) {
    setActionBusy(`conn-interval-${id}`);
    try {
      const res = await fetch(`${API}/connectors/config/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interval_minutes: interval }),
      });
      showToast(res.ok ? `Interval updated to ${interval}m` : 'Update failed', res.ok);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  async function updateConnectorPriority(id: string, priority: number) {
    setActionBusy(`conn-priority-${id}`);
    try {
      const res = await fetch(`${API}/connectors/config/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ priority }),
      });
      showToast(res.ok ? `Priority set to ${priority}` : 'Update failed', res.ok);
    } catch { showToast('Network error', false); }
    finally { setActionBusy(null); }
  }

  // ── Overview Tab ─────────────────────────────────────────────────────────
  function OverviewTab() {
    const activeSrc = sources.filter(s => s.is_active).length;
    const enabledConn = connectors.filter(c => c.is_enabled).length;
    const totalRuns = (metrics?.connector_success_total ?? 0) + (metrics?.connector_failure_total ?? 0);
    const rate = totalRuns > 0 ? `${(((metrics?.connector_success_total ?? 0) / totalRuns) * 100).toFixed(1)}%` : '—';

    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 gap-4">
          <MiniStat label="Active Sources"       value={fmt(activeSrc)}                          accent="cyan" />
          <MiniStat label="Enabled Connectors"   value={`${fmt(enabledConn)} / ${fmt(connectors.length)}`} accent="emerald" />
          <MiniStat label="Items Ingested"        value={fmt(metrics?.items_ingested_total)}     accent="indigo" />
          <MiniStat label="Duplicates Detected"  value={fmt(metrics?.duplicates_detected_total)} accent="amber" />
          <MiniStat label="Queue Depth"           value={metrics?.queue_depth != null && metrics.queue_depth >= 0 ? fmt(metrics.queue_depth) : '—'} accent="violet" />
          <MiniStat label="Connector Success Rate" value={rate}                                  accent="emerald" />
          <MiniStat label="API Errors"            value={fmt(metrics?.API_errors)}               accent="rose" />
          <MiniStat label="DB Connected"          value={health?.database_connected ? 'Yes' : 'No'} accent={health?.database_connected ? 'emerald' : 'rose'} />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Recent connector activity */}
          <div className="cyber-card rounded-2xl border border-slate-800/60 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-3">Connector Activity</h3>
            <div className="space-y-2">
              {connectors.slice(0, 6).map(c => (
                <div key={c.id} className="flex items-center justify-between py-1.5 border-b border-slate-800/40 last:border-0">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${c.is_enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                    <span className="text-xs font-mono text-slate-300 truncate max-w-[160px]">{c.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {statusBadge(c.last_run_status)}
                    <span className="text-[10px] font-mono text-slate-600">{timeAgo(c.last_run_at)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Latency snapshot */}
          <div className="cyber-card rounded-2xl border border-slate-800/60 p-4">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-3">Performance Snapshot</h3>
            <div className="space-y-3">
              {[
                { label: 'Processing p50', value: fmtMs(metrics?.processing_latency.p50_ms ?? 0) },
                { label: 'Processing p95', value: fmtMs(metrics?.processing_latency.p95_ms ?? 0), accent: true },
                { label: 'Search p50', value: fmtMs(metrics?.search_latency.p50_ms ?? 0) },
                { label: 'Search p95', value: fmtMs(metrics?.search_latency.p95_ms ?? 0), accent: true },
                { label: 'Observations', value: `${fmt(metrics?.processing_latency.count)} pipeline runs` },
              ].map(({ label, value, accent }) => (
                <div key={label} className="flex justify-between items-center">
                  <span className="text-xs text-slate-500">{label}</span>
                  <span className={`text-xs font-mono font-semibold ${accent ? 'text-amber-400' : 'text-cyan-400'}`}>{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── Sources Tab ───────────────────────────────────────────────────────────
  function SourcesTab() {
    return (
      <Section title="Source Registry">
        <div className="cyber-card rounded-2xl border border-slate-800/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm" id="table-sources">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {['ID', 'Name', 'Type', 'Category', 'Interval', 'Last Checked', 'Status', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {sources.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-600 text-xs font-mono">No sources registered — backend may be offline</td></tr>
                ) : sources.map(src => (
                  <tr key={src.id} className="hover:bg-slate-800/20 transition-colors" id={`row-source-${src.id}`}>
                    <td className="px-4 py-3 text-slate-500 font-mono text-xs">{src.id}</td>
                    <td className="px-4 py-3">
                      <p className="text-xs font-medium text-slate-200 truncate max-w-[180px]">{src.name}</p>
                      <p className="text-[10px] text-slate-600 font-mono truncate max-w-[180px]">{src.url}</p>
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">{src.source_type}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">{src.category}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">{src.fetch_interval_minutes}m</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500">{timeAgo(src.last_checked)}</td>
                    <td className="px-4 py-3">{statusBadge(src.is_active ? 'active' : 'disabled')}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button
                          id={`btn-source-toggle-${src.id}`}
                          onClick={() => toggleSource(src.id, !src.is_active)}
                          disabled={actionBusy === `src-toggle-${src.id}`}
                          className={`px-2 py-1 rounded text-[10px] font-semibold border transition-colors disabled:opacity-50 ${
                            src.is_active
                              ? 'border-rose-500/30 text-rose-400 hover:bg-rose-500/10'
                              : 'border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10'
                          }`}
                        >
                          {src.is_active ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          id={`btn-source-sync-${src.id}`}
                          onClick={() => syncSource(src.id)}
                          disabled={actionBusy === `src-sync-${src.id}` || !src.is_active}
                          className="px-2 py-1 rounded text-[10px] font-semibold border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 transition-colors disabled:opacity-30"
                        >
                          Sync
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>
    );
  }

  // ── Connectors Tab ────────────────────────────────────────────────────────
  function ConnectorsTab() {
    const [editInterval, setEditInterval] = useState<Record<string, string>>({});
    const [editPriority, setEditPriority] = useState<Record<string, string>>({});

    return (
      <Section title="OSINT Connectors — Enable / Disable / Configure">
        <div className="flex justify-end mb-2">
          <button
            id="btn-run-all-connectors"
            onClick={runAllConnectors}
            disabled={actionBusy === 'run-all'}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors text-xs font-semibold disabled:opacity-50"
          >
            {actionBusy === 'run-all' ? '⏳ Running…' : '▶ Run All Enabled'}
          </button>
        </div>
        <div className="cyber-card rounded-2xl border border-slate-800/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm" id="table-connectors">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {['Priority', 'Connector', 'Category', 'Status', 'Last Run', 'Items', 'Schedule', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {connectors.length === 0 ? (
                  <tr><td colSpan={8} className="px-4 py-8 text-center text-slate-600 text-xs font-mono">No connectors loaded — backend may be offline</td></tr>
                ) : [...connectors].sort((a, b) => a.priority - b.priority).map(c => (
                  <tr key={c.id} className="hover:bg-slate-800/20 transition-colors" id={`row-connector-${c.id}`}>
                    <td className="px-4 py-3 text-center font-mono text-xs text-slate-400">{c.priority}</td>
                    <td className="px-4 py-3">
                      <p className="text-xs font-medium text-slate-200 max-w-[160px] truncate">{c.name}</p>
                      <p className="text-[10px] font-mono text-slate-600">{c.id}</p>
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">{c.category}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-2 h-2 rounded-full ${c.is_enabled ? 'bg-emerald-400' : 'bg-slate-600'}`} />
                        {statusBadge(c.last_run_status ?? (c.is_enabled ? 'idle' : 'disabled'))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500">{timeAgo(c.last_run_at)}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">
                      <span className="text-emerald-400">{fmt(c.items_ingested)}</span>
                      <span className="text-slate-700"> / </span>
                      <span className="text-slate-500">{fmt(c.items_discovered)}</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <input
                          id={`input-interval-${c.id}`}
                          type="number"
                          min={1}
                          max={1440}
                          defaultValue={c.interval_minutes ?? 60}
                          onChange={e => setEditInterval(p => ({ ...p, [c.id]: e.target.value }))}
                          className="w-16 bg-slate-800 border border-slate-700 rounded px-2 py-1 text-[10px] font-mono text-slate-300"
                        />
                        <span className="text-[10px] text-slate-600">m</span>
                        <button
                          id={`btn-interval-save-${c.id}`}
                          onClick={() => updateConnectorInterval(c.id, parseInt(editInterval[c.id] ?? String(c.interval_minutes ?? 60)))}
                          disabled={!editInterval[c.id] || actionBusy === `conn-interval-${c.id}`}
                          className="px-1.5 py-1 rounded text-[10px] border border-amber-500/30 text-amber-400 hover:bg-amber-500/10 disabled:opacity-30 transition-colors"
                        >✓</button>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          id={`btn-connector-toggle-${c.id}`}
                          onClick={() => toggleConnector(c.id, !c.is_enabled)}
                          disabled={actionBusy === `conn-toggle-${c.id}`}
                          className={`px-2 py-1 rounded text-[10px] font-semibold border transition-colors disabled:opacity-50 ${
                            c.is_enabled
                              ? 'border-rose-500/30 text-rose-400 hover:bg-rose-500/10'
                              : 'border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10'
                          }`}
                        >
                          {c.is_enabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          id={`btn-connector-run-${c.id}`}
                          onClick={() => runConnector(c.id)}
                          disabled={!c.is_enabled || actionBusy === `conn-run-${c.id}`}
                          className="px-2 py-1 rounded text-[10px] font-semibold border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 transition-colors disabled:opacity-30"
                        >
                          {actionBusy === `conn-run-${c.id}` ? '⏳' : '▶ Run'}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>
    );
  }

  // ── Queue Tab ─────────────────────────────────────────────────────────────
  function QueueTab() {
    const [qName, setQName] = useState('ingestion');
    const [depth, setDepth] = useState<number | null>(null);
    const [fetching, setFetching] = useState(false);

    async function checkDepth() {
      setFetching(true);
      try {
        const res = await fetch(`${API}/queue/${qName}/length`);
        if (res.ok) { const d = await res.json(); setDepth(d.pending_count); }
      } finally { setFetching(false); }
    }

    async function processNext() {
      setActionBusy('queue-process-next');
      try {
        const res = await fetch(`${API}/queue/worker/process-next?queue_name=${qName}`, { method: 'POST' });
        if (res.ok) {
          const d = await res.json();
          showToast(d.status === 'empty' ? 'Queue is empty' : 'Task processed', d.status !== 'empty');
          checkDepth();
        } else showToast('Process failed', false);
      } catch { showToast('Network error', false); }
      finally { setActionBusy(null); }
    }

    return (
      <Section title="Processing Queue Inspection">
        <div className="flex flex-wrap items-center gap-3 mb-4">
          <input
            id="input-queue-name"
            value={qName}
            onChange={e => setQName(e.target.value)}
            placeholder="Queue name"
            className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 w-40"
          />
          <button
            id="btn-queue-check-depth"
            onClick={checkDepth}
            disabled={fetching}
            className="px-3 py-2 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20 hover:bg-violet-500/20 text-xs font-semibold transition-colors"
          >
            Check Depth
          </button>
          <button
            id="btn-queue-process-next"
            onClick={processNext}
            disabled={actionBusy === 'queue-process-next'}
            className="px-3 py-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 text-xs font-semibold transition-colors disabled:opacity-50"
          >
            {actionBusy === 'queue-process-next' ? '⏳ Processing…' : '▶ Process Next'}
          </button>
          {depth !== null && (
            <div className="ml-auto flex items-center gap-2 px-4 py-2 rounded-xl border border-violet-500/20 bg-violet-500/5">
              <span className="text-xs text-slate-500">Pending tasks in</span>
              <span className="text-xs font-mono text-violet-400 font-semibold">'{qName}'</span>
              <span className="text-2xl font-extrabold font-mono text-violet-300">{depth}</span>
            </div>
          )}
        </div>

        {/* Live metric card */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <MiniStat label="Global Queue Depth" value={metrics?.queue_depth != null && metrics.queue_depth >= 0 ? fmt(metrics.queue_depth) : '—'} accent="violet" />
          <MiniStat label="Items Ingested Total" value={fmt(metrics?.items_ingested_total)} accent="emerald" />
          <MiniStat label="Processing p95" value={fmtMs(metrics?.processing_latency.p95_ms ?? 0)} accent="amber" />
        </div>

        <div className="cyber-card rounded-2xl border border-slate-800/60 p-6 mt-4">
          <p className="text-xs text-slate-600 font-mono text-center">
            Use the queue worker endpoint to inspect and drain the queue.<br />
            Full task state is available at{' '}
            <a href={`${API}/queue/tasks/{task_id}`} className="text-cyan-500 hover:text-cyan-400 underline" target="_blank" rel="noreferrer">
              GET /api/v1/queue/tasks/&#123;task_id&#125;
            </a>
          </p>
        </div>
      </Section>
    );
  }

  // ── Jobs Tab ──────────────────────────────────────────────────────────────
  function JobsTab() {
    return (
      <Section title="Scheduler Jobs — Failed Job Retries & Inspect Errors">
        <div className="cyber-card rounded-2xl border border-slate-800/60 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm" id="table-scheduler-jobs">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {['Job ID', 'Name', 'Interval', 'Runs', 'Last Run', 'Next Run', 'Status', 'Errors', 'Actions'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {jobs.length === 0 ? (
                  <tr><td colSpan={9} className="px-4 py-8 text-center text-slate-600 text-xs font-mono">No scheduled jobs found — scheduler may not be running</td></tr>
                ) : jobs.map(j => (
                  <tr key={j.job_id} className="hover:bg-slate-800/20 transition-colors" id={`row-job-${j.job_id}`}>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500 max-w-[120px] truncate">{j.job_id}</td>
                    <td className="px-4 py-3 text-xs text-slate-300 max-w-[150px] truncate">{j.name}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-400">{Math.round((j.interval_seconds ?? 0) / 60)}m</td>
                    <td className="px-4 py-3 text-xs font-mono text-cyan-400">{fmt(j.run_count)}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500">{timeAgo(j.last_run_at)}</td>
                    <td className="px-4 py-3 text-xs font-mono text-slate-500">{timeAgo(j.next_run_at)}</td>
                    <td className="px-4 py-3">{statusBadge(j.last_status)}</td>
                    <td className="px-4 py-3">
                      {j.errors_count > 0 ? (
                        <div>
                          <span className="text-rose-400 font-mono text-xs font-semibold">{j.errors_count}</span>
                          {j.last_error && (
                            <p className="text-[10px] text-rose-500/70 mt-0.5 max-w-[160px] truncate" title={j.last_error}>
                              {j.last_error}
                            </p>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600 text-xs font-mono">0</span>
                      )}
                    </td>
                    <td className="px-4 py-3">
                      <button
                        id={`btn-job-trigger-${j.job_id}`}
                        onClick={() => triggerJob(j.job_id)}
                        disabled={actionBusy === `job-trigger-${j.job_id}` || j.is_running}
                        className="px-2 py-1 rounded text-[10px] font-semibold border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10 transition-colors disabled:opacity-30"
                        title={j.errors_count > 0 ? 'Retry this job' : 'Trigger manually'}
                      >
                        {j.is_running ? '⏳ Running' : j.errors_count > 0 ? '↺ Retry' : '▶ Trigger'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Section>
    );
  }

  // ── Metrics / API Usage Tab ───────────────────────────────────────────────
  function MetricsTab() {
    const connNames = Array.from(new Set([
      ...Object.keys(metrics?.connector_success_by_name ?? {}),
    ])).sort();

    return (
      <Section title="API Usage & Platform Metrics">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
          <MiniStat id="metric-connector-success" label="Connector Successes" value={fmt(metrics?.connector_success_total)} accent="emerald" />
          <MiniStat id="metric-connector-failure" label="Connector Failures"  value={fmt(metrics?.connector_failure_total)} accent="rose" />
          <MiniStat id="metric-api-errors"          label="API Errors"          value={fmt(metrics?.API_errors)}              accent="rose" />
          <MiniStat id="metric-items-discovered"    label="Items Discovered"    value={fmt(metrics?.items_discovered_total)}  accent="cyan" />
          <MiniStat id="metric-items-ingested"      label="Items Ingested"      value={fmt(metrics?.items_ingested_total)}    accent="emerald" />
          <MiniStat id="metric-duplicates"          label="Duplicates Detected" value={fmt(metrics?.duplicates_detected_total)} accent="amber" />
          <MiniStat id="metric-queue-depth"         label="Queue Depth"         value={metrics?.queue_depth != null && metrics.queue_depth >= 0 ? fmt(metrics.queue_depth) : '—'} accent="violet" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Processing latency */}
          <div id="metric-processing-latency" className="cyber-card rounded-2xl border border-slate-800/60 p-5">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">Processing Latency</h3>
            <div className="grid grid-cols-3 gap-3">
              {[
                { l: 'p50', v: fmtMs(metrics?.processing_latency.p50_ms ?? 0) },
                { l: 'p95', v: fmtMs(metrics?.processing_latency.p95_ms ?? 0) },
                { l: 'mean', v: fmtMs(metrics?.processing_latency.mean_ms ?? 0) },
              ].map(({ l, v }) => (
                <div key={l} className="rounded-lg bg-slate-800/60 px-3 py-2 text-center">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{l}</div>
                  <div className="text-base font-bold font-mono text-cyan-400 mt-0.5">{v}</div>
                </div>
              ))}
            </div>
            <p className="text-xs font-mono text-slate-600 mt-3">{fmt(metrics?.processing_latency.count)} total observations</p>
          </div>

          {/* Search latency */}
          <div id="metric-search-latency" className="cyber-card rounded-2xl border border-slate-800/60 p-5">
            <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-4">Search Latency</h3>
            <div className="grid grid-cols-3 gap-3">
              {[
                { l: 'p50', v: fmtMs(metrics?.search_latency.p50_ms ?? 0) },
                { l: 'p95', v: fmtMs(metrics?.search_latency.p95_ms ?? 0) },
                { l: 'mean', v: fmtMs(metrics?.search_latency.mean_ms ?? 0) },
              ].map(({ l, v }) => (
                <div key={l} className="rounded-lg bg-slate-800/60 px-3 py-2 text-center">
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{l}</div>
                  <div className="text-base font-bold font-mono text-violet-400 mt-0.5">{v}</div>
                </div>
              ))}
            </div>
            <p className="text-xs font-mono text-slate-600 mt-3">{fmt(metrics?.search_latency.count)} search observations</p>
          </div>
        </div>

        {/* Per-connector */}
        {connNames.length > 0 && (
          <div className="cyber-card rounded-2xl border border-slate-800/60 overflow-hidden mt-4">
            <table className="w-full text-sm" id="table-metrics-connectors">
              <thead>
                <tr className="border-b border-slate-800/60">
                  {['Connector', 'Successes', 'Failures', 'Rate'].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-[10px] font-semibold uppercase tracking-wider text-slate-500">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40">
                {connNames.map(n => {
                  const s = metrics?.connector_success_by_name?.[n] ?? 0;
                  const f = metrics?.connector_failure_by_name?.[n] ?? 0;
                  const t = s + f;
                  return (
                    <tr key={n} className="hover:bg-slate-800/20">
                      <td className="px-4 py-3 text-xs font-mono text-slate-300">{n}</td>
                      <td className="px-4 py-3 text-xs font-mono text-emerald-400">{fmt(s)}</td>
                      <td className="px-4 py-3 text-xs font-mono text-rose-400">{fmt(f)}</td>
                      <td className="px-4 py-3 text-xs font-mono text-cyan-400">{t > 0 ? `${((s / t) * 100).toFixed(1)}%` : '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        <div className="flex flex-wrap gap-3 mt-4">
          {[
            { id: 'link-full-metrics', href: `${API}/admin/metrics`, label: 'Full JSON' },
            { id: 'link-prometheus', href: `${API}/admin/metrics/prometheus`, label: 'Prometheus' },
            { id: 'link-monitoring', href: '/admin/monitoring', label: 'Monitoring Dashboard' },
          ].map(({ id, href, label }) => (
            <a key={id} id={id} href={href} target="_blank" rel="noreferrer"
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-slate-700 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/30 transition-colors">
              ↗ {label}
            </a>
          ))}
        </div>
      </Section>
    );
  }

  // ── Health Tab ────────────────────────────────────────────────────────────
  function HealthTab() {
    const dbOk = health?.database_connected;
    return (
      <Section title="System Health">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {[
            { id: 'health-api', label: 'API Service', value: health?.status ?? 'unknown', ok: health?.status === 'ok', detail: `v${health?.version ?? '—'} · ${health?.environment ?? '—'}` },
            { id: 'health-db', label: 'Database', value: dbOk ? 'Connected' : 'Disconnected', ok: !!dbOk, detail: dbOk ? 'PostgreSQL / SQLite' : 'Check DATABASE_URL' },
            { id: 'health-env', label: 'Environment', value: health?.environment ?? '—', ok: true, detail: `Version ${health?.version ?? '—'}` },
          ].map(({ id, label, value, ok, detail }) => (
            <div key={id} id={id} className={`cyber-card rounded-2xl border p-5 ${ok ? 'border-emerald-500/20' : 'border-rose-500/30'}`}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold uppercase tracking-widest text-slate-500">{label}</span>
                <span className={`w-3 h-3 rounded-full ${ok ? 'bg-emerald-400 status-pulse' : 'bg-rose-400'}`} />
              </div>
              <p className={`text-2xl font-extrabold font-mono ${ok ? 'text-emerald-400' : 'text-rose-400'}`}>{value}</p>
              <p className="text-xs text-slate-600 mt-1">{detail}</p>
            </div>
          ))}
        </div>

        <div className="cyber-card rounded-2xl border border-slate-800/60 p-5 mt-4">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-slate-500 mb-3">Health Endpoints</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              { id: 'link-health-basic', href: `${API}/health`, label: 'Basic Health Check' },
              { id: 'link-health-detail', href: `${API}/health/detail`, label: 'Detailed Health' },
              { id: 'link-docs', href: 'http://localhost:8000/docs', label: 'Swagger API Docs' },
              { id: 'link-security-posture', href: `${API}/security/posture`, label: 'Security Posture' },
            ].map(({ id, href, label }) => (
              <a key={id} id={id} href={href} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-800 hover:border-cyan-500/30 hover:text-cyan-400 text-slate-400 text-xs font-mono transition-colors">
                <span>↗</span>{label}
              </a>
            ))}
          </div>
        </div>

        {health?.timestamp && (
          <p className="text-xs font-mono text-slate-700 text-right mt-3">
            Last checked: {formatDateTime(health.timestamp)}
          </p>
        )}
      </Section>
    );
  }

  // ── Render ────────────────────────────────────────────────────────────────
  const TAB_CONTENT: Record<TabId, React.ReactNode> = {
    overview:   <OverviewTab />,
    sources:    <SourcesTab />,
    connectors: <ConnectorsTab />,
    queue:      <QueueTab />,
    jobs:       <JobsTab />,
    metrics:    <MetricsTab />,
    health:     <HealthTab />,
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-200 font-sans">
      {/* Header */}
      <header className="cyber-glass sticky top-0 z-30 px-6 py-4">
        <div className="max-w-screen-2xl mx-auto flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-violet-500/15 flex items-center justify-center">
              <span className="text-violet-400 text-sm font-bold">⚙</span>
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-tight text-white">OSINT Admin Panel</h1>
              <p className="text-[10px] text-slate-500 font-mono uppercase tracking-wider">
                Section 42 · Step 41 · /admin
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs font-mono">
            <span className={`flex items-center gap-1.5 ${health?.status === 'ok' ? 'text-emerald-400' : 'text-rose-400'}`}>
              <span className={`w-2 h-2 rounded-full ${health?.status === 'ok' ? 'bg-emerald-400 status-pulse' : 'bg-rose-400'}`} />
              {health?.status === 'ok' ? 'Healthy' : 'Degraded'}
            </span>
            <button
              id="btn-admin-refresh"
              onClick={() => { setLoading(true); fetchAll(); }}
              className="px-3 py-1.5 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20 hover:bg-violet-500/20 transition-colors"
            >
              ↺ Refresh
            </button>
            <a href="/admin/monitoring" id="link-monitoring-dashboard"
              className="px-3 py-1.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors">
              Metrics
            </a>
          </div>
        </div>
      </header>

      {/* Tab Nav */}
      <nav className="border-b border-slate-800/60 px-6 sticky top-[61px] z-20 bg-[#080c14]/95 backdrop-blur-lg">
        <div className="max-w-screen-2xl mx-auto flex items-center gap-1 overflow-x-auto">
          {TABS.map(t => (
            <button
              key={t.id}
              id={`tab-${t.id}`}
              onClick={() => setTab(t.id)}
              className={`flex items-center gap-1.5 px-4 py-3.5 text-xs font-semibold whitespace-nowrap border-b-2 transition-colors ${
                tab === t.id
                  ? 'border-violet-500 text-violet-400'
                  : 'border-transparent text-slate-500 hover:text-slate-300 hover:border-slate-700'
              }`}
            >
              <span>{t.icon}</span>
              {t.label}
            </button>
          ))}
        </div>
      </nav>

      {/* Content */}
      <main className="max-w-screen-2xl mx-auto px-6 py-8">
        {loading ? (
          <div className="flex items-center justify-center py-24">
            <div className="text-center space-y-4">
              <div className="w-10 h-10 rounded-full border-2 border-violet-500/40 border-t-violet-400 animate-spin mx-auto" />
              <p className="text-slate-500 text-xs font-mono">Loading admin data…</p>
            </div>
          </div>
        ) : (
          TAB_CONTENT[tab]
        )}
      </main>

      {/* Toast */}
      {toast && <Toast msg={toast.msg} ok={toast.ok} onDone={() => setToast(null)} />}
    </div>
  );
}
