"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  NotificationChannel,
  NotificationChannelConfig,
  NotificationImportanceLevel,
  NotificationItem,
  NotificationPipelineRunResult,
  NotificationSummary,
} from "../../lib/types";
import {
  deleteNotification,
  fetchNotificationChannels,
  fetchNotifications,
  fetchNotificationSummary,
  markAllNotificationsRead,
  markNotificationRead,
  runNotificationPipelineTest,
  saveNotificationChannelConfig,
  testChannelDispatch,
} from "../../lib/api";
import { SeverityBadge } from "../../components/SeverityBadge";
import { formatDateTime, safeUpper } from "../../lib/formatters";

export default function NotificationsPage() {
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [summary, setSummary] = useState<NotificationSummary | null>(null);
  const [channels, setChannels] = useState<NotificationChannelConfig[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // Filters
  const [selectedChannel, setSelectedChannel] = useState<string>("all");
  const [selectedImportance, setSelectedImportance] = useState<string>("all");
  const [readFilter, setReadFilter] = useState<string>("all"); // "all", "unread", "read"

  // Pipeline Simulator Modal
  const [showSimulator, setShowSimulator] = useState<boolean>(false);
  const [simTitle, setSimTitle] = useState<string>(
    "Critical Zero-Day in Edge Gateway VPN Appliances (CVE-2024-3400)"
  );
  const [simSeverity, setSimSeverity] = useState<string>("CRITICAL");
  const [simCvss, setSimCvss] = useState<number>(9.8);
  const [simCve, setSimCve] = useState<string>("CVE-2024-3400");
  const [simVendor, setSimVendor] = useState<string>("Palo Alto Networks");
  const [simSummary, setSimSummary] = useState<string>(
    "Unauthenticated command injection vulnerability in PAN-OS GlobalProtect feature allows remote attackers to execute arbitrary code with root privileges. Actively weaponized in the wild."
  );
  const [simThreshold, setSimThreshold] = useState<number>(0.45);
  const [simRunning, setSimRunning] = useState<boolean>(false);
  const [simResult, setSimResult] = useState<NotificationPipelineRunResult | null>(null);

  // Channel Config Modal
  const [showChannelModal, setShowChannelModal] = useState<boolean>(false);
  const [editingChannel, setEditingChannel] = useState<NotificationChannel>("webhook");
  const [channelDest, setChannelDest] = useState<string>("https://siem.corp.internal/api/v1/alerts");
  const [channelThreshold, setChannelThreshold] = useState<number>(0.50);
  const [channelSecret, setChannelSecret] = useState<string>("whsec_sample_key_99");
  const [testResult, setTestResult] = useState<any | null>(null);
  const [testingDispatch, setTestingDispatch] = useState<boolean>(false);

  useEffect(() => {
    loadData();
  }, [selectedChannel, selectedImportance, readFilter]);

  async function loadData() {
    setLoading(true);
    try {
      const isReadParam =
        readFilter === "unread" ? false : readFilter === "read" ? true : undefined;
      const channelParam = selectedChannel !== "all" ? selectedChannel : undefined;
      const importanceParam = selectedImportance !== "all" ? selectedImportance : undefined;

      const [notifs, sum, chs] = await Promise.all([
        fetchNotifications({
          channel: channelParam,
          importance: importanceParam,
          is_read: isReadParam,
        }),
        fetchNotificationSummary(),
        fetchNotificationChannels(),
      ]);
      setNotifications(notifs);
      setSummary(sum);
      setChannels(chs);
    } catch (err) {
      console.error("Failed to load notifications:", err);
    } finally {
      setLoading(false);
    }
  }

  async function handleToggleRead(notif: NotificationItem) {
    try {
      const updated = await markNotificationRead(notif.id, !notif.is_read);
      setNotifications((prev) =>
        prev.map((item) => (item.id === notif.id ? { ...item, is_read: updated.is_read } : item))
      );
      if (summary) {
        setSummary({
          ...summary,
          unread_count: updated.is_read ? Math.max(0, summary.unread_count - 1) : summary.unread_count + 1,
        });
      }
    } catch (err) {
      console.error("Toggle read error:", err);
    }
  }

  async function handleMarkAllRead() {
    try {
      await markAllNotificationsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
      if (summary) setSummary({ ...summary, unread_count: 0 });
    } catch (err) {
      console.error("Mark all read error:", err);
    }
  }

  async function handleDelete(id: number) {
    try {
      await deleteNotification(id);
      setNotifications((prev) => prev.filter((n) => n.id !== id));
      if (summary) setSummary({ ...summary, total_count: Math.max(0, summary.total_count - 1) });
    } catch (err) {
      console.error("Delete error:", err);
    }
  }

  async function handleRunPipelineSimulator() {
    setSimRunning(true);
    setSimResult(null);
    try {
      const payload = {
        title: simTitle,
        description: simSummary,
        summary: simSummary,
        severity: simSeverity,
        cvss_score: simCvss,
        source: "CISA Cybersecurity Advisories",
        canonical_url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
        category: "Vulnerabilities",
        tags: ["zero-day", "kev", "rce", "cisa", "actively exploited"],
        entities: [
          { entity_type: "cve", name: simCve },
          { entity_type: "vendor", name: simVendor },
        ],
      };

      const res = await runNotificationPipelineTest({
        content_payload: payload,
        force_dispatch: true,
        threshold_override: simThreshold,
      });
      setSimResult(res);
      await loadData();
    } catch (err) {
      console.error("Pipeline simulator error:", err);
    } finally {
      setSimRunning(false);
    }
  }

  async function handleSaveChannel() {
    try {
      await saveNotificationChannelConfig({
        channel_type: editingChannel,
        destination: channelDest,
        min_importance_threshold: channelThreshold,
        secret_token: channelSecret,
        is_enabled: true,
      });
      const updatedChannels = await fetchNotificationChannels();
      setChannels(updatedChannels);
      setShowChannelModal(false);
    } catch (err) {
      console.error("Save channel error:", err);
    }
  }

  async function handleTestChannelProbe(channelKey: string, dest?: string) {
    setTestingDispatch(true);
    setTestResult(null);
    try {
      const res = await testChannelDispatch(channelKey, dest);
      setTestResult(res);
    } catch (err) {
      console.error("Channel test error:", err);
    } finally {
      setTestingDispatch(false);
    }
  }

  const getChannelBadge = (ch: string) => {
    switch (ch.toLowerCase()) {
      case "webhook":
        return { label: "WEBHOOK", icon: "⚡", color: "text-amber-400 bg-amber-500/10 border-amber-500/30" };
      case "email":
        return { label: "EMAIL", icon: "✉", color: "text-blue-400 bg-blue-500/10 border-blue-500/30" };
      case "push":
        return { label: "PUSH", icon: "📱", color: "text-purple-400 bg-purple-500/10 border-purple-500/30" };
      default:
        return { label: "IN-APP", icon: "🌐", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" };
    }
  };

  const getImportanceBadge = (level: string) => {
    switch (safeUpper(level, "INFO")) {
      case "CRITICAL":
        return "text-red-400 bg-red-500/10 border-red-500/30";
      case "HIGH":
        return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "MEDIUM":
        return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      default:
        return "text-slate-400 bg-slate-800 border-slate-700";
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-xl bg-gradient-to-r from-red-950/40 via-slate-900 to-slate-950 p-6 border border-red-900/40 shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-red-500/20 text-red-300 border border-red-500/30">
                SECTION 33 • STEP 32
              </span>
              <span className="text-xs font-mono text-slate-400">SURVEILLANCE & DISPATCH</span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-black tracking-tight text-white flex items-center gap-3">
              <span>🔔</span>
              <span>Security Notifications & Alerts</span>
            </h1>
            <p className="mt-1 text-sm text-slate-400 max-w-2xl">
              Automated 5-stage alerting pipeline: evaluates new intelligence against surveillance watchlists,
              computes composite importance scores, and enforces thresholds across Web, Webhooks, Email, and Push.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => setShowSimulator(true)}
              className="px-3.5 py-2 rounded-lg bg-red-500/20 hover:bg-red-500/30 border border-red-500/40 text-red-300 font-mono text-xs font-semibold flex items-center gap-1.5 transition-all shadow-sm"
            >
              <span>⚙</span> Run Pipeline Simulator
            </button>
            <button
              onClick={() => setShowChannelModal(true)}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 font-mono text-xs flex items-center gap-1.5 transition-all"
            >
              <span>🖧</span> Delivery Channels
            </button>
            <button
              onClick={handleMarkAllRead}
              className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-300 font-mono text-xs transition-all"
            >
              ✓ Mark All Read
            </button>
          </div>
        </div>
      </div>

      {/* Telemetry Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">TOTAL ALERTS</div>
            <div className="text-2xl font-black text-white mt-1">{summary?.total_count ?? 0}</div>
            <div className="text-[11px] font-mono text-slate-500 mt-0.5">Across all surveillance watchlists</div>
          </div>
          <span className="text-2xl text-slate-600">📊</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-red-900/30 flex items-center justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-xl pointer-events-none" />
          <div>
            <div className="text-xs font-mono text-red-400">UNREAD ALERTS</div>
            <div className="text-2xl font-black text-red-300 mt-1">{summary?.unread_count ?? 0}</div>
            <div className="text-[11px] font-mono text-red-400/70 mt-0.5">Requiring analyst triage</div>
          </div>
          <span className="text-2xl text-red-400 animate-pulse">⚡</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-orange-900/30 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-orange-400">CRITICAL & HIGH</div>
            <div className="text-2xl font-black text-orange-300 mt-1">
              {(summary?.critical_count ?? 0) + (summary?.high_count ?? 0)}
            </div>
            <div className="text-[11px] font-mono text-orange-400/70 mt-0.5">
              Score ≥ 0.70 threshold
            </div>
          </div>
          <span className="text-2xl text-orange-400">🔥</span>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-cyan-400">DISPATCH CHANNELS</div>
            <div className="text-2xl font-black text-cyan-300 mt-1">{channels.length || 4}</div>
            <div className="text-[11px] font-mono text-slate-400 mt-0.5">Web • Webhook • Email • Push</div>
          </div>
          <span className="text-2xl text-cyan-400">📡</span>
        </div>
      </div>

      {/* Filter and Control Bar */}
      <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800/80 flex flex-wrap items-center justify-between gap-3">
        {/* Channel Filters */}
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs font-mono text-slate-400 mr-1">Channel:</span>
          {["all", "web", "webhook", "email", "push"].map((ch) => (
            <button
              key={ch}
              onClick={() => setSelectedChannel(ch)}
              className={`px-3 py-1 rounded-md text-xs font-mono uppercase tracking-wider transition-all ${
                selectedChannel === ch
                  ? "bg-red-500/20 text-red-300 border border-red-500/40 font-bold"
                  : "bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-slate-700/50"
              }`}
            >
              {ch}
            </button>
          ))}
        </div>

        {/* Importance & Read Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs font-mono text-slate-400">Importance:</span>
          {["all", "CRITICAL", "HIGH", "MEDIUM"].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setSelectedImportance(lvl)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono transition-all ${
                selectedImportance === lvl
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold"
                  : "bg-slate-800/60 text-slate-400 hover:text-slate-200 border border-slate-700/50"
              }`}
            >
              {lvl}
            </button>
          ))}

          <span className="text-slate-600 ml-1">|</span>

          <select
            value={readFilter}
            onChange={(e) => setReadFilter(e.target.value)}
            className="px-2.5 py-1 rounded-md bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 focus:outline-none focus:border-red-500"
          >
            <option value="all">All Status</option>
            <option value="unread">Unread Only</option>
            <option value="read">Read Only</option>
          </select>
        </div>
      </div>

      {/* Notifications Feed List */}
      <div className="space-y-3">
        {loading ? (
          <div className="p-12 text-center rounded-xl bg-slate-900/30 border border-slate-800 text-slate-500 font-mono text-sm">
            <span className="animate-spin inline-block mr-2">⚙</span> Loading intelligence alert notifications...
          </div>
        ) : notifications.length === 0 ? (
          <div className="p-12 text-center rounded-xl bg-slate-900/30 border border-dashed border-slate-800 text-slate-400 font-mono">
            <div className="text-3xl mb-2">🔕</div>
            <div className="font-semibold text-slate-300">No alert notifications matching criteria</div>
            <div className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
              All intelligence items have either been resolved, suppressed below importance thresholds, or filtered.
            </div>
            <button
              onClick={() => setShowSimulator(true)}
              className="mt-4 px-4 py-2 rounded-lg bg-red-500/20 text-red-300 border border-red-500/30 text-xs font-mono hover:bg-red-500/30"
            >
              Trigger Pipeline Test
            </button>
          </div>
        ) : (
          notifications.map((notif) => {
            const chBadge = getChannelBadge(notif.channel);
            const impColor = getImportanceBadge(notif.importance_level);

            return (
              <div
                key={notif.id}
                className={`p-5 rounded-xl border transition-all ${
                  notif.is_read
                    ? "bg-slate-900/40 border-slate-800/80 opacity-80"
                    : "bg-slate-900/80 border-slate-700/80 shadow-lg shadow-black/20"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      {/* Importance Level */}
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider border ${impColor}`}
                      >
                        {notif.importance_level} ({notif.importance_score.toFixed(2)})
                      </span>

                      {/* Channel Badge */}
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono border flex items-center gap-1 ${chBadge.color}`}
                      >
                        <span>{chBadge.icon}</span>
                        <span>{chBadge.label}</span>
                      </span>

                      {/* Watchlist Reference */}
                      {notif.watchlist_name && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/10 text-cyan-300 border border-cyan-500/30">
                          🎯 {notif.watchlist_name}
                        </span>
                      )}

                      {/* Unread Indicator */}
                      {!notif.is_read && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-red-500 text-white font-bold animate-pulse">
                          NEW
                        </span>
                      )}

                      <span className="text-[11px] font-mono text-slate-500 ml-auto">
                        {formatDateTime(notif.created_at, "Just now")}
                      </span>
                    </div>

                    {/* Title */}
                    <h3 className="text-base font-bold text-white tracking-tight">
                      {notif.title}
                    </h3>

                    {/* Description / Summary */}
                    <p className="text-xs text-slate-300 leading-relaxed max-w-4xl">
                      {notif.summary || notif.body}
                    </p>

                    {/* Matched target items snippet */}
                    {notif.metadata?.matched_items && notif.metadata.matched_items.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-1">
                        <span className="text-[10px] font-mono text-slate-500">MATCHED TARGETS:</span>
                        {notif.metadata.matched_items.map((item: any, idx: number) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
                          >
                            {safeUpper(item.item_type, "ITEM")}: <strong className="text-cyan-300">{item.item_value}</strong>
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Importance Score Factor Breakdown */}
                    {notif.metadata?.importance_factors && (
                      <div className="pt-2 border-t border-slate-800/60 mt-2 flex flex-wrap items-center gap-4 text-[11px] font-mono text-slate-400">
                        <span>
                          Severity: <strong className="text-slate-200">{notif.metadata.importance_factors.severity_factor}</strong>
                        </span>
                        <span>
                          Exploit Signals: <strong className="text-slate-200">{notif.metadata.importance_factors.exploit_factor}</strong>
                        </span>
                        <span>
                          Source Quality: <strong className="text-slate-200">{notif.metadata.importance_factors.source_factor}</strong>
                        </span>
                        <span>
                          Watchlist Depth: <strong className="text-slate-200">{notif.metadata.importance_factors.watchlist_factor}</strong>
                        </span>
                      </div>
                    )}
                  </div>

                  {/* Actions Column */}
                  <div className="flex sm:flex-col items-center gap-2 shrink-0 sm:self-start">
                    {notif.content_url && (
                      <a
                        href={notif.content_url}
                        target="_blank"
                        rel="noreferrer"
                        className="px-3 py-1.5 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center gap-1"
                      >
                        <span>Inspect</span> ↗
                      </a>
                    )}
                    <button
                      onClick={() => handleToggleRead(notif)}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-300 text-xs font-mono"
                    >
                      {notif.is_read ? "Mark Unread" : "Mark Read"}
                    </button>
                    <button
                      onClick={() => handleDelete(notif.id)}
                      className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-red-500/10 transition-colors"
                      title="Dismiss alert"
                    >
                      ✕
                    </button>
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>

      {/* 5-STAGE PIPELINE SIMULATOR MODAL */}
      {showSimulator && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#0c121e] border border-red-500/30 rounded-2xl max-w-3xl w-full p-6 space-y-6 shadow-2xl my-8">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>⚙</span>
                  <span>5-Stage Notification Pipeline Simulator</span>
                </h2>
                <p className="text-xs font-mono text-slate-400">
                  IMPLEMENT.md Section 33: New Content → Match Watchlists → Calculate Importance → Create Notification → Send
                </p>
              </div>
              <button
                onClick={() => setShowSimulator(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Test Content Inputs */}
            <div className="space-y-4 text-xs font-mono">
              <div>
                <label className="block text-slate-300 mb-1">Intelligence Article Title</label>
                <input
                  type="text"
                  value={simTitle}
                  onChange={(e) => setSimTitle(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white focus:outline-none focus:border-red-500"
                />
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1">Severity Level</label>
                  <select
                    value={simSeverity}
                    onChange={(e) => setSimSeverity(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  >
                    <option value="CRITICAL">CRITICAL (1.0)</option>
                    <option value="HIGH">HIGH (0.8)</option>
                    <option value="MEDIUM">MEDIUM (0.5)</option>
                    <option value="LOW">LOW (0.2)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">CVSS Base Score</label>
                  <input
                    type="number"
                    step="0.1"
                    min="0"
                    max="10"
                    value={simCvss}
                    onChange={(e) => setSimCvss(parseFloat(e.target.value) || 0)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1">Target CVE</label>
                  <input
                    type="text"
                    value={simCve}
                    onChange={(e) => setSimCve(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1">Summary / Exploitation Context</label>
                <textarea
                  rows={3}
                  value={simSummary}
                  onChange={(e) => setSimSummary(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                />
              </div>

              <div>
                <div className="flex justify-between text-slate-300 mb-1">
                  <span>Minimum Importance Threshold Gate:</span>
                  <span className="text-cyan-300 font-bold">{simThreshold.toFixed(2)}</span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="0.9"
                  step="0.05"
                  value={simThreshold}
                  onChange={(e) => setSimThreshold(parseFloat(e.target.value))}
                  className="w-full"
                />
                <span className="text-[10px] text-slate-500">
                  Articles scoring below this gate are suppressed to prevent alert fatigue.
                </span>
              </div>
            </div>

            {/* Run Button */}
            <button
              onClick={handleRunPipelineSimulator}
              disabled={simRunning}
              className="w-full py-2.5 rounded-lg bg-red-600 hover:bg-red-500 font-mono text-xs font-bold text-white uppercase tracking-wider transition-all disabled:opacity-50"
            >
              {simRunning ? "Executing 5-Stage Alert Pipeline..." : "Execute Pipeline Assessment"}
            </button>

            {/* Execution Result Flowchart */}
            {simResult && (
              <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-4 font-mono text-xs">
                <div className="text-slate-400 font-bold border-b border-slate-800 pb-2">
                  PIPELINE EXECUTION TELEMETRY:
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-5 gap-2 text-center">
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500">STAGE 1</div>
                    <div className="font-bold text-white">Content</div>
                    <div className="text-[10px] text-emerald-400 mt-1">Normalized</div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500">STAGE 2</div>
                    <div className="font-bold text-white">Watchlists</div>
                    <div className="text-[10px] text-cyan-400 mt-1">
                      {simResult.matched_items_count} Hits
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500">STAGE 3</div>
                    <div className="font-bold text-white">Importance</div>
                    <div className="text-[10px] text-yellow-400 mt-1">
                      Score {simResult.importance.score.toFixed(2)}
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500">STAGE 4</div>
                    <div className="font-bold text-white">Create Alert</div>
                    <div className="text-[10px] text-purple-400 mt-1">
                      {simResult.notifications_created.length} Records
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800">
                    <div className="text-[10px] text-slate-500">STAGE 5</div>
                    <div className="font-bold text-white">Dispatch</div>
                    <div className="text-[10px] text-emerald-400 mt-1">
                      {simResult.dispatch_results.length} Dispatched
                    </div>
                  </div>
                </div>

                {/* Factors Card */}
                <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800">
                  <div className="text-slate-300 font-bold mb-1">Reason:</div>
                  <div className="text-slate-400">{simResult.importance.reason}</div>
                  <div className="mt-2 text-[10px] text-slate-500">
                    Gate Result:{" "}
                    <span
                      className={
                        simResult.importance.exceeds_threshold
                          ? "text-emerald-400 font-bold"
                          : "text-red-400 font-bold"
                      }
                    >
                      {simResult.importance.exceeds_threshold
                        ? "EXCEEDS THRESHOLD (DISPATCHED)"
                        : "SUPPRESSED (BELOW THRESHOLD)"}
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* DELIVERY CHANNELS & THRESHOLDS MODAL */}
      {showChannelModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-[#0c121e] border border-cyan-500/30 rounded-2xl max-w-2xl w-full p-6 space-y-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <span>📡</span>
                  <span>Notification Channels & Thresholds</span>
                </h2>
                <p className="text-xs font-mono text-slate-400">
                  Configure destinations and minimum importance thresholds per channel to eliminate alert fatigue.
                </p>
              </div>
              <button
                onClick={() => setShowChannelModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg bg-slate-800"
              >
                ✕
              </button>
            </div>

            {/* Active Channels Overview */}
            <div className="space-y-3 font-mono text-xs">
              <div className="text-slate-300 font-bold">Configured Channel Destinations:</div>
              {channels.map((ch, idx) => (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-between"
                >
                  <div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-cyan-300 border border-slate-700 mr-2">
                      {ch.channel_type}
                    </span>
                    <span className="text-slate-300">{ch.destination || "In-app local sink"}</span>
                    <div className="text-[11px] text-slate-500 mt-1">
                      Minimum Threshold: <strong className="text-white">{ch.min_importance_threshold.toFixed(2)}</strong>
                    </div>
                  </div>
                  <button
                    onClick={() => handleTestChannelProbe(ch.channel_type, ch.destination)}
                    disabled={testingDispatch}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] border border-slate-700"
                  >
                    Test Probe
                  </button>
                </div>
              ))}
            </div>

            {/* Edit / Add Channel */}
            <div className="space-y-3 font-mono text-xs border-t border-slate-800 pt-4">
              <div className="text-slate-300 font-bold">Update Channel Settings:</div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Channel Type</label>
                  <select
                    value={editingChannel}
                    onChange={(e) => setEditingChannel(e.target.value as NotificationChannel)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  >
                    <option value="webhook">Webhook (SIEM/SOAR/ChatOps)</option>
                    <option value="email">Email (Advisory Digest)</option>
                    <option value="push">Push (Mobile/Browser)</option>
                    <option value="web">Web (In-App Center)</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Min Importance Threshold</label>
                  <input
                    type="number"
                    step="0.05"
                    min="0.1"
                    max="1.0"
                    value={channelThreshold}
                    onChange={(e) => setChannelThreshold(parseFloat(e.target.value) || 0.5)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">
                  Destination ({editingChannel === "email" ? "Email Address" : "Endpoint URL"})
                </label>
                <input
                  type="text"
                  value={channelDest}
                  onChange={(e) => setChannelDest(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                />
              </div>

              {editingChannel === "webhook" && (
                <div>
                  <label className="block text-slate-400 mb-1">HMAC Secret Key (X-CyberOsint-Signature)</label>
                  <input
                    type="text"
                    value={channelSecret}
                    onChange={(e) => setChannelSecret(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-white"
                  />
                </div>
              )}

              <button
                onClick={handleSaveChannel}
                className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 font-bold text-slate-950 uppercase tracking-wider transition-all"
              >
                Save Channel Configuration
              </button>
            </div>

            {/* Probe Output */}
            {testResult && (
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px]">
                <div className="text-emerald-400 font-bold mb-1">PROBE DISPATCH RESULT:</div>
                <pre className="text-slate-400 overflow-x-auto">{JSON.stringify(testResult, null, 2)}</pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
