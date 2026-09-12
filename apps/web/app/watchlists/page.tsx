"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  Watchlist,
  WatchlistItem,
  WatchlistItemType,
  WatchlistFeedResponse,
  MatchedContentItem,
} from "../../lib/types";
import {
  fetchWatchlists,
  createWatchlist,
  deleteWatchlist,
  updateWatchlist,
  addWatchlistItem,
  removeWatchlistItem,
  fetchWatchlistFeed,
} from "../../lib/api";
import { SeverityBadge } from "../../components/SeverityBadge";

const WATCHLIST_TYPES: { type: WatchlistItemType; label: string; placeholder: string; color: string }[] = [
  { type: "cve", label: "CVE", placeholder: "e.g. CVE-2024-3400", color: "text-red-400 bg-red-500/10 border-red-500/30" },
  { type: "product", label: "Product", placeholder: "e.g. PAN-OS, GlobalProtect", color: "text-blue-400 bg-blue-500/10 border-blue-500/30" },
  { type: "vendor", label: "Vendor", placeholder: "e.g. Palo Alto Networks, Cisco", color: "text-purple-400 bg-purple-500/10 border-purple-500/30" },
  { type: "threat_actor", label: "Threat Actor", placeholder: "e.g. LockBit, APT29", color: "text-amber-400 bg-amber-500/10 border-amber-500/30" },
  { type: "malware", label: "Malware", placeholder: "e.g. LockBit 3.0, Cobalt Strike", color: "text-rose-400 bg-rose-500/10 border-rose-500/30" },
  { type: "technology", label: "Technology", placeholder: "e.g. Kubernetes, eBPF", color: "text-cyan-400 bg-cyan-500/10 border-cyan-500/30" },
  { type: "topic", label: "Topic", placeholder: "e.g. Zero-Day Vulnerabilities, Ransomware", color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30" },
  { type: "researcher", label: "Researcher", placeholder: "e.g. Jann Horn, Tavis Ormandy", color: "text-teal-400 bg-teal-500/10 border-teal-500/30" },
  { type: "tool", label: "Tool", placeholder: "e.g. Falco, KubeArmor, Nuclei", color: "text-indigo-400 bg-indigo-500/10 border-indigo-500/30" },
  { type: "keyword", label: "Keyword", placeholder: "e.g. unauthenticated rce, privilege escalation", color: "text-slate-300 bg-slate-800 border-slate-700" },
];

export default function WatchlistsPage() {
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [selectedWlId, setSelectedWlId] = useState<number | null>(null);
  const [feed, setFeed] = useState<WatchlistFeedResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [feedLoading, setFeedLoading] = useState<boolean>(false);

  // New Watchlist Form Modal
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [newWlName, setNewWlName] = useState<string>("");
  const [newWlDesc, setNewWlDesc] = useState<string>("");
  const [newWlChannel, setNewWlChannel] = useState<string>("in_app");

  // Add Item to active watchlist Form
  const [activeType, setActiveType] = useState<WatchlistItemType>("cve");
  const [itemValue, setItemValue] = useState<string>("");
  const [itemSeverity, setItemSeverity] = useState<string>("");

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const wls = await fetchWatchlists();
        setWatchlists(wls);
        if (wls.length > 0) {
          setSelectedWlId(wls[0].id);
        }
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  useEffect(() => {
    if (!selectedWlId) return;
    async function loadFeed() {
      setFeedLoading(true);
      try {
        const f = await fetchWatchlistFeed(selectedWlId!);
        setFeed(f);
      } finally {
        setFeedLoading(false);
      }
    }
    loadFeed();
  }, [selectedWlId]);

  const activeWatchlist = watchlists.find((w) => w.id === selectedWlId) || watchlists[0];

  const handleCreateWatchlist = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newWlName.trim()) return;
    const created = await createWatchlist({
      name: newWlName.trim(),
      description: newWlDesc.trim(),
      notification_channel: newWlChannel,
    });
    setWatchlists([created, ...watchlists]);
    setSelectedWlId(created.id);
    setNewWlName("");
    setNewWlDesc("");
    setShowCreateModal(false);
  };

  const handleDeleteWatchlist = async (id: number, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!confirm("Are you sure you want to delete this watchlist?")) return;
    await deleteWatchlist(id);
    const remaining = watchlists.filter((w) => w.id !== id);
    setWatchlists(remaining);
    if (selectedWlId === id && remaining.length > 0) {
      setSelectedWlId(remaining[0].id);
    }
  };

  const handleToggleActive = async (wl: Watchlist, e: React.MouseEvent) => {
    e.stopPropagation();
    const updated = await updateWatchlist(wl.id, { is_active: !wl.is_active });
    setWatchlists(watchlists.map((w) => (w.id === wl.id ? updated : w)));
  };

  const handleAddItem = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!itemValue.trim() || !selectedWlId) return;
    const added = await addWatchlistItem(selectedWlId, {
      item_type: activeType,
      item_value: itemValue.trim(),
      severity_threshold: itemSeverity || undefined,
    });
    // Update local state
    const updatedWatchlists = watchlists.map((w) => {
      if (w.id === selectedWlId) {
        return {
          ...w,
          item_count: w.item_count + 1,
          items: [added, ...(w.items || [])],
        };
      }
      return w;
    });
    setWatchlists(updatedWatchlists);
    setItemValue("");
    // Reload feed
    const updatedFeed = await fetchWatchlistFeed(selectedWlId);
    setFeed(updatedFeed);
  };

  const handleRemoveItem = async (itemId: number) => {
    if (!selectedWlId) return;
    await removeWatchlistItem(selectedWlId, itemId);
    const updatedWatchlists = watchlists.map((w) => {
      if (w.id === selectedWlId) {
        return {
          ...w,
          item_count: Math.max(w.item_count - 1, 0),
          items: (w.items || []).filter((it) => it.id !== itemId),
        };
      }
      return w;
    });
    setWatchlists(updatedWatchlists);
    // Reload feed
    const updatedFeed = await fetchWatchlistFeed(selectedWlId);
    setFeed(updatedFeed);
  };

  const totalTargetsCount = watchlists.reduce((acc, w) => acc + (w.item_count || 0), 0);
  const activeTypeConfig = WATCHLIST_TYPES.find((t) => t.type === activeType) || WATCHLIST_TYPES[0];

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              SECTION 32 &bull; SURVEILLANCE RADAR
            </span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-xs font-mono text-emerald-400">10 MONITORED CATEGORIES</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Targeted Threat Intelligence Watchlists
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Surveillance radar continuously tracking CVEs, products, vendors, threat actors, malware, technologies, topics, researchers, tools, and keywords.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowCreateModal(true)}
            className="px-4 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shadow-lg shadow-cyan-500/10 flex items-center gap-1.5"
          >
            <span>+ Create Watchlist</span>
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <span className="text-xs font-mono text-slate-500 uppercase block mb-1">Active Watchlists</span>
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold text-white font-mono">{watchlists.length}</span>
            <span className="text-xs font-mono text-cyan-400">Continuous Monitoring</span>
          </div>
        </div>
        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <span className="text-xs font-mono text-slate-500 uppercase block mb-1">Monitored Targets</span>
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold text-white font-mono">{totalTargetsCount}</span>
            <span className="text-xs font-mono text-emerald-400">Across 10 Categories</span>
          </div>
        </div>
        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <span className="text-xs font-mono text-slate-500 uppercase block mb-1">Matched Intel Hits</span>
          <div className="flex items-center justify-between">
            <span className="text-2xl font-bold text-white font-mono">{feed?.total_matches || 0}</span>
            <span className="text-xs font-mono text-amber-400">Current Scope</span>
          </div>
        </div>
      </div>

      {/* Main Command Center Layout: Left Sidebar + Right Surveillance Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Watchlist Selector & Management */}
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold uppercase tracking-wider text-slate-400 font-mono flex items-center gap-2">
              <span className="text-cyan-400">◈</span> Configured Watchlists
            </h2>
            <span className="text-xs font-mono text-slate-500">{watchlists.length} active</span>
          </div>

          <div className="space-y-3">
            {watchlists.map((wl) => {
              const isSelected = wl.id === selectedWlId;
              return (
                <div
                  key={wl.id}
                  onClick={() => setSelectedWlId(wl.id)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer flex flex-col justify-between ${
                    isSelected
                      ? "bg-slate-900/90 border-cyan-500/60 shadow-lg shadow-cyan-500/10 ring-1 ring-cyan-500/30"
                      : "bg-slate-950/60 border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            wl.is_active ? "bg-emerald-400 animate-pulse" : "bg-slate-600"
                          }`}
                        />
                        <h3 className="text-sm font-bold text-white leading-tight">{wl.name}</h3>
                      </div>
                      {wl.description && (
                        <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                          {wl.description}
                        </p>
                      )}
                    </div>
                    <button
                      onClick={(e) => handleDeleteWatchlist(wl.id, e)}
                      title="Delete Watchlist"
                      className="text-slate-500 hover:text-red-400 text-sm p-1 transition-colors"
                    >
                      &times;
                    </button>
                  </div>

                  <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono">
                    <span className="text-cyan-400 font-semibold">{wl.item_count || 0} targets</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                        {wl.notification_channel}
                      </span>
                      <button
                        onClick={(e) => handleToggleActive(wl, e)}
                        className={`text-[10px] uppercase px-1.5 py-0.5 rounded border transition-colors ${
                          wl.is_active
                            ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                            : "bg-slate-800 text-slate-500 border-slate-700"
                        }`}
                      >
                        {wl.is_active ? "Active" : "Paused"}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Column: Active Watchlist Surveillance Command */}
        <div className="lg:col-span-2 space-y-6">
          {activeWatchlist ? (
            <>
              {/* Active Watchlist Banner */}
              <div className="p-6 rounded-2xl cyber-card border border-cyan-500/30 bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                      <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold">
                        SURVEILLANCE RADAR ACTIVE
                      </span>
                      <span className="text-slate-600">&bull;</span>
                      <span className="text-xs font-mono text-slate-400">
                        Channel: <span className="text-amber-300 uppercase">{activeWatchlist.notification_channel}</span>
                      </span>
                    </div>
                    <h2 className="text-xl font-bold text-white tracking-tight">{activeWatchlist.name}</h2>
                    <p className="text-xs text-slate-400 mt-1">{activeWatchlist.description}</p>
                  </div>
                  <div className="text-right">
                    <span className="text-2xl font-bold text-cyan-400 font-mono">
                      {activeWatchlist.items?.length || 0}
                    </span>
                    <span className="text-xs font-mono text-slate-500 block">Monitored Targets</span>
                  </div>
                </div>

                {/* Section 32: Add Monitored Target Box (Supporting all 10 types) */}
                <div className="pt-4 border-t border-slate-800 space-y-3">
                  <div className="flex items-center justify-between flex-wrap gap-2">
                    <span className="text-xs font-mono uppercase text-slate-400 font-bold flex items-center gap-1.5">
                      <span>◈</span> Add Monitored Target (Select 1 of 10 Types):
                    </span>
                  </div>

                  {/* 10 Types Selector Pills */}
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {WATCHLIST_TYPES.map((t) => (
                      <button
                        key={t.type}
                        type="button"
                        onClick={() => setActiveType(t.type)}
                        className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all border ${
                          activeType === t.type
                            ? t.color + " font-bold shadow-sm"
                            : "bg-slate-950/60 text-slate-500 border-slate-800 hover:text-slate-300"
                        }`}
                      >
                        {t.label}
                      </button>
                    ))}
                  </div>

                  {/* Input Form */}
                  <form onSubmit={handleAddItem} className="flex flex-col sm:flex-row items-center gap-2.5">
                    <div className="relative flex-1 w-full">
                      <input
                        type="text"
                        value={itemValue}
                        onChange={(e) => setItemValue(e.target.value)}
                        placeholder={activeTypeConfig.placeholder}
                        className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs font-mono text-white placeholder:text-slate-600 focus:outline-none"
                      />
                    </div>
                    <select
                      value={itemSeverity}
                      onChange={(e) => setItemSeverity(e.target.value)}
                      className="px-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-slate-300 focus:outline-none shrink-0"
                    >
                      <option value="">Any Severity</option>
                      <option value="CRITICAL">Critical Only</option>
                      <option value="HIGH">High & Critical</option>
                      <option value="MEDIUM">Medium and Above</option>
                    </select>
                    <button
                      type="submit"
                      className="w-full sm:w-auto px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors shrink-0 shadow-sm"
                    >
                      + Track Target
                    </button>
                  </form>
                </div>
              </div>

              {/* Active Monitored Target Chips Cloud */}
              <div className="p-5 rounded-2xl cyber-card border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-2">
                    <span className="text-cyan-400">◈</span> Active Targets ({activeWatchlist.items?.length || 0})
                  </h3>
                  <span className="text-[11px] font-mono text-slate-500">Click &times; to remove</span>
                </div>

                {activeWatchlist.items && activeWatchlist.items.length > 0 ? (
                  <div className="flex items-center gap-2 flex-wrap">
                    {activeWatchlist.items.map((it) => {
                      const typeConfig =
                        WATCHLIST_TYPES.find((t) => t.type === it.item_type) || WATCHLIST_TYPES[0];
                      return (
                        <div
                          key={it.id}
                          className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 group transition-all ${typeConfig.color}`}
                        >
                          <span className="uppercase text-[10px] font-bold opacity-70">
                            {it.item_type}
                          </span>
                          <span className="font-semibold text-white">{it.item_value}</span>
                          {it.severity_threshold && (
                            <span className="text-[9px] uppercase px-1 rounded bg-black/40 text-red-300">
                              {it.severity_threshold}
                            </span>
                          )}
                          <button
                            onClick={() => handleRemoveItem(it.id)}
                            className="text-slate-400 hover:text-red-400 font-bold ml-1 transition-colors"
                          >
                            &times;
                          </button>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="py-6 text-center text-xs font-mono text-slate-500">
                    No monitored targets added yet. Use the panel above to add targets.
                  </div>
                )}
              </div>

              {/* Live Matched Intelligence Surveillance Feed */}
              <div className="space-y-4 pt-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                    <span className="text-cyan-400 font-mono">⚡</span> Matched Intelligence Feed
                  </h3>
                  <span className="text-xs font-mono text-slate-500">
                    {feed?.total_matches || 0} matching reports
                  </span>
                </div>

                {feedLoading ? (
                  <div className="py-12 text-center text-xs font-mono text-slate-500 animate-pulse">
                    Scanning repository against watched targets...
                  </div>
                ) : feed && feed.items.length > 0 ? (
                  <div className="space-y-3">
                    {feed.items.map((item) => (
                      <Link
                        key={item.content_id}
                        href={`/content/${item.content_id}`}
                        className="p-4 rounded-xl cyber-card border border-slate-800 hover:border-cyan-500/50 transition-all block group"
                      >
                        <div className="flex items-start justify-between gap-3 mb-2">
                          <div>
                            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                                {item.source}
                              </span>
                              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                                {item.content_type}
                              </span>
                              {item.severity && <SeverityBadge severity={item.severity as any} score={item.cvss_score} />}
                            </div>
                            <h4 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors leading-snug">
                              {item.title}
                            </h4>
                          </div>
                          <span className="text-cyan-400 text-xs font-mono shrink-0 group-hover:translate-x-0.5 transition-transform">
                            &rarr;
                          </span>
                        </div>

                        <p className="text-xs text-slate-400 line-clamp-2 mb-3 leading-relaxed">
                          {item.summary || item.description}
                        </p>

                        {/* Matched Hits Chips */}
                        <div className="flex items-center gap-2 flex-wrap pt-2 border-t border-slate-800/80">
                          <span className="text-[10px] font-mono text-slate-500 uppercase">Triggered By:</span>
                          {item.matched_items.map((hit, hidx) => (
                            <span
                              key={hidx}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/40 text-cyan-300 border border-cyan-500/30 flex items-center gap-1"
                            >
                              <span className="uppercase text-[9px] opacity-70">{hit.item_type}:</span>
                              <span className="font-bold">{hit.item_value}</span>
                            </span>
                          ))}
                        </div>
                      </Link>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 rounded-2xl bg-slate-950/60 border border-slate-800 text-center text-xs font-mono text-slate-500">
                    No intelligence articles currently trigger these surveillance rules.
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="py-20 text-center text-sm font-mono text-slate-500">
              No watchlist selected. Create or select a watchlist to begin surveillance.
            </div>
          )}
        </div>
      </div>

      {/* Create Watchlist Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
          <div className="cyber-card w-full max-w-lg rounded-2xl p-6 border border-slate-700 bg-slate-900 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold text-white font-mono flex items-center gap-2">
                <span className="text-cyan-400">⚡</span> Create New Watchlist
              </h3>
              <button
                onClick={() => setShowCreateModal(false)}
                className="text-slate-400 hover:text-white text-lg font-mono"
              >
                &times;
              </button>
            </div>

            <form onSubmit={handleCreateWatchlist} className="space-y-4">
              <div>
                <label className="text-xs font-mono text-slate-400 uppercase block mb-1">
                  Watchlist Name *
                </label>
                <input
                  type="text"
                  required
                  value={newWlName}
                  onChange={(e) => setNewWlName(e.target.value)}
                  placeholder="e.g. Critical Edge Gateways"
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs font-mono text-white focus:outline-none"
                />
              </div>

              <div>
                <label className="text-xs font-mono text-slate-400 uppercase block mb-1">
                  Surveillance Scope & Description
                </label>
                <textarea
                  rows={3}
                  value={newWlDesc}
                  onChange={(e) => setNewWlDesc(e.target.value)}
                  placeholder="Describe the threats, components, and purpose of this surveillance list..."
                  className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-800 focus:border-cyan-500 text-xs font-mono text-white focus:outline-none resize-none"
                />
              </div>

              <div>
                <label className="text-xs font-mono text-slate-400 uppercase block mb-1">
                  Alert Delivery Channel
                </label>
                <select
                  value={newWlChannel}
                  onChange={(e) => setNewWlChannel(e.target.value)}
                  className="w-full px-3.5 py-2.5 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-white focus:outline-none"
                >
                  <option value="in_app">In-App Notification Ledger</option>
                  <option value="email">Email Alert Notification</option>
                  <option value="webhook">Webhook Integration (SIEM / Slack)</option>
                </select>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-5 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs font-mono transition-colors"
                >
                  Create & Launch
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
