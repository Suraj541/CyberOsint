"use client";

import React, { useEffect, useState } from "react";
import { fetchSources, triggerSourceSync } from "../../lib/api";
import { SourceConnectorItem } from "../../lib/types";

export default function SourcesPage() {
  const [sources, setSources] = useState<SourceConnectorItem[]>([]);
  const [syncingId, setSyncingId] = useState<number | null>(null);
  const [notification, setNotification] = useState<string | null>(null);

  useEffect(() => {
    fetchSources().then(setSources);
  }, []);

  const handleSync = async (id: number) => {
    setSyncingId(id);
    try {
      const res = await triggerSourceSync(id);
      setNotification(res.message);
      setTimeout(() => setNotification(null), 4000);
    } finally {
      setSyncingId(null);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block mb-1">
            INGESTION CONTROLLER & PIPELINE
          </span>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Source Connectors & Feed Registry
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Manage automated crawlers, RSS feeds, CVE API polls, GitHub security advisory monitors, and CERT endpoints.
          </p>
        </div>

        <button
          onClick={() => {
            alert("To register a new source, use the /api/v1/sources endpoint or source registry CLI.");
          }}
          className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm"
        >
          + Register New Feed
        </button>
      </div>

      {notification && (
        <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between">
          <span>⚡ {notification}</span>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      <div className="space-y-4">
        {sources.map((src) => (
          <div
            key={src.id}
            className="cyber-card rounded-xl p-5 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-cyan-500/30 transition-colors"
          >
            <div className="space-y-1.5 flex-1">
              <div className="flex items-center gap-2.5 flex-wrap">
                <span className="font-bold text-base text-white">{src.name}</span>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 uppercase">
                  {src.connector_type}
                </span>
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded border ${
                    src.is_active
                      ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                      : "bg-slate-800 text-slate-500 border-slate-700"
                  }`}
                >
                  {src.is_active ? "ACTIVE" : "PAUSED"}
                </span>
              </div>

              <div className="text-xs font-mono text-slate-400 truncate max-w-xl">{src.url}</div>

              <div className="flex items-center gap-4 text-xs font-mono text-slate-500 pt-1">
                <span>Interval: {src.fetch_interval_minutes}m</span>
                <span>&bull;</span>
                <span>
                  Last Run:{" "}
                  {src.last_fetched_at
                    ? new Date(src.last_fetched_at).toLocaleTimeString()
                    : "Not yet polled"}
                </span>
                <span>&bull;</span>
                <span>Items: {src.items_count?.toLocaleString() || 0}</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <button
                disabled={syncingId === src.id}
                onClick={() => handleSync(src.id)}
                className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 text-xs font-mono transition-colors disabled:opacity-50 flex items-center gap-1.5"
              >
                {syncingId === src.id ? (
                  <>
                    <span className="animate-spin text-cyan-400">↻</span>
                    <span>Syncing...</span>
                  </>
                ) : (
                  <>
                    <span>↻</span>
                    <span>Sync Now</span>
                  </>
                )}
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
