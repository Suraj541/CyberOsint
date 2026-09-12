"use client";

import React, { useEffect, useState } from "react";
import {
  fetchSources,
  getAllSourceQualities,
  recalculateAllSourceQualities,
  triggerSourceSync,
} from "../../lib/api";
import { SourceConnectorItem, SourceQuality } from "../../lib/types";
import { SourceQualityBadge } from "../../components/SourceQualityBadge";

export default function SourcesPage() {
  const [sources, setSources] = useState<SourceConnectorItem[]>([]);
  const [qualities, setQualities] = useState<Record<number, SourceQuality>>({});
  const [syncingId, setSyncingId] = useState<number | null>(null);
  const [recalculating, setRecalculating] = useState<boolean>(false);
  const [selectedTier, setSelectedTier] = useState<string>("all");
  const [notification, setNotification] = useState<string | null>(null);

  useEffect(() => {
    async function loadData() {
      const [srcList, qualList] = await Promise.all([
        fetchSources(),
        getAllSourceQualities(),
      ]);
      setSources(srcList);
      const qualMap: Record<number, SourceQuality> = {};
      qualList.forEach((q) => {
        qualMap[q.source_id] = q;
      });
      setQualities(qualMap);
    }
    loadData();
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

  const handleRecalculateAll = async () => {
    setRecalculating(true);
    try {
      const res = await recalculateAllSourceQualities();
      const qualMap: Record<number, SourceQuality> = {};
      res.qualities.forEach((q) => {
        qualMap[q.source_id] = q;
      });
      setQualities(qualMap);
      setNotification(`Recalculated reliability metrics across ${res.recalculated_count} sources.`);
      setTimeout(() => setNotification(null), 4000);
    } catch (err: any) {
      alert("Error recalculating quality metrics: " + err.message);
    } finally {
      setRecalculating(false);
    }
  };

  // Filter sources by tier
  const filteredSources = sources.filter((src) => {
    if (selectedTier === "all") return true;
    const q = qualities[src.id];
    if (!q) return false;
    if (selectedTier === "tier1") return q.overall_score >= 0.85;
    if (selectedTier === "tier2") return q.overall_score >= 0.70 && q.overall_score < 0.85;
    if (selectedTier === "tier3") return q.overall_score < 0.70;
    return true;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              INGESTION CONTROLLER & FEED REGISTRY
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
              IMPLEMENT.md Section 28
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Source Reliability & Feed Registry
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            Internal ranking indicator evaluating authority, accuracy, technical depth,
            originality, and historical reliability. (Non-authoritative ranking mechanism).
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleRecalculateAll}
            disabled={recalculating}
            className="px-3.5 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-cyan-300 text-xs font-mono transition-colors flex items-center gap-1.5"
            title="Recalculate 5-dimension quality metrics for all sources"
          >
            <span className={recalculating ? "animate-spin" : ""}>↻</span>
            <span>{recalculating ? "Evaluating..." : "Recalculate Reliability"}</span>
          </button>

          <button
            onClick={() => {
              alert("To register a new source, use the /api/v1/sources endpoint or source registry CLI.");
            }}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm"
          >
            + Register New Feed
          </button>
        </div>
      </div>

      {notification && (
        <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-mono flex items-center justify-between animate-fadeIn">
          <span>⚡ {notification}</span>
          <button onClick={() => setNotification(null)} className="text-slate-400 hover:text-white">
            ✕
          </button>
        </div>
      )}

      {/* Tier Filter Tabs */}
      <div className="flex items-center gap-2 p-1 rounded-lg bg-slate-900/90 border border-slate-800 self-start w-fit">
        {[
          { id: "all", label: "All Sources" },
          { id: "tier1", label: "Tier 1: Authoritative (A+ / A)" },
          { id: "tier2", label: "Tier 2: High Reliability (B+)" },
          { id: "tier3", label: "Tier 3: Standard (B / C)" },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setSelectedTier(tab.id)}
            className={`px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              selectedTier === tab.id
                ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Sources Listing */}
      <div className="space-y-4">
        {filteredSources.map((src) => {
          const quality = qualities[src.id];
          return (
            <div
              key={src.id}
              className="cyber-card rounded-xl p-5 border border-slate-800 flex flex-col gap-4 hover:border-cyan-500/30 transition-colors"
            >
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
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

                    {/* Source Quality Reliability Indicator Badge */}
                    <SourceQualityBadge quality={quality} sourceName={src.name} size="sm" />
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

                <div className="flex items-center gap-3 shrink-0">
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

              {/* 5-Dimension Mini Progress Bars */}
              {quality && (
                <div className="pt-3 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-5 gap-3 text-[11px] font-mono">
                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Authority</span>
                      <span className="text-cyan-300 font-bold">
                        {(quality.authority * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5">
                      <div
                        className="bg-cyan-400 h-1.5 rounded-full"
                        style={{ width: `${quality.authority * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Accuracy</span>
                      <span className="text-emerald-300 font-bold">
                        {(quality.accuracy * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5">
                      <div
                        className="bg-emerald-400 h-1.5 rounded-full"
                        style={{ width: `${quality.accuracy * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Tech Depth</span>
                      <span className="text-purple-300 font-bold">
                        {(quality.technical_depth * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5">
                      <div
                        className="bg-purple-400 h-1.5 rounded-full"
                        style={{ width: `${quality.technical_depth * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Originality</span>
                      <span className="text-amber-300 font-bold">
                        {(quality.originality * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5">
                      <div
                        className="bg-amber-400 h-1.5 rounded-full"
                        style={{ width: `${quality.originality * 100}%` }}
                      />
                    </div>
                  </div>

                  <div className="space-y-1 col-span-2 sm:col-span-1">
                    <div className="flex justify-between text-slate-400">
                      <span>Reliability</span>
                      <span className="text-blue-300 font-bold">
                        {(quality.historical_reliability * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-900 rounded-full h-1.5">
                      <div
                        className="bg-blue-400 h-1.5 rounded-full"
                        style={{ width: `${quality.historical_reliability * 100}%` }}
                      />
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
