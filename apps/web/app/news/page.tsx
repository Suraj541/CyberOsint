"use client";

import React, { useEffect, useState, useMemo } from "react";
import { fetchRecentContent } from "../../lib/api";
import { ContentItem } from "../../lib/types";
import { ContentCard } from "../../components/ContentCard";
import { ContentModal } from "../../components/ContentModal";
import { safeUpper, formatDate } from "../../lib/formatters";

export default function NewsPage() {
  const [items, setItems] = useState<ContentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [filterSource, setFilterSource] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedCategory, setSelectedCategory] = useState<string>("all");

  useEffect(() => {
    setLoading(true);
    fetchRecentContent("article,advisory", undefined, 100)
      .then((data) => {
        setItems(data);
      })
      .catch(() => {
        setItems([]);
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  // Compute source distribution
  const sourceStats = useMemo(() => {
    const counts: Record<string, number> = {};
    items.forEach((item) => {
      if (item.source) {
        counts[item.source] = (counts[item.source] || 0) + 1;
      }
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [items]);

  // Compute category distribution
  const categoryStats = useMemo(() => {
    const counts: Record<string, number> = {};
    items.forEach((item) => {
      const cat = item.category || "General Threat";
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [items]);

  const filteredItems = useMemo(() => {
    return items.filter((item) => {
      if (filterSource !== "all" && item.source !== filterSource) return false;
      if (selectedCategory !== "all" && (item.category || "General Threat") !== selectedCategory) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = item.title?.toLowerCase().includes(q);
        const matchSnippet = (item.summary || item.description || "").toLowerCase().includes(q);
        const matchSource = item.source?.toLowerCase().includes(q);
        if (!matchTitle && !matchSnippet && !matchSource) return false;
      }
      return true;
    });
  }, [items, filterSource, selectedCategory, searchQuery]);

  // Lead story: highest severity or first item
  const leadStory = filteredItems.length > 0 ? filteredItems[0] : null;
  const chronologicalDispatches = filteredItems.length > 1 ? filteredItems.slice(1) : [];

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Editorial Intelligence Header */}
      <div className="border-b border-paper-border pb-6 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2.5 h-2.5 rounded-full bg-paper-accent animate-pulse" />
            <span className="text-[11px] font-mono tracking-widest uppercase text-paper-accent font-semibold">
              INTELLIGENCE DISPATCH // SITUATION BRIEFING
            </span>
            <span className="text-[11px] font-mono text-paper-muted border border-paper-border rounded px-1.5 py-0.5">
              CYCLE: LIVE
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-serif font-bold text-paper-ink tracking-tight">
            Threat Intelligence & Advisory Wire
          </h1>
          <p className="text-sm text-paper-muted mt-1 max-w-2xl">
            Curated reporting from sovereign cybersecurity agencies, independent threat research labs, and incident response teams.
          </p>
        </div>

        {/* Live wire search */}
        <div className="w-full md:w-72">
          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search wire dispatches..."
              className="w-full bg-paper-card border border-paper-border rounded-lg px-3.5 py-2 text-xs font-mono text-paper-ink placeholder:text-paper-muted focus:outline-none focus:border-paper-accent focus:ring-1 focus:ring-paper-accent"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-2.5 top-2 text-xs text-paper-muted hover:text-paper-ink font-mono"
              >
                ✕
              </button>
            )}
          </div>
        </div>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-24 space-y-3">
          <div className="w-8 h-8 border-2 border-paper-accent border-t-transparent rounded-full animate-spin" />
          <p className="font-mono text-xs text-paper-muted uppercase tracking-wider">
            Compiling intelligence wire...
          </p>
        </div>
      ) : filteredItems.length === 0 ? (
        <div className="text-center py-16 bg-paper-card border border-paper-border rounded-xl p-8">
          <div className="text-paper-accent text-3xl mb-2 font-mono">∅</div>
          <h3 className="font-serif text-lg font-bold text-paper-ink">No Dispatches Match Criteria</h3>
          <p className="text-xs font-mono text-paper-muted mt-1">
            Try resetting your source filter or clearing the search query.
          </p>
          <button
            onClick={() => {
              setFilterSource("all");
              setSelectedCategory("all");
              setSearchQuery("");
            }}
            className="mt-4 px-4 py-1.5 bg-paper-panel hover:bg-paper-border border border-paper-border rounded-lg text-xs font-mono text-paper-ink transition-colors"
          >
            Reset All Filters
          </button>
        </div>
      ) : (
        <div className="space-y-8">
          {/* TOP STORY / LEAD DOSSIER */}
          {leadStory && (
            <div className="bg-paper-card border-2 border-paper-border rounded-2xl p-6 lg:p-8 shadow-sm relative overflow-hidden">
              <div className="absolute top-0 right-0 px-4 py-1.5 bg-paper-accent text-paper-card font-mono text-[10px] font-bold uppercase tracking-widest rounded-bl-xl">
                TOP DISPATCH // LEAD STORY
              </div>

              <div className="max-w-4xl space-y-4">
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold uppercase bg-paper-panel text-paper-accent border border-paper-border">
                    {leadStory.source || "OFFICIAL SOURCE"}
                  </span>
                  <span className="text-[11px] font-mono text-paper-muted">
                    {formatDate(leadStory.published_at)}
                  </span>
                  {leadStory.category && (
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-paper-bg text-paper-ink border border-paper-border">
                      {leadStory.category}
                    </span>
                  )}
                  {leadStory.severity && (
                    <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      leadStory.severity === "CRITICAL"
                        ? "bg-red-100 text-red-800 border border-red-200"
                        : leadStory.severity === "HIGH"
                        ? "bg-amber-100 text-amber-800 border border-amber-200"
                        : "bg-paper-panel text-paper-muted"
                    }`}>
                      {leadStory.severity}
                    </span>
                  )}
                </div>

                <h2
                  onClick={() => setSelectedItem(leadStory)}
                  className="text-2xl sm:text-3xl lg:text-4xl font-serif font-bold text-paper-ink hover:text-paper-accent cursor-pointer transition-colors leading-tight"
                >
                  {leadStory.title}
                </h2>

                <p className="text-sm sm:text-base text-paper-muted font-sans line-clamp-3 leading-relaxed">
                  {leadStory.summary || leadStory.description || "Full advisory intelligence available in detailed dossier view."}
                </p>

                <div className="flex flex-wrap items-center justify-between gap-4 pt-2 border-t border-paper-border">
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => setSelectedItem(leadStory)}
                      className="px-4 py-2 bg-paper-accent hover:bg-amber-700 text-white font-mono text-xs font-semibold rounded-lg shadow-sm transition-colors flex items-center gap-2"
                    >
                      Read Full Dispatch →
                    </button>
                    {leadStory.canonical_url && (
                      <a
                        href={leadStory.canonical_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="px-3 py-2 bg-paper-panel hover:bg-paper-border border border-paper-border text-paper-ink font-mono text-xs rounded-lg transition-colors"
                      >
                        External Source ↗
                      </a>
                    )}
                  </div>
                  <div className="text-[11px] font-mono text-paper-muted">
                    REF: #{leadStory.id} // PUBLISHED: {formatDate(leadStory.published_at)}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* MAIN LAYOUT: CHRONOLOGICAL DISPATCHES + SIDEBAR TELEMETRY */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            {/* LEFT 8 COLS: CHRONOLOGICAL BULLETINS */}
            <div className="lg:col-span-8 space-y-4">
              <div className="flex items-center justify-between border-b border-paper-border pb-2">
                <h3 className="font-mono text-xs uppercase tracking-widest text-paper-ink font-bold flex items-center gap-2">
                  <span className="w-2 h-2 rounded bg-paper-accent" />
                  CHRONOLOGICAL DISPATCHES ({filteredItems.length})
                </h3>
                <span className="text-[11px] font-mono text-paper-muted">
                  SORT: MOST RECENT
                </span>
              </div>

              {chronologicalDispatches.length === 0 && filteredItems.length <= 1 ? (
                <p className="text-xs font-mono text-paper-muted py-6">
                  Only lead dispatch available for this query filter.
                </p>
              ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {chronologicalDispatches.map((item) => (
                    <ContentCard
                      key={item.id}
                      item={item}
                      onSelect={setSelectedItem}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* RIGHT 4 COLS: TELEMETRY & CATEGORY BRIEFING */}
            <div className="lg:col-span-4 space-y-6">
              {/* SOURCE ACTIVITY & TELEMETRY */}
              <div className="bg-paper-card border border-paper-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-paper-border pb-2">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-paper-ink font-bold">
                    SOURCE ACTIVITY
                  </h4>
                  <span className="text-[10px] font-mono text-paper-muted">
                    {sourceStats.length} CHANNELS
                  </span>
                </div>

                <div className="space-y-1.5">
                  <button
                    onClick={() => setFilterSource("all")}
                    className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition-colors ${
                      filterSource === "all"
                        ? "bg-paper-panel text-paper-ink font-bold border border-paper-border"
                        : "text-paper-muted hover:text-paper-ink hover:bg-paper-bg"
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full ${filterSource === "all" ? "bg-paper-accent" : "bg-paper-muted"}`} />
                      ALL MONITORED FEEDS
                    </span>
                    <span className="text-[11px] text-paper-muted">{items.length}</span>
                  </button>

                  {sourceStats.map(([src, count]) => (
                    <button
                      key={src}
                      onClick={() => setFilterSource(src)}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition-colors ${
                        filterSource === src
                          ? "bg-paper-panel text-paper-ink font-bold border border-paper-border"
                          : "text-paper-muted hover:text-paper-ink hover:bg-paper-bg"
                      }`}
                    >
                      <span className="flex items-center gap-2 truncate pr-2">
                        <span className={`w-1.5 h-1.5 rounded-full ${filterSource === src ? "bg-paper-accent" : "bg-paper-border"}`} />
                        <span className="truncate">{safeUpper(src)}</span>
                      </span>
                      <span className="text-[11px] text-paper-muted font-normal">{count}</span>
                    </button>
                  ))}
                </div>
              </div>

              {/* THREAT CATEGORIES */}
              <div className="bg-paper-card border border-paper-border rounded-xl p-5 shadow-sm space-y-4">
                <div className="flex items-center justify-between border-b border-paper-border pb-2">
                  <h4 className="font-mono text-xs uppercase tracking-wider text-paper-ink font-bold">
                    THREAT CATEGORIES
                  </h4>
                  <span className="text-[10px] font-mono text-paper-muted">
                    TAXONOMY
                  </span>
                </div>

                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => setSelectedCategory("all")}
                    className={`px-2.5 py-1 rounded-md text-xs font-mono transition-colors ${
                      selectedCategory === "all"
                        ? "bg-paper-accent text-paper-card font-bold"
                        : "bg-paper-panel text-paper-muted hover:text-paper-ink border border-paper-border"
                    }`}
                  >
                    ALL
                  </button>
                  {categoryStats.map(([cat, count]) => (
                    <button
                      key={cat}
                      onClick={() => setSelectedCategory(cat)}
                      className={`px-2.5 py-1 rounded-md text-xs font-mono transition-colors ${
                        selectedCategory === cat
                          ? "bg-paper-accent text-paper-card font-bold"
                          : "bg-paper-panel text-paper-muted hover:text-paper-ink border border-paper-border"
                      }`}
                    >
                      {cat} ({count})
                    </button>
                  ))}
                </div>
              </div>

              {/* INTELLIGENCE STANDARDS DOSSIER NOTICE */}
              <div className="bg-paper-panel border border-paper-border rounded-xl p-4 text-xs font-mono text-paper-muted space-y-2">
                <div className="flex items-center gap-1.5 text-paper-ink font-bold">
                  <span>ℹ</span>
                  <span>DISPATCH PROTOCOL</span>
                </div>
                <p className="text-[11px] leading-relaxed">
                  Advisories and articles ingested here are normalized across RSS/Atom wire sources, sovereign CERT feeds, and national vulnerability databases. Entities mentioned are automatically linked into the knowledge graph.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
