"use client";

import React, { useState, useEffect } from "react";
import { executeSearch } from "../../lib/api";
import { SearchResponse, SearchHitItem, ContentItem } from "../../lib/types";
import { SearchBar } from "../../components/SearchBar";
import { ContentModal } from "../../components/ContentModal";

const CATEGORIES = [
  "all",
  "vulnerability_management",
  "malware",
  "application_security",
  "cloud_security",
  "network_security",
  "threat_intelligence",
  "digital_forensics",
];

export default function SearchPage() {
  const [query, setQuery] = useState("ransomware zero-day");
  const [mode, setMode] = useState<"hybrid" | "keyword">("hybrid");
  const [selectedCategory, setSelectedCategory] = useState("all");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [modalItem, setModalItem] = useState<ContentItem | null>(null);

  const performSearch = async (q: string, m: "hybrid" | "keyword", cat: string = selectedCategory) => {
    setLoading(true);
    try {
      const resp = await executeSearch(
        q,
        m,
        cat === "all" ? undefined : cat
      );
      setResults(resp);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    performSearch(query, mode, selectedCategory);
  }, []);

  const handleSearchSubmit = (newQuery: string, newMode: "hybrid" | "keyword") => {
    setQuery(newQuery);
    setMode(newMode);
    performSearch(newQuery, newMode, selectedCategory);
  };

  const handleCategorySelect = (cat: string) => {
    setSelectedCategory(cat);
    performSearch(query, mode, cat);
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
            SEARCH & DISCOVERY
          </span>
          <span className="text-slate-600">&bull;</span>
          <span className="text-xs font-mono text-slate-400">
            {mode === "hybrid" ? "RECIPROCAL RANK FUSION (RRF)" : "LEXICAL KEYWORD"}
          </span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Hybrid Threat Search Engine
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Simultaneously queries OpenSearch text indexes and 384-dimensional dense vector embeddings with Reciprocal Rank Fusion ($k=60$).
        </p>
      </div>

      {/* Search Input Bar */}
      <SearchBar initialQuery={query} initialMode={mode} onSearch={handleSearchSubmit} />

      {/* Category Filter Pills */}
      <div className="flex items-center gap-2 overflow-x-auto pb-2 scrollbar-none">
        <span className="text-xs font-mono text-slate-500 uppercase shrink-0">Category:</span>
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => handleCategorySelect(cat)}
            className={`px-3 py-1 rounded-lg text-xs font-mono whitespace-nowrap transition-colors ${
              selectedCategory === cat
                ? "bg-cyan-500 text-slate-950 font-bold"
                : "bg-slate-900/80 text-slate-400 hover:text-slate-200 border border-slate-800"
            }`}
          >
            {cat.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {/* Results Telemetry & Stats */}
      {results && (
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 border-b border-slate-800 pb-3">
          <div>
            Showing <span className="text-white font-bold">{results.hits.length}</span> hits for{" "}
            <span className="text-cyan-400">&ldquo;{query}&rdquo;</span> (took {results.took_ms}ms)
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px]">
              ENGINE: {mode.toUpperCase()}
            </span>
          </div>
        </div>
      )}

      {/* Results List */}
      <div className="space-y-4">
        {loading ? (
          <div className="p-12 text-center text-slate-500 font-mono text-xs animate-pulse">
            Executing hybrid vector ranking and reciprocal rank fusion...
          </div>
        ) : results && results.hits.length > 0 ? (
          results.hits.map((hit) => (
            <div
              key={hit.id}
              onClick={() =>
                setModalItem({
                  id: hit.id,
                  title: hit.title,
                  canonical_url: hit.canonical_url,
                  content_type: (hit.content_type as any) || "article",
                  source: hit.source || "OSINT",
                  category: hit.category || "threat_intelligence",
                  summary: hit.matched_chunk || hit.highlight,
                  description: hit.highlight,
                  published_at: hit.published_at,
                  tags: hit.tags,
                })
              }
              className="cyber-card rounded-xl p-5 cursor-pointer group hover:border-cyan-500/50 transition-all"
            >
              <div className="flex items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                    {hit.source || "OSINT"}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-400 border border-slate-700">
                    {hit.category ? hit.category.replace(/_/g, " ") : "general"}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-violet-500/10 text-violet-300 border border-violet-500/20">
                    {hit.content_type}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-xs font-mono text-emerald-400">
                    Score: {hit.score.toFixed(3)}
                  </span>
                </div>
              </div>

              <h3 className="text-base font-bold text-white group-hover:text-cyan-300 transition-colors mb-2">
                {hit.title}
              </h3>

              {hit.highlight && (
                <p className="text-sm text-slate-300 mb-3 leading-relaxed">
                  {hit.highlight}
                </p>
              )}

              {hit.matched_chunk && (
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono text-slate-400 mb-3">
                  <span className="text-cyan-400 block mb-1">SEMANTIC VECTOR MATCH:</span>
                  {hit.matched_chunk}
                </div>
              )}

              <div className="flex items-center justify-between text-xs font-mono text-slate-500 pt-2 border-t border-slate-800/60">
                <span>{hit.canonical_url}</span>
                <span className="text-cyan-400 group-hover:underline">Inspect details &rarr;</span>
              </div>
            </div>
          ))
        ) : (
          <div className="cyber-card rounded-xl p-12 text-center text-slate-400 font-mono text-sm">
            No intelligence items match your query. Try adjusting keyword or category filters.
          </div>
        )}
      </div>

      <ContentModal item={modalItem} onClose={() => setModalItem(null)} />
    </div>
  );
}
