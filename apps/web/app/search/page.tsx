"use client";

import React, { useState, useEffect } from "react";
import { executeSearch } from "../../lib/api";
import { SearchResponse, SearchHitItem, ContentItem } from "../../lib/types";
import { SearchBar } from "../../components/SearchBar";
import { ContentModal } from "../../components/ContentModal";
import { formatDate } from "../../lib/formatters";

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
  const [showDiagnostics, setShowDiagnostics] = useState(false);

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

  const isDegraded = results?.engine_status === "degraded" || results?.vector_status === "failed";

  return (
    <div className="space-y-6 animate-in fade-in duration-200 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-[#E4DBC8] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-[#C2821A] font-bold uppercase tracking-wider">
              HYBRID INTEL SEARCH
            </span>
            <span className="text-[#8C887B]">&bull;</span>
            {/* Compact Status Indicator */}
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#F1EBD8] border border-[#E4DBC8] text-[11px] font-mono font-semibold">
              <span className="flex items-center gap-1 text-[#171714]">
                TEXT <span className="text-[#2D7A4F]">●</span>
              </span>
              {isDegraded ? (
                <span className="flex items-center gap-1 text-[#D97706]">
                  VECTOR <span className="font-bold text-[#D97706]">!</span>
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[#171714]">
                  VECTOR <span className="text-[#2D7A4F]">●</span>
                </span>
              )}
              {isDegraded ? (
                <span className="text-[#D97706] font-bold">RRF DEGRADED</span>
              ) : (
                <span className="flex items-center gap-1 text-[#171714]">
                  RRF <span className="text-[#2D7A4F]">●</span>
                </span>
              )}
            </div>
          </div>

          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#171714] tracking-tight font-sans">
            Reciprocal Rank Fusion Threat Search
          </h1>
          <p className="text-xs sm:text-sm text-[#68655B] mt-1 max-w-2xl">
            Simultaneously queries OpenSearch BM25 lexical text indexes and 384-dimensional dense vector embeddings with Reciprocal Rank Fusion (k=60).
          </p>
        </div>

        {/* Toggle Diagnostics */}
        <button
          onClick={() => setShowDiagnostics(!showDiagnostics)}
          className="text-xs font-mono text-[#68655B] hover:text-[#171714] flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8] transition-colors"
        >
          <span>{showDiagnostics ? "Hide" : "Show"} Search Diagnostics</span>
          <span>{showDiagnostics ? "▲" : "▼"}</span>
        </button>
      </div>

      {/* Expandable Search Diagnostics Section */}
      {showDiagnostics && results && (
        <div className="p-4 rounded-2xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm font-mono text-xs space-y-3">
          <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-2 font-bold text-[#171714]">
            <span className="uppercase tracking-wider text-[11px] text-[#C2821A]">Search Engine Diagnostics</span>
            <span>Query Runtime: {results.took_ms ? `${results.took_ms.toFixed(1)}ms` : "N/A"}</span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px]">
            <div className="p-2.5 rounded bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[#68655B] block uppercase text-[10px]">Engine Mode</span>
              <span className="font-bold text-[#171714] uppercase">{results.engine || mode}</span>
            </div>
            <div className="p-2.5 rounded bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[#68655B] block uppercase text-[10px]">Text Index Hits</span>
              <span className="font-bold text-[#171714]">{results.text_count ?? 0}</span>
            </div>
            <div className="p-2.5 rounded bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[#68655B] block uppercase text-[10px]">Vector k-NN Hits</span>
              <span className="font-bold text-[#171714]">{results.vector_count ?? 0}</span>
            </div>
            <div className="p-2.5 rounded bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[#68655B] block uppercase text-[10px]">RRF Constant</span>
              <span className="font-bold text-[#171714]">k = 60</span>
            </div>
          </div>
        </div>
      )}

      {/* Search Input Bar */}
      <SearchBar initialQuery={query} initialMode={mode} onSearch={handleSearchSubmit} />

      {/* Category Filter Pills */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 scrollbar-none font-mono text-xs">
        <span className="text-[#68655B] uppercase shrink-0 font-semibold mr-1">Category:</span>
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => handleCategorySelect(cat)}
            className={`px-3 py-1 rounded-lg text-xs whitespace-nowrap transition-colors ${
              selectedCategory === cat
                ? "bg-[#C2821A] text-white font-bold shadow-sm"
                : "bg-[#F1EBD8] text-[#68655B] hover:text-[#171714] border border-[#E4DBC8]"
            }`}
          >
            {cat.replace(/_/g, " ")}
          </button>
        ))}
      </div>

      {/* Error State Banner */}
      {results?.error && (
        <div className="p-4 rounded-xl bg-[#B91C1C]/10 border border-[#B91C1C]/30 text-[#B91C1C] text-xs font-mono flex items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <span className="text-base font-bold">⚠</span>
            <div>
              <span className="font-bold block">Search Engine Diagnostic Notice</span>
              <span>{results.error}</span>
            </div>
          </div>
          <button
            onClick={() => performSearch(query, mode, selectedCategory)}
            className="px-3 py-1.5 rounded-lg bg-[#B91C1C] text-white font-bold text-xs transition-colors shrink-0"
          >
            Retry Query
          </button>
        </div>
      )}

      {/* Results Telemetry & Stats */}
      {results && !results.error && (
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-[#68655B] border-b border-[#E4DBC8] pb-3">
          <div>
            Showing <strong className="text-[#171714]">{results.hits.length}</strong> intelligence records for{" "}
            <span className="text-[#C2821A] font-bold">&ldquo;{query}&rdquo;</span>
            {typeof results.took_ms === "number" && results.took_ms > 0 ? ` (${results.took_ms.toFixed(0)}ms)` : ""}
          </div>
          <div className="flex items-center gap-2">
            <span className="px-2 py-0.5 rounded bg-[#F1EBD8] border border-[#E4DBC8] text-[11px] text-[#171714] font-semibold">
              ENGINE: {mode.toUpperCase()}
            </span>
          </div>
        </div>
      )}

      {/* Results List */}
      <div className="space-y-4">
        {loading ? (
          <div className="p-12 text-center text-[#68655B] font-mono text-xs animate-pulse">
            Executing hybrid reciprocal rank fusion query across dense vector space and lexical indexes...
          </div>
        ) : results?.error ? null : results && results.hits.length > 0 ? (
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
              className="cyber-card rounded-2xl p-5 cursor-pointer group bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm hover:border-[#C2821A] transition-all"
            >
              {/* Header row: Source, Category, Type, Relevance chips, RRF score */}
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#F1EBD8] text-[#C2821A] border border-[#E4DBC8] font-bold">
                    {hit.source || "OSINT"}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#F1EBD8] text-[#68655B] border border-[#E4DBC8]">
                    {hit.category ? hit.category.replace(/_/g, " ") : "threat_intelligence"}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#F1EBD8] text-[#171714] border border-[#E4DBC8]">
                    {hit.content_type}
                  </span>

                  {/* Keyword & Semantic Relevance Metrics */}
                  {hit.keyword_rank && hit.semantic_rank ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#C2821A]/10 text-[#C2821A] border border-[#C2821A]/30 font-bold">
                      RRF Fused (Text #{hit.keyword_rank} + Vector #{hit.semantic_rank})
                    </span>
                  ) : hit.keyword_rank ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#F1EBD8] text-[#171714] border border-[#E4DBC8]">
                      Text Match #{hit.keyword_rank}
                    </span>
                  ) : hit.semantic_rank ? (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#7C3AED]/10 text-[#7C3AED] border border-[#7C3AED]/25">
                      Vector Match #{hit.semantic_rank}
                    </span>
                  ) : null}
                </div>

                <div className="text-right font-mono text-xs">
                  <span className="text-[#2D7A4F] font-bold px-2 py-0.5 rounded bg-[#2D7A4F]/10 border border-[#2D7A4F]/25">
                    {typeof hit.rrf_score === "number"
                      ? `RRF: ${hit.rrf_score.toFixed(4)}`
                      : `Score: ${hit.score.toFixed(3)}`}
                  </span>
                </div>
              </div>

              {/* Title */}
              <h3 className="text-base font-bold text-[#171714] group-hover:text-[#C2821A] transition-colors mb-2 font-sans">
                {hit.title}
              </h3>

              {/* Highlight / Snippet */}
              {hit.highlight && (
                <p className="text-xs sm:text-sm text-[#68655B] mb-3 leading-relaxed">
                  {hit.highlight}
                </p>
              )}

              {/* Matched Semantic Chunk */}
              {hit.matched_chunk && (
                <div className="p-3 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] text-xs font-mono text-[#171714] mb-3">
                  <span className="text-[#C2821A] font-bold block mb-1">SEMANTIC VECTOR EMBEDDING MATCH:</span>
                  {hit.matched_chunk}
                </div>
              )}

              {/* Footer row: Date, URL, Inspect action */}
              <div className="flex items-center justify-between text-xs font-mono text-[#68655B] pt-2.5 border-t border-[#E4DBC8]">
                <div className="flex items-center gap-3 truncate max-w-[70%]">
                  <span>{formatDate(hit.published_at)}</span>
                  <span className="truncate text-[#8C887B]">{hit.canonical_url}</span>
                </div>
                <span className="text-[#C2821A] group-hover:underline font-bold shrink-0">
                  Inspect details &rarr;
                </span>
              </div>
            </div>
          ))
        ) : (
          <div className="cyber-card rounded-2xl p-12 text-center text-[#68655B] font-mono text-sm bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
            No intelligence items match your query. Try adjusting keyword terms or category filters.
          </div>
        )}
      </div>

      <ContentModal item={modalItem} onClose={() => setModalItem(null)} />
    </div>
  );
}
