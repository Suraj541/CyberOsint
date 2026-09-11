"use client";

import React, { useEffect, useState } from "react";
import { fetchRecentContent } from "../../lib/api";
import { ContentItem } from "../../lib/types";
import { ContentCard } from "../../components/ContentCard";
import { ContentModal } from "../../components/ContentModal";

export default function NewsPage() {
  const [items, setItems] = useState<ContentItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [filterSource, setFilterSource] = useState<string>("all");

  useEffect(() => {
    fetchRecentContent().then((all) => {
      setItems(all.filter((i) => i.content_type === "article" || i.content_type === "advisory"));
    });
  }, []);

  const sources = ["all", ...Array.from(new Set(items.map((i) => i.source)))];
  const displayedItems =
    filterSource === "all" ? items : items.filter((i) => i.source === filterSource);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block mb-1">
            INTELLIGENCE DISPATCH
          </span>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Cybersecurity News & Advisories
          </h1>
        </div>

        {/* Source Filter */}
        <div className="flex items-center gap-2 overflow-x-auto pb-1">
          {sources.map((src) => (
            <button
              key={src}
              onClick={() => setFilterSource(src)}
              className={`px-3 py-1 rounded-lg text-xs font-mono whitespace-nowrap transition-colors ${
                filterSource === src
                  ? "bg-cyan-500 text-slate-950 font-bold"
                  : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {src.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {displayedItems.map((item) => (
          <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
        ))}
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
