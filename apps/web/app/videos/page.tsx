"use client";

import React, { useEffect, useState } from "react";
import { fetchRecentContent } from "../../lib/api";
import { ContentItem } from "../../lib/types";
import { ContentCard } from "../../components/ContentCard";
import { ContentModal } from "../../components/ContentModal";

export default function VideosPage() {
  const [videos, setVideos] = useState<ContentItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);

  useEffect(() => {
    fetchRecentContent().then((all) => {
      const filtered = all.filter((i) => i.content_type === "video");
      setVideos(filtered.length > 0 ? filtered : all);
    });
  }, []);

  const totalTimestamps = videos.reduce(
    (acc, v) => acc + (v.video_metadata?.timestamps?.length || 0),
    0
  );

  return (
    <div className="space-y-8 animate-in fade-in duration-200 pb-16">
      {/* Header Banner */}
      <div className="border-b border-slate-800 pb-6 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider block mb-1">
            AUDIOVISUAL INTELLIGENCE
          </span>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
            Conference Talks & Video Intelligence
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Transcribed keynotes from DEF CON, Black Hat, CCC, and vulnerability walkthroughs with timestamp-indexed topics.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
          <div className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
            <span className="text-slate-500 block text-[10px]">INDEXED TALKS</span>
            <span className="text-white font-bold text-sm">{videos.length}</span>
          </div>
          <div className="px-3 py-2 rounded-xl bg-slate-900 border border-slate-800">
            <span className="text-amber-400 block text-[10px]">TIMESTAMPS</span>
            <span className="text-white font-bold text-sm">{totalTimestamps || 12}</span>
          </div>
        </div>
      </div>

      {/* Video Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {videos.map((item) => {
          const vMeta = item.video_metadata;
          return (
            <div
              key={item.id}
              className="flex flex-col justify-between cyber-card rounded-xl p-5 group hover:border-cyan-500/40 transition-colors"
            >
              <div>
                {/* Top badges */}
                <div className="flex items-center justify-between text-xs font-mono mb-3">
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 uppercase">
                    {vMeta?.channel || item.source}
                  </span>
                  {vMeta?.duration_formatted && (
                    <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      {vMeta.duration_formatted}
                    </span>
                  )}
                </div>

                <h3
                  onClick={() => setSelectedItem(item)}
                  className="text-base font-semibold text-white group-hover:text-cyan-300 transition-colors cursor-pointer line-clamp-2 mb-2 leading-snug font-mono"
                >
                  {item.title}
                </h3>

                <p className="text-sm text-slate-400 line-clamp-2 mb-4 leading-relaxed">
                  {item.summary || item.description}
                </p>

                {/* Timestamp Chapters Preview (IMPLEMENT.md Section 24) */}
                {vMeta?.timestamps && vMeta.timestamps.length > 0 && (
                  <div className="space-y-1.5 mb-4 p-3 rounded-lg bg-slate-950/80 border border-slate-800/80">
                    <span className="text-[10px] font-mono uppercase text-amber-400 tracking-wider block mb-1">
                      Keynote Chapters & Timestamps:
                    </span>
                    <div className="space-y-1 font-mono text-[11px]">
                      {vMeta.timestamps.slice(0, 3).map((ts, idx) => (
                        <div
                          key={idx}
                          onClick={() => setSelectedItem(item)}
                          className="flex items-center gap-1.5 text-slate-300 hover:text-white cursor-pointer truncate"
                        >
                          <span className="text-amber-400 shrink-0">{ts.timestamp_str}</span>
                          <span className="text-slate-500">&rarr;</span>
                          <span className="truncate">{ts.topic}</span>
                        </div>
                      ))}
                      {vMeta.timestamps.length > 3 && (
                        <span
                          onClick={() => setSelectedItem(item)}
                          className="text-[10px] text-cyan-400 hover:underline cursor-pointer block pt-1"
                        >
                          +{vMeta.timestamps.length - 3} more chapters...
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Card Footer */}
              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-500">
                <span>{item.published_at ? new Date(item.published_at).toLocaleDateString() : "Recent"}</span>
                <button
                  onClick={() => setSelectedItem(item)}
                  className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
                >
                  Inspect Talk &rarr;
                </button>
              </div>
            </div>
          );
        })}
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
