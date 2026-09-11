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

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="border-b border-slate-800 pb-5">
        <span className="text-xs font-mono text-emerald-400 uppercase tracking-wider block mb-1">
          AUDIOVISUAL INTELLIGENCE
        </span>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Conference Talks & Video Intelligence
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Keynotes from DEF CON, Black Hat, CCC, and vulnerability walkthroughs.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {videos.map((item) => (
          <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
        ))}
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
