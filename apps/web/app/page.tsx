"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ContentItem,
  DashboardData,
  TrendingTopic,
} from "../lib/types";
import { fetchDashboard } from "../lib/api";
import { StatCard } from "../components/StatCard";
import { ContentCard } from "../components/ContentCard";
import { ContentModal } from "../components/ContentModal";
import { SeverityBadge } from "../components/SeverityBadge";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const d = await fetchDashboard();
        setData(d);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const metrics = data?.metrics;

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              OPERATIONAL COMMAND CENTER
            </span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-xs font-mono text-emerald-400">REAL DATABASE AGGREGATION</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Threat Intelligence Unified Dashboard
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/search"
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm flex items-center gap-1.5"
          >
            <span>Hybrid Search (RRF) &rarr;</span>
          </Link>
        </div>
      </div>

      {/* Section 21: Real Database Aggregate Telemetry */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Aggregated Content"
          value={metrics ? metrics.total_content.toLocaleString() : "..."}
          change="real-time"
          accentColor="cyan"
          iconText="⚡"
        />
        <StatCard
          title="Active Feeds & Connectors"
          value={metrics ? metrics.active_sources : "..."}
          change="100% online"
          accentColor="emerald"
          iconText="🖧"
        />
        <StatCard
          title="Tracked Vulnerabilities (CVE)"
          value={metrics ? metrics.tracked_cves.toLocaleString() : "..."}
          change="KEV active"
          accentColor="crimson"
          iconText="🛡"
        />
        <StatCard
          title="Critical Threat Advisories"
          value={metrics ? metrics.threat_advisories.toLocaleString() : "..."}
          change="active triage"
          accentColor="amber"
          iconText="⚠"
        />
      </div>

      {/* Section 21 Component 4: Trending Topics Strip */}
      {data && data.trending_topics && data.trending_topics.length > 0 && (
        <div className="p-4 rounded-xl cyber-card border border-slate-800">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-mono text-sm">◈</span>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                Trending Security Entities & Topics
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              Aggregated from extracted entity frequencies
            </span>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {data.trending_topics.map((topic, idx) => (
              <Link
                key={idx}
                href={`/search?q=${encodeURIComponent(topic.name)}`}
                className="px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono transition-colors flex items-center gap-2 group"
              >
                <span className="text-cyan-300 font-bold group-hover:text-cyan-200">
                  {topic.name}
                </span>
                <span className="text-[10px] text-slate-500 uppercase">
                  {topic.entity_type}
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-900 text-emerald-400 border border-emerald-500/20">
                  {topic.mention_count} mentions
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Main Grid: All 7 Section 21 Dashboard Components */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Latest News, Research, Tools, Videos */}
        <div className="lg:col-span-2 space-y-8">
          {/* Section 21 Component 1: Latest News */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  Latest Threat Advisories & News
                </h2>
              </div>
              <Link href="/news" className="text-xs font-mono text-cyan-400 hover:underline">
                View all news &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data?.latest_news.slice(0, 4).map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>

          {/* Section 21 Component 3: New Research */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="text-violet-400 font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-white tracking-tight">
                  New Vulnerability & Exploit Research
                </h2>
              </div>
              <Link href="/research" className="text-xs font-mono text-cyan-400 hover:underline">
                View papers &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data?.new_research.slice(0, 4).map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>

          {/* Section 21 Component 5: New Tools */}
          {data?.new_tools && data.new_tools.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-mono text-sm">◈</span>
                  <h2 className="text-lg font-bold text-white tracking-tight">
                    New Security Tools & Frameworks
                  </h2>
                </div>
                <Link href="/tools" className="text-xs font-mono text-cyan-400 hover:underline">
                  Browse arsenal &rarr;
                </Link>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {data.new_tools.slice(0, 4).map((item) => (
                  <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
                ))}
              </div>
            </div>
          )}

          {/* Section 21 Component 6: Latest Videos */}
          {data?.latest_videos && data.latest_videos.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-red-400 font-mono text-sm">◈</span>
                  <h2 className="text-lg font-bold text-white tracking-tight">
                    Latest Security Talks & Video Intel
                  </h2>
                </div>
                <Link href="/videos" className="text-xs font-mono text-cyan-400 hover:underline">
                  Watch all &rarr;
                </Link>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {data.latest_videos.slice(0, 4).map((item) => (
                  <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Critical Vulnerabilities & Threat Intelligence */}
        <div className="space-y-8">
          {/* Section 21 Component 2: Critical Vulnerabilities */}
          <div className="cyber-card rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-red-400 font-mono text-sm">⚠</span>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Critical Vulnerabilities
                </h3>
              </div>
              <Link href="/vulnerabilities" className="text-xs font-mono text-cyan-400 hover:underline">
                Tracker &rarr;
              </Link>
            </div>

            <div className="space-y-3">
              {data?.critical_vulnerabilities.slice(0, 5).map((cve) => (
                <div
                  key={cve.id}
                  onClick={() => setSelectedItem(cve)}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-red-500/40 cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-300">{cve.title}</span>
                    {cve.severity && <SeverityBadge severity={cve.severity} score={cve.cvss_score} />}
                  </div>
                  <p className="text-xs text-slate-300 line-clamp-2 mb-2 leading-relaxed">
                    {cve.summary || cve.description}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>{cve.source}</span>
                    <span className="text-cyan-400 hover:underline">Inspect &rarr;</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 21 Component 7: Threat Intelligence */}
          <div className="cyber-card rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-amber-400 font-mono text-sm">⚡</span>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Threat Intelligence & APTs
                </h3>
              </div>
              <Link href="/intelligence" className="text-xs font-mono text-cyan-400 hover:underline">
                Details &rarr;
              </Link>
            </div>

            <div className="space-y-3">
              {data?.threat_intelligence.slice(0, 4).map((intel) => (
                <div
                  key={intel.id}
                  onClick={() => setSelectedItem(intel)}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-amber-500/40 cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-amber-300 line-clamp-1">
                      {intel.title}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-2 mb-2">
                    {intel.summary || intel.description}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>{intel.source}</span>
                    <span className="text-amber-400 hover:underline">Inspect &rarr;</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Reusable Content Inspection Modal */}
      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
