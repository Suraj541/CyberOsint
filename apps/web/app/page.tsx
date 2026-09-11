"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ContentItem,
  DashboardMetrics,
  ThreatIntelligenceItem,
  VulnerabilityItem,
} from "../lib/types";
import {
  fetchDashboardMetrics,
  fetchRecentContent,
  fetchThreatIntelligence,
  fetchVulnerabilities,
} from "../lib/api";
import { StatCard } from "../components/StatCard";
import { ContentCard } from "../components/ContentCard";
import { ContentModal } from "../components/ContentModal";
import { SeverityBadge } from "../components/SeverityBadge";

export default function DashboardPage() {
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);
  const [newsItems, setNewsItems] = useState<ContentItem[]>([]);
  const [researchItems, setResearchItems] = useState<ContentItem[]>([]);
  const [toolItems, setToolItems] = useState<ContentItem[]>([]);
  const [videoItems, setVideoItems] = useState<ContentItem[]>([]);
  const [cveList, setCveList] = useState<VulnerabilityItem[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligenceItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [m, allContent, cves, intel] = await Promise.all([
          fetchDashboardMetrics(),
          fetchRecentContent(),
          fetchVulnerabilities(),
          fetchThreatIntelligence(),
        ]);
        setMetrics(m);
        setCveList(cves.slice(0, 4));
        setThreatIntel(intel.slice(0, 3));

        // Segment content items into Section 21 Dashboard components
        setNewsItems(allContent.filter((c) => c.content_type === "article" || c.content_type === "advisory").slice(0, 4));
        setResearchItems(allContent.filter((c) => c.content_type === "paper").slice(0, 2));
        setToolItems(allContent.filter((c) => c.content_type === "tool").slice(0, 2));
        setVideoItems(allContent.filter((c) => c.content_type === "video").slice(0, 2));
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
              OPERATIONAL DASHBOARD
            </span>
            <span className="text-slate-600">&bull;</span>
            <span className="text-xs font-mono text-slate-400">REAL-TIME FEEDS</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Threat Intelligence Command Center
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/search"
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono transition-colors shadow-sm flex items-center gap-1.5"
          >
            <span>Launch Hybrid Search &rarr;</span>
          </Link>
        </div>
      </div>

      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Aggregated Content"
          value={metrics ? metrics.total_content.toLocaleString() : "..."}
          change="340 today"
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
          change="18 KEV active"
          accentColor="crimson"
          iconText="🛡"
        />
        <StatCard
          title="Critical Threat Alerts"
          value={metrics ? metrics.threat_advisories : "..."}
          change="5 new zero-days"
          accentColor="amber"
          iconText="⚠"
        />
      </div>

      {/* Main Grid: Section 21 Dashboard Components */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Latest News & Research */}
        <div className="lg:col-span-2 space-y-8">
          {/* Section 21: Latest News */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-white tracking-tight">Latest Threat Advisories & News</h2>
              </div>
              <Link href="/news" className="text-xs font-mono text-cyan-400 hover:underline">
                View all news &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {newsItems.map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>

          {/* Section 21: New Research & Tooling */}
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="text-violet-400 font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-white tracking-tight">Exploit Research & New Tools</h2>
              </div>
              <Link href="/research" className="text-xs font-mono text-cyan-400 hover:underline">
                Explore papers &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {researchItems.concat(toolItems).map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>

          {/* Section 21: Latest Videos */}
          {videoItems.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 font-mono text-sm">◈</span>
                  <h2 className="text-lg font-bold text-white tracking-tight">Security Conferences & Video Intel</h2>
                </div>
                <Link href="/videos" className="text-xs font-mono text-cyan-400 hover:underline">
                  Watch all &rarr;
                </Link>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {videoItems.map((item) => (
                  <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Critical Vulnerabilities & Threat Actors */}
        <div className="space-y-8">
          {/* Section 21: Critical Vulnerabilities */}
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
              {cveList.map((cve) => (
                <div
                  key={cve.cve_id}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-cyan-300">{cve.cve_id}</span>
                    <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
                  </div>
                  <p className="text-xs text-slate-300 line-clamp-2 mb-2 leading-relaxed">
                    {cve.description}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span>{cve.vendor || "Enterprise"}</span>
                    {cve.is_exploited && (
                      <span className="text-red-400 font-semibold">CISA KEV EXPLOITED</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 21: Threat Intelligence & Actors */}
          <div className="cyber-card rounded-xl p-5 border border-slate-800">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-amber-400 font-mono text-sm">⚡</span>
                <h3 className="text-sm font-bold text-white uppercase tracking-wider">
                  Active Threat Actors
                </h3>
              </div>
              <Link href="/intelligence" className="text-xs font-mono text-cyan-400 hover:underline">
                Details &rarr;
              </Link>
            </div>

            <div className="space-y-3">
              {threatIntel.map((actor) => (
                <div
                  key={actor.id}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-amber-300">
                      {actor.threat_actor}
                    </span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                      {(actor.confidence * 100).toFixed(0)}% Conf.
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-2 mb-2">
                    {actor.summary}
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {actor.mitre_techniques?.slice(0, 2).map((t, idx) => (
                      <span
                        key={idx}
                        className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Content Inspection Modal */}
      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
