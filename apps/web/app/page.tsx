"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ContentItem,
  DashboardData,
  TrendingTopic,
  RecommendationItem,
  TopicRecommendation,
  UserProfile,
} from "../lib/types";
import {
  fetchDashboard,
  fetchRecommendations,
  fetchUserProfile,
  recordInteraction,
  updateUserProfile,
  fetchRelatedTopics,
} from "../lib/api";
import { StatCard } from "../components/StatCard";
import { ContentCard } from "../components/ContentCard";
import { ContentModal } from "../components/ContentModal";
import { SeverityBadge } from "../components/SeverityBadge";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [loading, setLoading] = useState(true);

  // Section 31 (Step 30): Personalized Recommendations State
  const [recommendations, setRecommendations] = useState<RecommendationItem[]>([]);
  const [suggestedTopics, setSuggestedTopics] = useState<TopicRecommendation[]>([]);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [selectedContentType, setSelectedContentType] = useState<string>("all");
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>("all");
  const [savedIds, setSavedIds] = useState<Set<number>>(new Set());
  const [recsLoading, setRecsLoading] = useState<boolean>(true);
  const [customInterestInput, setCustomInterestInput] = useState<string>("");
  const [showAddInterest, setShowAddInterest] = useState<boolean>(false);

  useEffect(() => {
    async function loadData() {
      try {
        const [d, prof] = await Promise.all([
          fetchDashboard(),
          fetchUserProfile(),
        ]);
        setData(d);
        setUserProfile(prof);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  useEffect(() => {
    async function loadRecs() {
      setRecsLoading(true);
      try {
        const feed = await fetchRecommendations({
          contentType: selectedContentType,
          difficulty: selectedDifficulty === "all" ? undefined : selectedDifficulty,
          limit: 8,
        });
        setRecommendations(feed.items);
        setSuggestedTopics(feed.suggested_topics);
      } finally {
        setRecsLoading(false);
      }
    }
    loadRecs();
  }, [selectedContentType, selectedDifficulty]);

  const handleToggleSave = async (rec: RecommendationItem, e: React.MouseEvent) => {
    e.stopPropagation();
    const isSaved = savedIds.has(rec.content_id);
    const nextSaved = new Set(savedIds);
    if (isSaved) {
      nextSaved.delete(rec.content_id);
      setSavedIds(nextSaved);
      await recordInteraction("unsave", rec.content_id);
    } else {
      nextSaved.add(rec.content_id);
      setSavedIds(nextSaved);
      await recordInteraction("save", rec.content_id);
    }
  };

  const handleSelectRecommendation = (rec: RecommendationItem) => {
    recordInteraction("view", rec.content_id, undefined, { source: "dashboard_recommendation" });
    const contentItem: ContentItem = {
      id: rec.content_id,
      title: rec.title,
      description: rec.description,
      summary: rec.summary,
      canonical_url: rec.canonical_url,
      content_type: (rec.content_type as any) || "article",
      source: rec.source,
      category: rec.category || "cloud_security",
      author: rec.author,
      published_at: rec.published_at,
      tags: rec.tags,
      entities: rec.entities?.map((e) => ({ entity_type: "entity", name: e })),
    };
    setSelectedItem(contentItem);
  };

  const handleToggleInterest = async (interest: string) => {
    if (!userProfile) return;
    const current = userProfile.interests || [];
    const next = current.includes(interest)
      ? current.filter((i) => i !== interest)
      : [...current, interest];
    const updated = await updateUserProfile(next);
    setUserProfile(updated);
    // Refresh recommendations
    const feed = await fetchRecommendations({
      contentType: selectedContentType,
      difficulty: selectedDifficulty === "all" ? undefined : selectedDifficulty,
      limit: 8,
    });
    setRecommendations(feed.items);
    setSuggestedTopics(feed.suggested_topics);
  };

  const handleAddCustomInterest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!customInterestInput.trim() || !userProfile) return;
    const clean = customInterestInput.trim();
    if (!userProfile.interests.includes(clean)) {
      const next = [...userProfile.interests, clean];
      const updated = await updateUserProfile(next);
      setUserProfile(updated);
      setCustomInterestInput("");
      setShowAddInterest(false);
      const feed = await fetchRecommendations({
        contentType: selectedContentType,
        difficulty: selectedDifficulty === "all" ? undefined : selectedDifficulty,
        limit: 8,
      });
      setRecommendations(feed.items);
      setSuggestedTopics(feed.suggested_topics);
    }
  };

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

      {/* Section 31: Adaptive Intelligence & Personalized Recommendations */}
      <section className="p-6 rounded-2xl cyber-card border border-cyan-500/20 bg-gradient-to-b from-slate-900/90 via-slate-950/80 to-slate-950/90 space-y-6 shadow-xl relative overflow-hidden">
        {/* Glow accent */}
        <div className="absolute top-0 right-0 w-96 h-48 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

        {/* Section Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold">
                SECTION 31 INTELLIGENCE
              </span>
              <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping inline-block" />
                Adaptive Recommendation Engine
              </span>
              <span className="text-slate-600">&bull;</span>
              <span className="text-[11px] font-mono text-slate-400">
                Depth: <span className="text-amber-300 uppercase font-semibold">{userProfile?.difficulty_level || "Intermediate"}</span>
              </span>
              <span className="text-slate-600">&bull;</span>
              <span className="text-[11px] font-mono text-slate-400">
                Bookmarks: <span className="text-cyan-300 font-semibold">{savedIds.size} saved</span>
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-cyan-400 font-mono">⚡</span> Recommended For You
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Contextual feed matched to your interests, saved bookmarks, search history, and technical difficulty level.
            </p>
          </div>

          {/* Difficulty Controls */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1 bg-slate-950/80 p-1 rounded-lg border border-slate-800">
              <span className="text-[10px] font-mono text-slate-500 px-2 uppercase">Depth:</span>
              {(["all", "beginner", "intermediate", "advanced", "expert"] as const).map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setSelectedDifficulty(lvl)}
                  className={`px-2.5 py-1 rounded text-xs font-mono uppercase transition-colors ${
                    selectedDifficulty === lvl
                      ? "bg-cyan-500 text-slate-950 font-bold"
                      : "text-slate-400 hover:text-white"
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Content Type Filter Tabs (Section 31 outputs: Articles, Videos, Research, Tools, Courses, Documents) */}
        <div className="flex items-center justify-between gap-4 flex-wrap border-b border-slate-800/60 pb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-slate-500 uppercase mr-1">Types:</span>
            {[
              { id: "all", label: "All Intel" },
              { id: "articles", label: "Articles" },
              { id: "videos", label: "Videos" },
              { id: "research", label: "Research" },
              { id: "tools", label: "Tools" },
              { id: "courses", label: "Courses" },
              { id: "documents", label: "Documents" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedContentType(tab.id)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                  selectedContentType === tab.id
                    ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/50 font-semibold"
                    : "bg-slate-950/60 text-slate-400 hover:text-slate-200 border border-slate-800"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Interests Pill Bar */}
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-slate-500 uppercase">Interests:</span>
            {userProfile?.interests.map((int, i) => (
              <span
                key={i}
                onClick={() => handleToggleInterest(int)}
                title="Click to remove"
                className="px-2.5 py-0.5 rounded-full bg-cyan-950/40 text-cyan-300 border border-cyan-500/30 text-[11px] font-mono cursor-pointer hover:border-red-500/40 hover:text-red-300 transition-colors flex items-center gap-1"
              >
                #{int} &times;
              </span>
            ))}
            {showAddInterest ? (
              <form onSubmit={handleAddCustomInterest} className="inline-flex items-center gap-1">
                <input
                  type="text"
                  value={customInterestInput}
                  onChange={(e) => setCustomInterestInput(e.target.value)}
                  placeholder="e.g. Docker Security"
                  className="px-2 py-0.5 rounded bg-slate-900 border border-cyan-500/50 text-[11px] font-mono text-white focus:outline-none"
                  autoFocus
                />
                <button
                  type="submit"
                  className="px-2 py-0.5 rounded bg-cyan-500 text-slate-950 text-[10px] font-mono font-bold"
                >
                  Add
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddInterest(false)}
                  className="text-slate-500 text-xs px-1"
                >
                  &times;
                </button>
              </form>
            ) : (
              <button
                onClick={() => setShowAddInterest(true)}
                className="px-2 py-0.5 rounded bg-slate-900 hover:bg-slate-800 text-slate-400 border border-slate-800 text-[11px] font-mono transition-colors"
              >
                + Add
              </button>
            )}
          </div>
        </div>

        {/* Section 31 Canonical Example Topic Strip: Kubernetes Security -> Container, Docker, Cloud, Threat Detection, Runtime */}
        {suggestedTopics && suggestedTopics.length > 0 && (
          <div className="p-3 rounded-xl bg-slate-950/70 border border-cyan-500/20 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-mono text-xs">◈</span>
              <span className="text-xs font-mono text-slate-400">
                Correlated Topics ({suggestedTopics[0]?.related_from || "Kubernetes Security"}):
              </span>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {suggestedTopics.map((top, idx) => (
                <button
                  key={idx}
                  onClick={() => handleToggleInterest(top.topic)}
                  className="px-2.5 py-1 rounded bg-slate-900/90 text-cyan-300 hover:bg-cyan-500/20 hover:text-cyan-200 border border-slate-800 hover:border-cyan-500/40 text-xs font-mono transition-colors flex items-center gap-1"
                >
                  <span>{top.topic}</span>
                  <span className="text-[10px] text-cyan-500/70">{(top.score * 100).toFixed(0)}%</span>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Recommended Items Grid */}
        {recsLoading ? (
          <div className="py-12 text-center font-mono text-xs text-slate-500 animate-pulse">
            Computing multi-factor personalized threat intelligence...
          </div>
        ) : recommendations.length === 0 ? (
          <div className="py-10 text-center text-xs font-mono text-slate-500">
            No intelligence artifacts matched current filters.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {recommendations.map((rec) => {
              const isSaved = savedIds.has(rec.content_id) || rec.is_saved;
              const diffColor =
                rec.difficulty_level === "expert"
                  ? "text-rose-400 bg-rose-500/10 border-rose-500/30"
                  : rec.difficulty_level === "advanced"
                  ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                  : rec.difficulty_level === "beginner"
                  ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                  : "text-cyan-400 bg-cyan-500/10 border-cyan-500/30";

              return (
                <div
                  key={rec.content_id}
                  onClick={() => handleSelectRecommendation(rec)}
                  className="group relative p-4 rounded-xl bg-slate-950/70 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer flex flex-col justify-between hover:shadow-lg hover:shadow-cyan-500/5"
                >
                  <div>
                    {/* Header: Content Type, Difficulty & Bookmark */}
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                          {rec.content_type}
                        </span>
                        <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${diffColor}`}>
                          {rec.difficulty_level}
                        </span>
                      </div>
                      <button
                        onClick={(e) => handleToggleSave(rec, e)}
                        title={isSaved ? "Saved (click to unsave)" : "Bookmark for later"}
                        className={`p-1.5 rounded-lg border text-xs transition-colors ${
                          isSaved
                            ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                            : "bg-slate-900 text-slate-500 hover:text-amber-300 border-slate-800 hover:border-amber-500/30"
                        }`}
                      >
                        {isSaved ? "★" : "☆"}
                      </button>
                    </div>

                    {/* Title */}
                    <h3 className="text-sm font-bold text-white group-hover:text-cyan-300 transition-colors line-clamp-2 mb-2 leading-snug">
                      {rec.title}
                    </h3>

                    {/* Summary */}
                    <p className="text-xs text-slate-400 line-clamp-2 mb-3 leading-relaxed">
                      {rec.summary || rec.description}
                    </p>

                    {/* Match Justification Chips */}
                    <div className="flex flex-wrap gap-1 mb-3">
                      {rec.match_reasons.slice(0, 2).map((reason, ridx) => (
                        <span
                          key={ridx}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/30 text-cyan-400/90 border border-cyan-500/20"
                        >
                          {reason}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Footer */}
                  <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-500">
                    <span className="truncate max-w-[130px]">{rec.source}</span>
                    <span className="text-cyan-400 group-hover:underline flex items-center gap-0.5">
                      Inspect &rarr;
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

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
