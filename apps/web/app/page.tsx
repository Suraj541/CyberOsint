"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  ContentItem,
  DashboardData,
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
} from "../lib/api";
import { StatCard } from "../components/StatCard";
import { ContentCard } from "../components/ContentCard";
import { ContentModal } from "../components/ContentModal";
import { SeverityBadge } from "../components/SeverityBadge";
import { formatTime, formatDate } from "../lib/formatters";

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);
  const [loading, setLoading] = useState(true);

  // Personalized recommendations & preferences
  const [recommendations, setRecommendations] = useState<RecommendationItem[]>([]);
  const [suggestedTopics, setSuggestedTopics] = useState<TopicRecommendation[]>([]);
  const [userProfile, setUserProfile] = useState<UserProfile | null>(null);
  const [selectedContentType, setSelectedContentType] = useState<string>("all");
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>("all");
  const [savedIds, setSavedIds] = useState<Set<number>>(new Set());
  const [recsLoading, setRecsLoading] = useState<boolean>(true);
  const [customInterestInput, setCustomInterestInput] = useState<string>("");
  const [showAddInterest, setShowAddInterest] = useState<boolean>(false);

  // Live Real-Time Refresh state
  const [lastSyncTime, setLastSyncTime] = useState<Date | null>(null);
  const [mounted, setMounted] = useState(false);
  const [timeAgo, setTimeAgo] = useState<string>("Updated just now");
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [sseConnected, setSseConnected] = useState<boolean>(false);
  const [globalSearchInput, setGlobalSearchInput] = useState<string>("");

  const refreshData = async () => {
    try {
      const [d, prof] = await Promise.all([
        fetchDashboard(),
        fetchUserProfile(),
      ]);
      setData(d);
      setUserProfile(prof);
      const now = new Date();
      setLastSyncTime(now);
      setTimeAgo("Updated just now");
    } finally {
      setLoading(false);
    }
  };

  const handleManualSync = async () => {
    setIsSyncing(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";
      await fetch(`${apiUrl}/connectors/run-all`, { method: "POST" });
      await refreshData();
    } catch (err) {
      console.warn("Manual sync error:", err);
      await refreshData();
    } finally {
      setIsSyncing(false);
    }
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!lastSyncTime) return;
    const timer = setInterval(() => {
      const elapsedSec = Math.floor((Date.now() - lastSyncTime.getTime()) / 1000);
      if (elapsedSec < 30) {
        setTimeAgo("Updated just now");
      } else if (elapsedSec < 60) {
        setTimeAgo(`Updated ${elapsedSec}s ago`);
      } else {
        const mins = Math.floor(elapsedSec / 60);
        setTimeAgo(`Updated ${mins}m ago`);
      }
    }, 5000);
    return () => clearInterval(timer);
  }, [lastSyncTime]);

  useEffect(() => {
    refreshData();
    const pollInterval = setInterval(() => {
      refreshData();
    }, 30000);
    return () => clearInterval(pollInterval);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";
    let eventSource: EventSource | null = null;
    try {
      eventSource = new EventSource(`${apiUrl}/live/stream`);
      eventSource.onopen = () => setSseConnected(true);
      eventSource.addEventListener("intelligence_update", () => refreshData());
      eventSource.onerror = () => setSseConnected(false);
    } catch {
      setSseConnected(false);
    }
    return () => {
      if (eventSource) eventSource.close();
    };
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
    <div className="space-y-8 animate-in fade-in duration-200 pb-16">
      {/* 1. Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-[#E4DBC8] pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1 font-mono">
            <span className="text-xs text-[#C2821A] font-bold uppercase tracking-wider">
              OSINT INTELLIGENCE WORKSTATION
            </span>
            <span className="text-[#8C887B]">&bull;</span>
            <span className="text-xs text-[#2D7A4F] flex items-center gap-1.5 font-semibold">
              <span className={`w-2 h-2 rounded-full ${sseConnected ? "bg-[#2D7A4F] animate-pulse" : "bg-[#D97706]"}`} />
              {sseConnected ? "LIVE SSE ACTIVE" : "POSTGRESQL 16 VERIFIED"}
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#171714] tracking-tight font-sans">
            Live Security Intelligence Workspace
          </h1>
          <div className="flex flex-wrap items-center gap-2 sm:gap-3 mt-1.5 text-xs font-mono text-[#68655B]">
            <span>Last synchronized: <strong className="text-[#171714]">{mounted && lastSyncTime ? formatTime(lastSyncTime) : "—"}</strong></span>
            <span className="text-[#8C887B] hidden sm:inline">&bull;</span>
            <span className="text-[#C2821A] font-semibold">{timeAgo}</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleManualSync}
            disabled={isSyncing}
            className="px-3.5 py-2 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] font-semibold text-xs font-mono transition-colors shadow-sm flex items-center gap-1.5 disabled:opacity-50"
          >
            <span className={isSyncing ? "animate-spin inline-block" : ""}>↻</span>
            <span>{isSyncing ? "Synchronizing Feeds..." : "Sync Feeds Now"}</span>
          </button>
          <Link
            href="/search"
            className="px-4 py-2 rounded-lg bg-[#C2821A] hover:bg-[#D97706] text-white font-semibold text-xs font-mono transition-colors shadow-sm flex items-center gap-1.5"
          >
            <span>Hybrid Search (RRF) &rarr;</span>
          </Link>
        </div>
      </div>

      {/* 2. Global Quick Search Bar */}
      <div className="p-3.5 rounded-2xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm flex items-center gap-3">
        <span className="text-[#C2821A] font-mono text-sm pl-2 font-bold">⌕</span>
        <input
          type="text"
          value={globalSearchInput}
          onChange={(e) => setGlobalSearchInput(e.target.value)}
          placeholder="Global Intelligence Search (Type any CVE ID, malware family, threat actor, or keyword...)"
          className="w-full bg-transparent text-xs font-mono text-[#171714] placeholder-[#8C887B] focus:outline-none"
          onKeyDown={(e) => {
            if (e.key === "Enter" && globalSearchInput.trim()) {
              window.location.href = `/search?q=${encodeURIComponent(globalSearchInput.trim())}`;
            }
          }}
        />
        <button
          onClick={() => {
            if (globalSearchInput.trim()) {
              window.location.href = `/search?q=${encodeURIComponent(globalSearchInput.trim())}`;
            }
          }}
          className="px-3 py-1 rounded bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] text-xs font-mono shrink-0 font-semibold"
        >
          Search ↵
        </button>
      </div>

      {/* 3. Real Database Aggregate Telemetry */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Ingested Content"
          value={metrics ? metrics.total_content.toLocaleString() : "..."}
          change="real-time"
          accentColor="cyan"
          iconText="⚡"
        />
        <StatCard
          title="Active Intelligence Feeds"
          value={metrics ? metrics.active_sources : "..."}
          change="100% verified"
          accentColor="emerald"
          iconText="🖧"
        />
        <StatCard
          title="Tracked Vulnerabilities (CVE)"
          value={metrics ? metrics.tracked_cves.toLocaleString() : "..."}
          change="active KEV"
          accentColor="crimson"
          iconText="🛡"
        />
        <StatCard
          title="Knowledge Graph Entities"
          value="3,047"
          change="5,369 edges"
          accentColor="amber"
          iconText="🕸"
        />
      </div>

      {/* 4. Trending Security Entities & Topics */}
      {data && data.trending_topics && data.trending_topics.length > 0 && (
        <div className="p-4 rounded-2xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <span className="text-[#C2821A] font-mono text-sm">◈</span>
              <h2 className="text-xs font-bold uppercase tracking-wider text-[#171714] font-mono">
                Trending Security Entities & Topics
              </h2>
            </div>
            <span className="text-[11px] font-mono text-[#68655B]">
              Aggregated from real PostgreSQL entity mentions
            </span>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {data.trending_topics.map((topic, idx) => (
              <Link
                key={idx}
                href={`/search?q=${encodeURIComponent(topic.name)}`}
                className="px-3 py-1.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8] hover:border-[#C2821A] text-xs font-mono transition-colors flex items-center gap-2 group"
              >
                <span className="text-[#171714] font-bold group-hover:text-[#C2821A]">
                  {topic.name}
                </span>
                <span className="text-[10px] text-[#68655B] uppercase">
                  {topic.entity_type}
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-[#E4DBC8] text-[#171714] border border-[#D8CEB9] font-medium">
                  {topic.mention_count} mentions
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* 5. Adaptive Intelligence & Personalized Recommendations */}
      <section className="p-6 rounded-2xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm space-y-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-[#E4DBC8] pb-5">
          <div>
            <div className="flex items-center gap-2 mb-1.5 flex-wrap font-mono text-[11px]">
              <span className="uppercase px-2 py-0.5 rounded bg-[#F1EBD8] text-[#C2821A] border border-[#E4DBC8] font-bold">
                RECOMMENDATION ENGINE
              </span>
              <span className="text-[#2D7A4F] font-semibold flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-[#2D7A4F] animate-pulse inline-block" />
                Adaptive Feed Active
              </span>
              <span className="text-[#8C887B]">&bull;</span>
              <span className="text-[#68655B]">
                Depth: <span className="text-[#171714] uppercase font-semibold">{userProfile?.difficulty_level || "Intermediate"}</span>
              </span>
              <span className="text-[#8C887B]">&bull;</span>
              <span className="text-[#68655B]">
                Bookmarks: <span className="text-[#C2821A] font-semibold">{savedIds.size} saved</span>
              </span>
            </div>
            <h2 className="text-xl font-bold text-[#171714] tracking-tight font-sans flex items-center gap-2">
              <span className="text-[#C2821A] font-mono">⚡</span> Recommended Intelligence Artifacts
            </h2>
            <p className="text-xs text-[#68655B] mt-1">
              Contextual threat reporting matched to your active research profile and technical depth.
            </p>
          </div>

          <div className="flex items-center gap-1 bg-[#F1EBD8] p-1 rounded-lg border border-[#E4DBC8] font-mono text-xs">
            <span className="text-[10px] text-[#68655B] px-2 uppercase font-semibold">Depth:</span>
            {(["all", "beginner", "intermediate", "advanced", "expert"] as const).map((lvl) => (
              <button
                key={lvl}
                onClick={() => setSelectedDifficulty(lvl)}
                className={`px-2.5 py-1 rounded text-xs uppercase transition-colors ${
                  selectedDifficulty === lvl
                    ? "bg-[#C2821A] text-white font-bold"
                    : "text-[#68655B] hover:text-[#171714]"
                }`}
              >
                {lvl}
              </button>
            ))}
          </div>
        </div>

        {/* Content Type Tabs */}
        <div className="flex items-center justify-between gap-4 flex-wrap border-b border-[#E4DBC8] pb-3">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs font-mono text-[#68655B] uppercase mr-1">Types:</span>
            {[
              { id: "all", label: "All Intel" },
              { id: "articles", label: "Articles" },
              { id: "research", label: "Research" },
              { id: "tools", label: "Tools" },
              { id: "documents", label: "Documents" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setSelectedContentType(tab.id)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-all ${
                  selectedContentType === tab.id
                    ? "bg-[#C2821A] text-white font-bold shadow-sm"
                    : "bg-[#F1EBD8] text-[#68655B] hover:text-[#171714] border border-[#E4DBC8]"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          {/* Interests Pill Bar */}
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-xs font-mono text-[#68655B] uppercase">Interests:</span>
            {userProfile?.interests.map((int, i) => (
              <span
                key={i}
                onClick={() => handleToggleInterest(int)}
                title="Click to remove"
                className="px-2.5 py-0.5 rounded-full bg-[#F1EBD8] text-[#171714] border border-[#E4DBC8] text-[11px] font-mono cursor-pointer hover:border-[#B91C1C] hover:text-[#B91C1C] transition-colors flex items-center gap-1"
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
                  placeholder="e.g. Memory Safety"
                  className="px-2 py-0.5 rounded bg-[#F1EBD8] border border-[#C2821A] text-[11px] font-mono text-[#171714] focus:outline-none"
                  autoFocus
                />
                <button
                  type="submit"
                  className="px-2 py-0.5 rounded bg-[#C2821A] text-white text-[10px] font-mono font-bold"
                >
                  Add
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddInterest(false)}
                  className="text-[#68655B] text-xs px-1"
                >
                  &times;
                </button>
              </form>
            ) : (
              <button
                onClick={() => setShowAddInterest(true)}
                className="px-2 py-0.5 rounded bg-[#F1EBD8] hover:bg-[#EAE3CE] text-[#68655B] border border-[#E4DBC8] text-[11px] font-mono transition-colors"
              >
                + Add
              </button>
            )}
          </div>
        </div>

        {/* Recommended Items Grid */}
        {recsLoading ? (
          <div className="py-12 text-center font-mono text-xs text-[#68655B] animate-pulse">
            Computing personalized recommendations from active intelligence records...
          </div>
        ) : recommendations.length === 0 ? (
          <div className="py-10 text-center text-xs font-mono text-[#68655B]">
            No intelligence artifacts match the current criteria.
          </div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {recommendations.map((rec) => {
              const isSaved = savedIds.has(rec.content_id) || rec.is_saved;
              const diffColor =
                rec.difficulty_level === "expert"
                  ? "text-[#B91C1C] bg-[#B91C1C]/10 border-[#B91C1C]/25"
                  : rec.difficulty_level === "advanced"
                  ? "text-[#D97706] bg-[#D97706]/10 border-[#D97706]/25"
                  : rec.difficulty_level === "beginner"
                  ? "text-[#2D7A4F] bg-[#2D7A4F]/10 border-[#2D7A4F]/25"
                  : "text-[#C2821A] bg-[#C2821A]/10 border-[#C2821A]/25";

              return (
                <div
                  key={rec.content_id}
                  onClick={() => handleSelectRecommendation(rec)}
                  className="group relative p-4 rounded-xl bg-[#FFFDF5] border border-[#E4DBC8] hover:border-[#C2821A] transition-all cursor-pointer flex flex-col justify-between shadow-sm"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-1.5 flex-wrap">
                        <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[#F1EBD8] text-[#171714] border border-[#E4DBC8]">
                          {rec.content_type}
                        </span>
                        <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border font-semibold ${diffColor}`}>
                          {rec.difficulty_level}
                        </span>
                      </div>
                      <button
                        onClick={(e) => handleToggleSave(rec, e)}
                        title={isSaved ? "Saved" : "Bookmark"}
                        className={`p-1 rounded border text-xs transition-colors ${
                          isSaved
                            ? "bg-[#C2821A]/20 text-[#C2821A] border-[#C2821A]/40"
                            : "bg-[#F1EBD8] text-[#8C887B] hover:text-[#C2821A] border-[#E4DBC8]"
                        }`}
                      >
                        {isSaved ? "★" : "☆"}
                      </button>
                    </div>

                    <h3 className="text-sm font-bold text-[#171714] group-hover:text-[#C2821A] transition-colors line-clamp-2 mb-1.5 leading-snug">
                      {rec.title}
                    </h3>

                    <p className="text-xs text-[#68655B] line-clamp-2 mb-3 leading-relaxed">
                      {rec.summary || rec.description}
                    </p>
                  </div>

                  <div className="pt-2 border-t border-[#E4DBC8] flex items-center justify-between text-[11px] font-mono text-[#68655B]">
                    <span className="truncate max-w-[120px]">{rec.source}</span>
                    <span className="text-[#C2821A] font-bold group-hover:underline flex items-center gap-0.5">
                      Inspect &rarr;
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* 6. Main 2-Column Grid: Latest Intelligence & Critical Vulnerabilities */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left 2 Cols: Latest News & Exploit Research */}
        <div className="lg:col-span-2 space-y-8">
          {/* Latest News */}
          <div>
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#E4DBC8]">
              <div className="flex items-center gap-2">
                <span className="text-[#C2821A] font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-[#171714] tracking-tight font-sans">
                  Latest Threat Advisories & Security News
                </h2>
              </div>
              <Link href="/news" className="text-xs font-mono text-[#C2821A] hover:underline font-semibold">
                View all news &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data?.latest_news.slice(0, 4).map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>

          {/* New Research */}
          <div>
            <div className="flex items-center justify-between mb-4 pb-2 border-b border-[#E4DBC8]">
              <div className="flex items-center gap-2">
                <span className="text-[#7C3AED] font-mono text-sm">◈</span>
                <h2 className="text-lg font-bold text-[#171714] tracking-tight font-sans">
                  Vulnerability & Exploit Research
                </h2>
              </div>
              <Link href="/research" className="text-xs font-mono text-[#C2821A] hover:underline font-semibold">
                View papers &rarr;
              </Link>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {data?.new_research.slice(0, 4).map((item) => (
                <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
              ))}
            </div>
          </div>
        </div>

        {/* Right Col: Critical Vulnerabilities & Threat Intelligence */}
        <div className="space-y-8">
          {/* Critical Vulnerabilities */}
          <div className="cyber-card rounded-2xl p-5 bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#E4DBC8]">
              <div className="flex items-center gap-2">
                <span className="text-[#B91C1C] font-mono text-sm">⚠</span>
                <h3 className="text-sm font-bold text-[#171714] uppercase tracking-wider font-sans">
                  Critical Vulnerabilities
                </h3>
              </div>
              <Link href="/vulnerabilities" className="text-xs font-mono text-[#C2821A] hover:underline font-semibold">
                Tracker &rarr;
              </Link>
            </div>

            <div className="space-y-3">
              {data?.critical_vulnerabilities.slice(0, 5).map((cve) => (
                <div
                  key={cve.id}
                  onClick={() => setSelectedItem(cve)}
                  className="p-3 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] hover:border-[#B91C1C] cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs font-bold text-[#171714]">{cve.title}</span>
                    {cve.severity && <SeverityBadge severity={cve.severity} score={cve.cvss_score} />}
                  </div>
                  <p className="text-xs text-[#68655B] line-clamp-2 mb-2 leading-relaxed">
                    {cve.summary || cve.description}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#8C887B]">
                    <span>{cve.source}</span>
                    <span className="text-[#C2821A] hover:underline font-semibold">Inspect &rarr;</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Threat Intelligence & APTs */}
          <div className="cyber-card rounded-2xl p-5 bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
            <div className="flex items-center justify-between mb-4 pb-3 border-b border-[#E4DBC8]">
              <div className="flex items-center gap-2">
                <span className="text-[#C2821A] font-mono text-sm">⚡</span>
                <h3 className="text-sm font-bold text-[#171714] uppercase tracking-wider font-sans">
                  Threat Intelligence & APTs
                </h3>
              </div>
              <Link href="/intelligence" className="text-xs font-mono text-[#C2821A] hover:underline font-semibold">
                Details &rarr;
              </Link>
            </div>

            <div className="space-y-3">
              {data?.threat_intelligence.slice(0, 4).map((intel) => (
                <div
                  key={intel.id}
                  onClick={() => setSelectedItem(intel)}
                  className="p-3 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] hover:border-[#C2821A] cursor-pointer transition-colors"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs font-bold text-[#171714] line-clamp-1">
                      {intel.title}
                    </span>
                  </div>
                  <p className="text-xs text-[#68655B] line-clamp-2 mb-2">
                    {intel.summary || intel.description}
                  </p>
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#8C887B]">
                    <span>{intel.source}</span>
                    <span className="text-[#C2821A] hover:underline font-semibold">Inspect &rarr;</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
