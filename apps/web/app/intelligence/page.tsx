"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  fetchCampaigns,
  fetchCorrelationClusters,
  fetchIncidentTimelines,
  fetchIntelligenceOverview,
  fetchLearningPaths,
  fetchMalwareFamilies,
  fetchThreatActors,
  getMitreGroups,
  getMitreMatrix,
  getMitreSoftware,
  investigateWithAssistant,
} from "../../lib/api";
import {
  AttackGroup,
  AttackMatrixColumn,
  AttackMatrixResponse,
  AttackSoftware,
  AttackTechnique,
  Campaign,
  CorrelationCluster,
  IncidentTimeline,
  IntelligenceOverview,
  LearningPath,
  MalwareFamily,
  ResearchAssistantDossier,
  ThreatActor,
} from "../../lib/types";
import { formatDateTime } from "../../lib/formatters";

type IntelligenceTab =
  | "overview"
  | "actors"
  | "malware"
  | "campaigns"
  | "timelines"
  | "correlations"
  | "academy"
  | "assistant"
  | "mitre";

export default function IntelligencePage() {
  const [activeTab, setActiveTab] = useState<IntelligenceTab>("overview");
  const [loading, setLoading] = useState<boolean>(true);

  // Core Section 48 State
  const [overview, setOverview] = useState<IntelligenceOverview | null>(null);
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [malware, setMalware] = useState<MalwareFamily[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [timelines, setTimelines] = useState<IncidentTimeline[]>([]);
  const [correlations, setCorrelations] = useState<CorrelationCluster[]>([]);
  const [learningPaths, setLearningPaths] = useState<LearningPath[]>([]);

  // Selected Detail Modals / Drawers
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null);
  const [selectedMalware, setSelectedMalware] = useState<MalwareFamily | null>(null);
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | null>(null);
  const [selectedTimeline, setSelectedTimeline] = useState<IncidentTimeline | null>(null);
  const [selectedCluster, setSelectedCluster] = useState<CorrelationCluster | null>(null);
  const [selectedPath, setSelectedPath] = useState<LearningPath | null>(null);

  // Filter States
  const [actorCountry, setActorCountry] = useState<string>("all");
  const [actorStatus, setActorStatus] = useState<string>("all");
  const [actorSearch, setActorSearch] = useState<string>("");

  const [malwareType, setMalwareType] = useState<string>("all");
  const [malwarePlatform, setMalwarePlatform] = useState<string>("all");
  const [malwareSearch, setMalwareSearch] = useState<string>("");

  const [campaignStatus, setCampaignStatus] = useState<string>("all");
  const [campaignSearch, setCampaignSearch] = useState<string>("");

  const [correlationSearch, setCorrelationSearch] = useState<string>("");

  const [pathDifficulty, setPathDifficulty] = useState<string>("all");
  const [pathRole, setPathRole] = useState<string>("all");

  // AI Research Assistant State
  const [assistantQuery, setAssistantQuery] = useState<string>("");
  const [isInvestigating, setIsInvestigating] = useState<boolean>(false);
  const [assistantDossier, setAssistantDossier] = useState<ResearchAssistantDossier | null>(null);

  // MITRE ATT&CK Matrix State (Retained for backwards compatibility)
  const [matrixData, setMatrixData] = useState<AttackMatrixResponse | null>(null);
  const [groups, setGroups] = useState<AttackGroup[]>([]);
  const [software, setSoftware] = useState<AttackSoftware[]>([]);
  const [selectedTacticId, setSelectedTacticId] = useState<string>("all");
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const [expandedTechniques, setExpandedTechniques] = useState<Record<string, boolean>>({});
  const [mitreSearch, setMitreSearch] = useState<string>("");

  // Load all initial Section 48 datasets
  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [
          ovRes,
          actRes,
          malRes,
          campRes,
          timeRes,
          corrRes,
          learnRes,
          mRes,
          gRes,
          sRes,
        ] = await Promise.all([
          fetchIntelligenceOverview(),
          fetchThreatActors(),
          fetchMalwareFamilies(),
          fetchCampaigns(),
          fetchIncidentTimelines(),
          fetchCorrelationClusters(),
          fetchLearningPaths(),
          getMitreMatrix(),
          getMitreGroups(),
          getMitreSoftware(),
        ]);
        setOverview(ovRes);
        setActors(actRes);
        setMalware(malRes);
        setCampaigns(campRes);
        setTimelines(timeRes);
        setCorrelations(corrRes);
        setLearningPaths(learnRes);
        setMatrixData(mRes);
        setGroups(gRes);
        setSoftware(sRes);

        // Pre-select first items for drawer previews
        if (actRes.length > 0) setSelectedActor(actRes[0]);
        if (malRes.length > 0) setSelectedMalware(malRes[0]);
        if (timeRes.length > 0) setSelectedTimeline(timeRes[0]);
        if (corrRes.length > 0) setSelectedCluster(corrRes[0]);
        if (learnRes.length > 0) setSelectedPath(learnRes[0]);
      } catch (err) {
        console.error("Failed to load intelligence data:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Filtered Threat Actors
  const filteredActors = useMemo(() => {
    return actors.filter((a) => {
      const matchCountry = actorCountry === "all" || a.country?.toLowerCase() === actorCountry.toLowerCase();
      const matchStatus = actorStatus === "all" || a.status === actorStatus;
      const q = actorSearch.toLowerCase().trim();
      const matchSearch =
        !q ||
        a.name.toLowerCase().includes(q) ||
        a.aliases.some((al) => al.toLowerCase().includes(q)) ||
        a.associated_malware.some((m) => m.toLowerCase().includes(q)) ||
        a.associated_cves.some((c) => c.toLowerCase().includes(q));
      return matchCountry && matchStatus && matchSearch;
    });
  }, [actors, actorCountry, actorStatus, actorSearch]);

  // Filtered Malware Families
  const filteredMalware = useMemo(() => {
    return malware.filter((m) => {
      const matchType = malwareType === "all" || m.malware_type.toLowerCase() === malwareType.toLowerCase();
      const matchPlat = malwarePlatform === "all" || m.target_platforms.some((p) => p.toLowerCase().includes(malwarePlatform.toLowerCase()));
      const q = malwareSearch.toLowerCase().trim();
      const matchSearch =
        !q ||
        m.name.toLowerCase().includes(q) ||
        m.aliases.some((al) => al.toLowerCase().includes(q)) ||
        (m.description && m.description.toLowerCase().includes(q));
      return matchType && matchPlat && matchSearch;
    });
  }, [malware, malwareType, malwarePlatform, malwareSearch]);

  // Filtered Campaigns
  const filteredCampaigns = useMemo(() => {
    return campaigns.filter((c) => {
      const matchStatus = campaignStatus === "all" || c.status === campaignStatus;
      const q = campaignSearch.toLowerCase().trim();
      const matchSearch =
        !q ||
        c.name.toLowerCase().includes(q) ||
        (c.actor_name && c.actor_name.toLowerCase().includes(q)) ||
        c.target_sectors.some((s) => s.toLowerCase().includes(q)) ||
        c.cves_exploited.some((v) => v.toLowerCase().includes(q));
      return matchStatus && matchSearch;
    });
  }, [campaigns, campaignStatus, campaignSearch]);

  // Filtered Correlations
  const filteredCorrelations = useMemo(() => {
    if (!correlationSearch.trim()) return correlations;
    const q = correlationSearch.toLowerCase().trim();
    return correlations.filter(
      (c) =>
        c.title.toLowerCase().includes(q) ||
        (c.summary && c.summary.toLowerCase().includes(q)) ||
        c.matched_entities.some((e) => e.value.toLowerCase().includes(q))
    );
  }, [correlations, correlationSearch]);

  // Filtered Learning Paths
  const filteredPaths = useMemo(() => {
    return learningPaths.filter((p) => {
      const matchDiff = pathDifficulty === "all" || p.difficulty === pathDifficulty;
      const matchRole = pathRole === "all" || p.role.toLowerCase().includes(pathRole.toLowerCase());
      return matchDiff && matchRole;
    });
  }, [learningPaths, pathDifficulty, pathRole]);

  // Filtered MITRE Matrix
  const filteredMatrix: AttackMatrixColumn[] = useMemo(() => {
    if (!matrixData) return [];
    return matrixData.matrix
      .filter((col) => selectedTacticId === "all" || col.tactic.id === selectedTacticId)
      .map((col) => {
        if (!mitreSearch.trim()) return col;
        const q = mitreSearch.toLowerCase().trim();
        const matchingTechs = col.techniques.filter((item) => {
          const matchParent =
            item.technique.id.toLowerCase().includes(q) ||
            item.technique.name.toLowerCase().includes(q) ||
            item.technique.description.toLowerCase().includes(q);
          const matchSub = item.subtechniques.some(
            (st) =>
              st.id.toLowerCase().includes(q) ||
              st.name.toLowerCase().includes(q) ||
              st.description.toLowerCase().includes(q)
          );
          return matchParent || matchSub;
        });
        return {
          ...col,
          techniques: matchingTechs,
          techniques_count: matchingTechs.length,
        };
      });
  }, [matrixData, selectedTacticId, mitreSearch]);

  // Handle AI Research Investigation
  const handleRunInvestigation = async (queryText?: string) => {
    const q = (queryText || assistantQuery).trim();
    if (!q) return;
    setIsInvestigating(true);
    try {
      const dossier = await investigateWithAssistant(q);
      setAssistantDossier(dossier);
      setActiveTab("assistant");
    } catch (err) {
      console.error("Investigation failed:", err);
    } finally {
      setIsInvestigating(false);
    }
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* =================================================================== */}
      {/* HEADER BANNER & STATS BAR                                           */}
      {/* =================================================================== */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 font-mono text-[10px] font-bold uppercase tracking-wider">
                VERSION 3 • ADVANCED INTELLIGENCE
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] font-medium">
                STEP 47 OPERATIONAL
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Cyber Threat Intelligence & Correlation Engine
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
              Comprehensive threat actor tracking, malware family analysis, multi-source correlation convergence, chronological incident timelines, cybersecurity learning paths, and autonomous AI research dossiers.
            </p>
          </div>

          {/* Quick Stats Pill Grid */}
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-cyan-400 font-bold mr-1.5">{overview?.total_threat_actors || actors.length}</span>
              <span className="text-slate-500">Actors</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-red-400 font-bold mr-1.5">{overview?.total_malware_families || malware.length}</span>
              <span className="text-slate-500">Malware</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-amber-400 font-bold mr-1.5">{overview?.active_campaigns || campaigns.length}</span>
              <span className="text-slate-500">Campaigns</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-purple-400 font-bold mr-1.5">{overview?.incident_timelines_count || timelines.length}</span>
              <span className="text-slate-500">Timelines</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-emerald-400 font-bold mr-1.5">{overview?.correlated_clusters_count || correlations.length}</span>
              <span className="text-slate-500">Correlated</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-blue-400 font-bold mr-1.5">{overview?.learning_paths_count || learningPaths.length}</span>
              <span className="text-slate-500">Academy</span>
            </div>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-1.5 mt-6 border-b border-slate-800 overflow-x-auto pb-0.5 no-scrollbar">
          {[
            { id: "overview", label: "Overview & Telemetry", count: null },
            { id: "actors", label: "Threat Actors", count: actors.length },
            { id: "malware", label: "Malware Families", count: malware.length },
            { id: "campaigns", label: "Campaigns", count: campaigns.length },
            { id: "timelines", label: "Incident Timelines", count: timelines.length },
            { id: "correlations", label: "Cross-Source Correlation", count: correlations.length },
            { id: "academy", label: "Learning Academy", count: learningPaths.length },
            { id: "assistant", label: "AI Research Assistant", count: "AI" },
            { id: "mitre", label: "MITRE ATT&CK", count: matrixData?.total_techniques || 23 },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as IntelligenceTab)}
                className={`px-3.5 py-2 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all whitespace-nowrap flex items-center gap-1.5 ${
                  isActive
                    ? "border-cyan-500 text-cyan-400 bg-cyan-950/20"
                    : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700"
                }`}
              >
                <span>{tab.label}</span>
                {tab.count !== null && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                      isActive ? "bg-cyan-500/20 text-cyan-300" : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: INTELLIGENCE OVERVIEW DASHBOARD                              */}
      {/* =================================================================== */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* AI Fast Investigation Search Bar */}
          <div className="cyber-card rounded-xl p-5 border border-cyan-500/30 bg-gradient-to-r from-slate-900/90 via-slate-950 to-cyan-950/20 shadow-xl">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                  AUTONOMOUS AGENTIC OSINT INVESTIGATOR
                </span>
                <h3 className="text-lg font-bold text-white tracking-tight">
                  Launch an AI Threat Intelligence Dossier
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Ask the research assistant to decompose complex APT campaigns, analyze living-off-the-land techniques, or synthesize mitigation plans.
                </p>
              </div>

              <div className="flex items-center gap-2 w-full md:w-auto">
                <input
                  type="text"
                  placeholder="e.g. Investigate Volt Typhoon critical infrastructure TTPs..."
                  value={assistantQuery}
                  onChange={(e) => setAssistantQuery(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleRunInvestigation()}
                  className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-full md:w-96"
                />
                <button
                  onClick={() => handleRunInvestigation()}
                  disabled={isInvestigating || !assistantQuery.trim()}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  {isInvestigating ? (
                    <>
                      <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>⚡ Investigate</>
                  )}
                </button>
              </div>
            </div>

            {/* Suggested Prompt Badges */}
            <div className="flex flex-wrap items-center gap-2 mt-4 pt-3 border-t border-slate-800/80 font-mono text-[11px]">
              <span className="text-slate-500">Quick Inquiries:</span>
              {[
                "Investigate Volt Typhoon living-off-the-land techniques",
                "Analyze Citrix Bleed CVE-2023-4966 session token theft",
                "Profile Lazarus Group cryptocurrency heist playbooks",
                "Examine APT29 supply-chain intrusion methods",
              ].map((p, idx) => (
                <button
                  key={idx}
                  onClick={() => {
                    setAssistantQuery(p);
                    handleRunInvestigation(p);
                  }}
                  className="px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 hover:border-cyan-500/40 transition-colors"
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          {/* KPI Dashboard Metrics Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Tracked Nation-States</span>
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {overview?.total_threat_actors || actors.length}
              </div>
              <p className="text-xs text-slate-500 font-mono">
                {overview?.active_threat_actors || actors.filter((a) => a.status === "active").length} actively operating
              </p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-red-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Malware Families</span>
                <span className="w-2.5 h-2.5 rounded-full bg-red-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {overview?.total_malware_families || malware.length}
              </div>
              <p className="text-xs text-slate-500 font-mono">C2, Infostealers, Ransomware, Loaders</p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-amber-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Active Campaigns</span>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {overview?.active_campaigns || campaigns.filter((c) => c.status === "active").length}
              </div>
              <p className="text-xs text-slate-500 font-mono">Critical infrastructure & cloud attacks</p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-purple-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Incident Timelines</span>
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {overview?.incident_timelines_count || timelines.length}
              </div>
              <p className="text-xs text-slate-500 font-mono">Multi-stage kill chain reconstructions</p>
            </div>
          </div>

          {/* Overview Split Columns: Top Actors & Recent Campaigns */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Top Threat Actors Table */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-cyan-400 text-lg">⚡</span>
                  <h3 className="text-sm font-bold text-white font-mono uppercase">Key Threat Actors</h3>
                </div>
                <button
                  onClick={() => setActiveTab("actors")}
                  className="text-xs font-mono text-cyan-400 hover:underline"
                >
                  View All ({actors.length}) →
                </button>
              </div>

              <div className="space-y-3">
                {actors.slice(0, 4).map((actor) => (
                  <div
                    key={actor.id}
                    onClick={() => {
                      setSelectedActor(actor);
                      setActiveTab("actors");
                    }}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 hover:border-cyan-500/50 cursor-pointer transition-all flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-sm font-bold text-white">{actor.name}</span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {actor.country}
                        </span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded uppercase bg-red-500/10 text-red-400 border border-red-500/20">
                          {actor.threat_level}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 line-clamp-1">{actor.description}</p>
                    </div>
                    <span className="text-xs font-mono text-slate-500">Inspect →</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Campaigns Table */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-amber-400 text-lg">🎯</span>
                  <h3 className="text-sm font-bold text-white font-mono uppercase">Ongoing Operations</h3>
                </div>
                <button
                  onClick={() => setActiveTab("campaigns")}
                  className="text-xs font-mono text-amber-400 hover:underline"
                >
                  View All ({campaigns.length}) →
                </button>
              </div>

              <div className="space-y-3">
                {campaigns.slice(0, 4).map((camp) => (
                  <div
                    key={camp.id}
                    onClick={() => {
                      setSelectedCampaign(camp);
                      setActiveTab("campaigns");
                    }}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 hover:border-amber-500/50 cursor-pointer transition-all space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <h4 className="font-mono text-xs font-bold text-white line-clamp-1">{camp.name}</h4>
                      <span className="font-mono text-[10px] px-2 py-0.5 rounded uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        {camp.status}
                      </span>
                    </div>
                    <div className="flex items-center gap-3 text-[11px] font-mono text-slate-400">
                      <span>Actor: <strong className="text-cyan-300">{camp.actor_name || "Unknown"}</strong></span>
                      <span>Confidence: <strong className="text-emerald-400">{camp.confidence_score}%</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: THREAT ACTOR TRACKING                                        */}
      {/* =================================================================== */}
      {activeTab === "actors" && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search actor, alias, or malware..."
                value={actorSearch}
                onChange={(e) => setActorSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
              {actorSearch && (
                <button
                  onClick={() => setActorSearch("")}
                  className="absolute right-2.5 top-1.5 text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Origin:</span>
              <select
                value={actorCountry}
                onChange={(e) => setActorCountry(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Countries</option>
                <option value="RU">Russia (RU)</option>
                <option value="CN">China (CN)</option>
                <option value="KP">North Korea (KP)</option>
                <option value="IR">Iran (IR)</option>
              </select>

              <span className="text-xs font-mono text-slate-400 ml-2">Status:</span>
              <select
                value={actorStatus}
                onChange={(e) => setActorStatus(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Statuses</option>
                <option value="active">Active</option>
                <option value="dormant">Dormant</option>
                <option value="disrupted">Disrupted</option>
              </select>
            </div>
          </div>

          {/* Actor Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {filteredActors.map((actor) => {
              const isSelected = selectedActor?.id === actor.id;
              return (
                <div
                  key={actor.id}
                  onClick={() => setSelectedActor(actor)}
                  className={`cyber-card rounded-xl p-5 border cursor-pointer transition-all space-y-3 ${
                    isSelected
                      ? "border-cyan-500 bg-cyan-950/20 shadow-lg shadow-cyan-950/40"
                      : "border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 status-pulse" />
                      <h3 className="text-base font-bold text-white font-mono">{actor.name}</h3>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {actor.country}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold bg-red-500/10 text-red-400 border border-red-500/20">
                      {actor.threat_level}
                    </span>
                  </div>

                  {actor.aliases && actor.aliases.length > 0 && (
                    <div className="text-xs font-mono">
                      <span className="text-slate-500 mr-1.5">Aliases:</span>
                      <span className="text-slate-300">{actor.aliases.join(", ")}</span>
                    </div>
                  )}

                  <p className="text-xs text-slate-400 line-clamp-3 leading-relaxed">{actor.description}</p>

                  <div className="space-y-2 pt-2 border-t border-slate-800/60 font-mono text-xs">
                    <div>
                      <span className="text-slate-500 block mb-1 uppercase text-[10px]">Associated Malware</span>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.associated_malware.map((m, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20 text-[10px]"
                          >
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 block mb-1 uppercase text-[10px]">Exploited CVEs</span>
                      <div className="flex flex-wrap gap-1.5">
                        {actor.associated_cves.map((c, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 text-[10px]"
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Threat Actor Detailed Inspector Drawer */}
          {selectedActor && (
            <div className="cyber-card rounded-xl p-6 border border-cyan-500/40 bg-slate-900/90 shadow-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 font-mono text-xs font-bold border border-cyan-500/40">
                    {selectedActor.mitre_group_id || "APT"}
                  </span>
                  <h3 className="text-xl font-bold text-white font-mono">{selectedActor.name}</h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Country: {selectedActor.country}
                  </span>
                  <span className="text-xs font-mono px-2 py-0.5 rounded uppercase bg-red-500/10 text-red-400 border border-red-500/20">
                    {selectedActor.threat_level} Level
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRunInvestigation(`Investigate threat actor ${selectedActor.name} tactics`)}
                    className="px-3 py-1 text-xs font-mono rounded bg-cyan-600 hover:bg-cyan-500 text-white transition-colors"
                  >
                    AI Investigate ⚡
                  </button>
                  <button
                    onClick={() => setSelectedActor(null)}
                    className="p-1 text-slate-400 hover:text-white text-xs font-mono"
                  >
                    ✕ Close
                  </button>
                </div>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">{selectedActor.description}</p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 font-mono text-xs">
                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-cyan-400 block mb-2 font-semibold uppercase text-[11px]">Target Sectors</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedActor.target_sectors.map((sec, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                        {sec}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-emerald-400 block mb-2 font-semibold uppercase text-[11px]">Target Countries</span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedActor.target_countries.map((c, idx) => (
                      <span key={idx} className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                        {c}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-amber-400 block mb-2 font-semibold uppercase text-[11px]">Primary Motivation</span>
                  <span className="text-slate-200 capitalize">{selectedActor.motivation || "State Espionage"}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: MALWARE TRACKING & REVERSE ENGINEERING                       */}
      {/* =================================================================== */}
      {activeTab === "malware" && (
        <div className="space-y-4">
          {/* Controls Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search malware name or hash..."
                value={malwareSearch}
                onChange={(e) => setMalwareSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
              {malwareSearch && (
                <button
                  onClick={() => setMalwareSearch("")}
                  className="absolute right-2.5 top-1.5 text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Category:</span>
              <select
                value={malwareType}
                onChange={(e) => setMalwareType(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Types</option>
                <option value="ransomware">Ransomware</option>
                <option value="c2">Command & Control (C2)</option>
                <option value="infostealer">Infostealer</option>
                <option value="loader">Loader / Dropper</option>
              </select>

              <span className="text-xs font-mono text-slate-400 ml-2">Platform:</span>
              <select
                value={malwarePlatform}
                onChange={(e) => setMalwarePlatform(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Platforms</option>
                <option value="Windows">Windows</option>
                <option value="Linux">Linux</option>
                <option value="ESXi">VMware ESXi</option>
              </select>
            </div>
          </div>

          {/* Malware Family Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredMalware.map((fam) => {
              const isSelected = selectedMalware?.id === fam.id;
              return (
                <div
                  key={fam.id}
                  onClick={() => setSelectedMalware(fam)}
                  className={`cyber-card rounded-xl p-5 border cursor-pointer transition-all space-y-3 ${
                    isSelected
                      ? "border-red-500 bg-red-950/10 shadow-lg shadow-red-950/30"
                      : "border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-red-400 status-pulse" />
                      <h3 className="text-base font-bold text-white font-mono">{fam.name}</h3>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase bg-red-500/10 text-red-400 border border-red-500/20">
                        {fam.malware_type}
                      </span>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {fam.mitre_software_id || "MALWARE"}
                    </span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed">{fam.description}</p>

                  <div className="space-y-2 pt-2 border-t border-slate-800/60 font-mono text-xs">
                    <div>
                      <span className="text-slate-500 block mb-1 uppercase text-[10px]">Target Platforms</span>
                      <div className="flex flex-wrap gap-1.5">
                        {fam.target_platforms.map((plat, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800 text-[10px]">
                            {plat}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <span className="text-slate-500 block mb-1 uppercase text-[10px]">Associated Actors</span>
                      <div className="flex flex-wrap gap-1.5">
                        {fam.associated_actors.map((act, idx) => (
                          <span key={idx} className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[10px]">
                            {act}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Malware Deep Inspector (YARA + Hashes) */}
          {selectedMalware && (
            <div className="cyber-card rounded-xl p-6 border border-red-500/40 bg-slate-900/90 shadow-2xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-red-500/20 text-red-300 font-mono text-xs font-bold border border-red-500/40">
                    {selectedMalware.mitre_software_id || "S-ID"}
                  </span>
                  <h3 className="text-xl font-bold text-white font-mono">{selectedMalware.name}</h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded uppercase bg-red-500/10 text-red-400 border border-red-500/20">
                    {selectedMalware.severity} SEVERITY
                  </span>
                </div>
                <button
                  onClick={() => setSelectedMalware(null)}
                  className="p-1 text-slate-400 hover:text-white text-xs font-mono"
                >
                  ✕ Close
                </button>
              </div>

              {/* YARA Rules Box */}
              <div className="space-y-2">
                <span className="text-xs font-mono text-amber-400 font-semibold uppercase block">
                  🛡️ YARA Detection Signatures ({selectedMalware.yara_rules?.length || 0})
                </span>
                {selectedMalware.yara_rules && selectedMalware.yara_rules.length > 0 ? (
                  <div className="space-y-2">
                    {selectedMalware.yara_rules.map((rule, idx) => (
                      <pre
                        key={idx}
                        className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto"
                      >
                        <code>{rule}</code>
                      </pre>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs font-mono text-slate-500">No YARA signatures currently cataloged.</p>
                )}
              </div>

              {/* Sample Cryptographic Hashes */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <span className="text-xs font-mono text-cyan-400 font-semibold uppercase block">
                  🔑 Sample Cryptographic Hashes ({selectedMalware.sample_hashes?.length || 0})
                </span>
                <div className="space-y-1.5">
                  {selectedMalware.sample_hashes?.map((h, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/90 font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <span className="text-slate-400">{h.type || "Sample Hash"}:</span>
                      <span className="text-slate-200 break-all select-all font-bold">
                        {h.sha256 || h.md5 || h.sha1}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: CAMPAIGN TRACKING                                            */}
      {/* =================================================================== */}
      {activeTab === "campaigns" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search campaign name, actor, sector..."
                value={campaignSearch}
                onChange={(e) => setCampaignSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Status:</span>
              <select
                value={campaignStatus}
                onChange={(e) => setCampaignStatus(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Campaigns</option>
                <option value="active">Active</option>
                <option value="emerging">Emerging</option>
                <option value="historical">Historical</option>
              </select>
            </div>
          </div>

          <div className="space-y-4">
            {filteredCampaigns.map((camp) => (
              <div
                key={camp.id}
                className="cyber-card rounded-xl p-6 border border-slate-800 hover:border-amber-500/40 transition-colors space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-3">
                    <span className="w-3 h-3 rounded-full bg-amber-400 status-pulse" />
                    <h3 className="text-base sm:text-lg font-bold text-white font-mono">{camp.name}</h3>
                    <span className="text-xs font-mono px-2 py-0.5 rounded uppercase bg-amber-500/10 text-amber-400 border border-amber-500/20">
                      {camp.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 font-mono text-xs text-slate-400">
                    <span>Actor: <strong className="text-cyan-300">{camp.actor_name || "Unknown"}</strong></span>
                    <span>Confidence: <strong className="text-emerald-400">{camp.confidence_score}%</strong></span>
                  </div>
                </div>

                <p className="text-sm text-slate-300 leading-relaxed">{camp.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono text-xs">
                  <div>
                    <span className="text-slate-500 block mb-2 uppercase">Targeted Sectors</span>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.target_sectors.map((sec, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800">
                          {sec}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-2 uppercase">Exploited CVEs</span>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.cves_exploited.map((cve, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20">
                          {cve}
                        </span>
                      ))}
                    </div>
                  </div>

                  <div>
                    <span className="text-slate-500 block mb-2 uppercase">Malware Arsenal</span>
                    <div className="flex flex-wrap gap-1.5">
                      {camp.malware_used.map((m, idx) => (
                        <span key={idx} className="px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20">
                          {m}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 5: INCIDENT TIMELINES                                           */}
      {/* =================================================================== */}
      {activeTab === "timelines" && (
        <div className="space-y-6">
          {/* Timeline Selector Tabs */}
          <div className="flex items-center gap-2 overflow-x-auto pb-2 border-b border-slate-800">
            {timelines.map((tl) => (
              <button
                key={tl.id}
                onClick={() => setSelectedTimeline(tl)}
                className={`px-4 py-2 text-xs font-mono rounded-lg transition-all ${
                  selectedTimeline?.id === tl.id
                    ? "bg-purple-950/40 text-purple-300 border border-purple-500/40 font-bold"
                    : "bg-slate-900 text-slate-400 hover:text-white border border-slate-800"
                }`}
              >
                {tl.incident_name}
              </button>
            ))}
          </div>

          {/* Active Reconstructed Timeline Display */}
          {selectedTimeline && (
            <div className="cyber-card rounded-xl p-6 border border-purple-500/30 bg-slate-900/60 space-y-6">
              <div className="border-b border-slate-800 pb-4">
                <span className="text-xs font-mono text-purple-400 font-semibold uppercase block mb-1">
                  CHRONOLOGICAL KILL-CHAIN RECONSTRUCTION
                </span>
                <h3 className="text-xl font-bold text-white tracking-tight">{selectedTimeline.title}</h3>
                <p className="text-xs sm:text-sm text-slate-300 mt-1">{selectedTimeline.summary}</p>
              </div>

              {/* Vertical Chronological Stepper */}
              <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-purple-500 before:via-cyan-500 before:to-emerald-500">
                {selectedTimeline.events.map((evt, idx) => (
                  <div key={idx} className="relative group">
                    {/* Stepper Dot */}
                    <div className="absolute -left-[1.85rem] sm:-left-[2.35rem] top-1.5 w-4 h-4 rounded-full bg-slate-950 border-2 border-purple-400 group-hover:scale-110 transition-transform" />

                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-purple-500/40 transition-all space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono text-[10px] font-bold uppercase">
                            {evt.phase}
                          </span>
                          <h4 className="font-mono text-sm font-bold text-white">{evt.title}</h4>
                        </div>
                        <span className="text-[11px] font-mono text-slate-500">
                          {new Date(evt.timestamp).toUTCString()}
                        </span>
                      </div>

                      <p className="text-xs text-slate-300 leading-relaxed">{evt.description}</p>

                      {evt.iocs && evt.iocs.length > 0 && (
                        <div className="pt-2 border-t border-slate-800/60 flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                          <span className="text-slate-500">IOCs / Artifacts:</span>
                          {evt.iocs.map((ioc, iIdx) => (
                            <span
                              key={iIdx}
                              className="px-2 py-0.5 rounded bg-slate-900 text-cyan-300 border border-slate-800 select-all"
                            >
                              {ioc}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 6: CROSS-SOURCE CORRELATION MATRIX                              */}
      {/* =================================================================== */}
      {activeTab === "correlations" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-96">
              <input
                type="text"
                placeholder="Search CVE, actor, or source..."
                value={correlationSearch}
                onChange={(e) => setCorrelationSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
            <div className="text-xs font-mono text-slate-400">
              Correlated Multi-Source Clusters: <strong className="text-emerald-400">{filteredCorrelations.length}</strong>
            </div>
          </div>

          <div className="space-y-4">
            {filteredCorrelations.map((cluster) => (
              <div
                key={cluster.id}
                className="cyber-card rounded-xl p-6 border border-slate-800 hover:border-emerald-500/40 transition-colors space-y-4"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div>
                    <span className="text-[10px] font-mono text-emerald-400 uppercase tracking-wider block mb-1">
                      MULTI-SOURCE CONVERGENCE CLUSTER #{cluster.id}
                    </span>
                    <h3 className="text-base sm:text-lg font-bold text-white font-mono">{cluster.title}</h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-400 font-mono text-xs font-bold border border-emerald-500/30">
                      {cluster.correlation_score.toFixed(1)}% Convergence Score
                    </span>
                  </div>
                </div>

                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">{cluster.summary}</p>

                {/* Overlapping Entities */}
                <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex flex-wrap items-center gap-2 font-mono text-xs">
                  <span className="text-slate-500 uppercase text-[10px]">Overlapping Anchors:</span>
                  {cluster.matched_entities.map((ent, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[11px]"
                    >
                      {ent.entity_type}: {ent.value}
                    </span>
                  ))}
                </div>

                {/* Connected Source Feeds */}
                <div className="space-y-2">
                  <span className="text-xs font-mono text-slate-400 uppercase block">
                    Corroborating Disparate Feeds ({cluster.source_items.length})
                  </span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {cluster.source_items.map((src, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 hover:border-slate-700 transition-colors space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                            {src.source}
                          </span>
                          <a
                            href={src.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[11px] font-mono text-cyan-400 hover:underline"
                          >
                            Source Ref ↗
                          </a>
                        </div>
                        <h5 className="font-mono text-xs font-semibold text-slate-200 line-clamp-1">{src.title}</h5>
                        {src.snippet && <p className="text-[11px] text-slate-400 line-clamp-2">{src.snippet}</p>}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 7: CYBERSECURITY LEARNING PATHS (ACADEMY)                       */}
      {/* =================================================================== */}
      {activeTab === "academy" && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div>
              <h3 className="text-sm font-bold text-white font-mono uppercase">Structured Cybersecurity Curricula</h3>
              <p className="text-xs text-slate-400">
                Master defensive SOC triage, threat attribution, and reverse engineering with guided hands-on labs.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Difficulty:</span>
              <select
                value={pathDifficulty}
                onChange={(e) => setPathDifficulty(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Difficulties</option>
                <option value="beginner">Beginner</option>
                <option value="intermediate">Intermediate</option>
                <option value="advanced">Advanced</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {filteredPaths.map((path) => (
              <div
                key={path.id}
                className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-blue-500/40 transition-all flex flex-col justify-between space-y-4"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded uppercase font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                      {path.role}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                      {path.difficulty} • {path.estimated_hours} Hours
                    </span>
                  </div>

                  <h3 className="text-base font-bold text-white font-mono">{path.title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{path.description}</p>
                </div>

                <div className="space-y-3 pt-3 border-t border-slate-800">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">
                    Curriculum Modules ({path.modules.length})
                  </span>
                  <div className="space-y-2">
                    {path.modules.map((mod) => (
                      <div
                        key={mod.id}
                        className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-xs font-mono space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-slate-200">{mod.title}</span>
                          <span className="text-slate-500 text-[10px]">{mod.duration_hours}h</span>
                        </div>
                        {mod.lab_exercise && (
                          <div className="text-[11px] text-amber-300/90 pt-1">
                            🧪 Lab: {mod.lab_exercise}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 8: AI RESEARCH ASSISTANT CONSOLE                                */}
      {/* =================================================================== */}
      {activeTab === "assistant" && (
        <div className="space-y-6">
          {/* Query Bar */}
          <div className="cyber-card rounded-xl p-5 border border-cyan-500/40 bg-slate-900/80 space-y-3 shadow-xl">
            <span className="text-xs font-mono text-cyan-400 font-semibold uppercase block">
              OSINT Agentic Research Assistant
            </span>
            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Enter investigation prompt (e.g. Analyze Volt Typhoon living-off-the-land stealth techniques)..."
                value={assistantQuery}
                onChange={(e) => setAssistantQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleRunInvestigation()}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-full"
              />
              <button
                onClick={() => handleRunInvestigation()}
                disabled={isInvestigating || !assistantQuery.trim()}
                className="px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors disabled:opacity-50 flex items-center gap-2"
              >
                {isInvestigating ? (
                  <>
                    <span className="inline-block w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                    Synthesizing...
                  </>
                ) : (
                  <>Execute Research Dossier ⚡</>
                )}
              </button>
            </div>
          </div>

          {/* Dossier Results */}
          {assistantDossier ? (
            <div className="cyber-card rounded-xl p-6 border border-slate-800 bg-slate-900/90 space-y-6 shadow-2xl">
              <div className="border-b border-slate-800 pb-4">
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">
                    SYNTHESIZED OSINT THREAT DOSSIER
                  </span>
                  <span className="text-xs font-mono text-slate-500">
                    Generated: {formatDateTime(assistantDossier.generated_at)}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white tracking-tight">
                  Investigation: &ldquo;{assistantDossier.query}&rdquo;
                </h2>
              </div>

              {/* Executive Summary */}
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-2">
                <span className="text-xs font-mono text-cyan-300 font-bold uppercase block">
                  Executive Briefing & Synthesis
                </span>
                <p className="text-xs sm:text-sm text-slate-200 leading-relaxed">
                  {assistantDossier.executive_summary}
                </p>
              </div>

              {/* Key Findings */}
              <div className="space-y-3">
                <h4 className="font-mono text-sm font-bold text-white uppercase text-amber-400">
                  Key Findings & Attribution ({assistantDossier.key_findings.length})
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {assistantDossier.key_findings.map((finding, idx) => (
                    <div
                      key={idx}
                      className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-xs font-bold text-slate-200">{finding.topic}</span>
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-emerald-400 font-bold">
                          {(finding.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 leading-relaxed">{finding.summary}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attack Path Milestones */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <h4 className="font-mono text-sm font-bold text-white uppercase text-purple-400">
                  Kill-Chain Progression & Attack Milestones
                </h4>
                <div className="space-y-2 font-mono text-xs">
                  {assistantDossier.attack_path_milestones.map((ms, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 text-slate-300 flex items-center gap-3"
                    >
                      <span className="w-5 h-5 rounded-full bg-purple-500/20 text-purple-300 flex items-center justify-center font-bold text-[10px]">
                        {idx + 1}
                      </span>
                      <span>{ms}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Mitigations */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <h4 className="font-mono text-sm font-bold text-white uppercase text-emerald-400">
                  Actionable Defensive Recommendations
                </h4>
                <ul className="space-y-2 font-mono text-xs">
                  {assistantDossier.recommended_mitigations.map((mit, idx) => (
                    <li
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-slate-300 flex items-start gap-2"
                    >
                      <span className="text-emerald-400 font-bold">✓</span>
                      <span>{mit}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Citations */}
              <div className="pt-3 border-t border-slate-800 flex flex-wrap items-center gap-2 font-mono text-xs">
                <span className="text-slate-500">Traceable Citations:</span>
                {assistantDossier.citations.map((cit, idx) => (
                  <a
                    key={idx}
                    href={cit.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 transition-colors"
                  >
                    {cit.source}: {cit.title} ↗
                  </a>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-12 text-center border border-dashed border-slate-800 rounded-xl space-y-3 font-mono text-xs text-slate-500">
              <span className="text-2xl block">🤖</span>
              <p>No active dossier generated yet. Enter an inquiry above or select a quick prompt.</p>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 9: MITRE ATT&CK ENTERPRISE MATRIX (RETAINED)                    */}
      {/* =================================================================== */}
      {activeTab === "mitre" && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search technique (e.g. T1190, Phishing)..."
                value={mitreSearch}
                onChange={(e) => setMitreSearch(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Tactic:</span>
              <select
                value={selectedTacticId}
                onChange={(e) => setSelectedTacticId(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All 14 Tactics</option>
                {matrixData?.matrix.map((c) => (
                  <option key={c.tactic.id} value={c.tactic.id}>
                    {c.tactic.name} ({c.tactic.id})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="overflow-x-auto pb-4">
            <div className="flex gap-3 min-w-max">
              {filteredMatrix.map((col) => (
                <div
                  key={col.tactic.id}
                  className="w-64 flex-shrink-0 flex flex-col rounded-xl bg-slate-900/50 border border-slate-800 overflow-hidden"
                >
                  <div className="p-3 bg-slate-950/80 border-b border-slate-800">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-mono text-cyan-400 font-semibold uppercase">
                        {col.tactic.id}
                      </span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {col.techniques.length}
                      </span>
                    </div>
                    <h3 className="text-xs font-bold text-white tracking-tight leading-snug">
                      {col.tactic.name}
                    </h3>
                  </div>

                  <div className="p-2 space-y-2 flex-1 overflow-y-auto max-h-[600px]">
                    {col.techniques.length === 0 ? (
                      <p className="text-[11px] font-mono text-slate-500 p-2 text-center">No matching techniques</p>
                    ) : (
                      col.techniques.map((item) => {
                        const pt = item.technique;
                        const hasSubs = item.subtechniques.length > 0;
                        const isExpanded = !!expandedTechniques[pt.id];
                        const isSelected = selectedTechnique?.id === pt.id;

                        return (
                          <div
                            key={pt.id}
                            className={`rounded-lg border transition-all text-xs ${
                              isSelected
                                ? "bg-cyan-950/40 border-cyan-500 shadow-md shadow-cyan-950/50"
                                : "bg-slate-950/70 border-slate-800/90 hover:border-slate-700"
                            }`}
                          >
                            <div
                              onClick={() => setSelectedTechnique(pt)}
                              className="p-2.5 cursor-pointer"
                            >
                              <div className="flex items-center justify-between gap-1 mb-1">
                                <span className="font-mono text-[10px] text-cyan-300 font-semibold">
                                  {pt.id}
                                </span>
                                {hasSubs && (
                                  <button
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setExpandedTechniques((prev) => ({ ...prev, [pt.id]: !prev[pt.id] }));
                                    }}
                                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
                                  >
                                    {isExpanded ? "−" : `+${item.subtechniques.length}`}
                                  </button>
                                )}
                              </div>
                              <p className="font-medium text-slate-200 text-xs line-clamp-2 leading-tight">
                                {pt.name}
                              </p>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
