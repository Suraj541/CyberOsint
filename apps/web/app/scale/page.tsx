"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { formatTime } from "../../lib/formatters";
import {
  calculateBlastRadius,
  executeFederatedSearch,
  fetchCacheTelemetry,
  fetchEvaluationBenchmarks,
  fetchGraphCentrality,
  fetchGraphCommunities,
  fetchILMPolicies,
  fetchIngestionBackpressure,
  fetchMarketplaceConnectors,
  fetchModelRoutes,
  fetchMultiRegionTopology,
  fetchScaleOverview,
  fetchSourceReputations,
  installMarketplaceConnector,
  invalidateCacheTags,
  resolveGeoRoute,
  routeModelInference,
  simulateRegionFailover,
  submitSourceReputationFeedback,
  triggerEvaluationRun,
  uninstallMarketplaceConnector,
  updateIngestionBackpressure,
} from "../../lib/api";
import {
  BackpressureStatus,
  BenchmarkRun,
  BlastRadiusResponse,
  CacheStats,
  CentralityRankingItem,
  CommunityClusterItem,
  FederatedSearchResponse,
  GeoRouteResult,
  ILMPolicy,
  MarketplaceConnector,
  ModelRouteConfig,
  ModelRouteResponse,
  RegionNode,
  ScaleOverview,
  SourceReputation,
} from "../../lib/types";

type ScaleTab =
  | "overview"
  | "ingestion"
  | "marketplace"
  | "regions"
  | "caching"
  | "search"
  | "graph"
  | "models"
  | "quality";

export default function ScaleArchitecturePage() {
  const [activeTab, setActiveTab] = useState<ScaleTab>("overview");
  const [loading, setLoading] = useState<boolean>(true);

  // Core Section 49 State
  const [overview, setOverview] = useState<ScaleOverview | null>(null);
  const [backpressure, setBackpressure] = useState<BackpressureStatus | null>(null);
  const [connectors, setConnectors] = useState<MarketplaceConnector[]>([]);
  const [regions, setRegions] = useState<RegionNode[]>([]);
  const [cacheStats, setCacheStats] = useState<CacheStats | null>(null);
  const [ilmPolicies, setIlmPolicies] = useState<ILMPolicy[]>([]);
  const [centralities, setCentralities] = useState<CentralityRankingItem[]>([]);
  const [communities, setCommunities] = useState<CommunityClusterItem[]>([]);
  const [modelRoutes, setModelRoutes] = useState<ModelRouteConfig[]>([]);
  const [benchmarks, setBenchmarks] = useState<BenchmarkRun[]>([]);
  const [reputations, setReputations] = useState<SourceReputation[]>([]);

  // Interactive Action States
  const [selectedConnector, setSelectedConnector] = useState<MarketplaceConnector | null>(null);
  const [rateMultiplier, setRateMultiplier] = useState<number>(1.0);
  const [clientIpQuery, setClientIpQuery] = useState<string>("198.51.100.44");
  const [geoRouteResult, setGeoRouteResult] = useState<GeoRouteResult | null>(null);
  const [tagToInvalidate, setTagToInvalidate] = useState<string>("cve:CVE-2023-4966");
  const [invalidateNotice, setInvalidateNotice] = useState<string | null>(null);
  const [federatedQuery, setFederatedQuery] = useState<string>("CVE-2023-4966");
  const [federatedResults, setFederatedResults] = useState<FederatedSearchResponse | null>(null);
  const [blastTarget, setBlastTarget] = useState<string>("CVE-2023-4966");
  const [blastResult, setBlastResult] = useState<BlastRadiusResponse | null>(null);
  const [routerPrompt, setRouterPrompt] = useState<string>("Extract threat actors from advisory text");
  const [routerTaskType, setRouterTaskType] = useState<string>("entity_extraction");
  const [routerLatencyPriority, setRouterLatencyPriority] = useState<boolean>(false);
  const [routeResult, setRouteResult] = useState<ModelRouteResponse | null>(null);

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [
          ovRes,
          bpRes,
          connRes,
          regRes,
          cStatsRes,
          ilmRes,
          centRes,
          commRes,
          mRoutesRes,
          benchRes,
          repRes,
        ] = await Promise.all([
          fetchScaleOverview(),
          fetchIngestionBackpressure(),
          fetchMarketplaceConnectors(),
          fetchMultiRegionTopology(),
          fetchCacheTelemetry(),
          fetchILMPolicies(),
          fetchGraphCentrality(),
          fetchGraphCommunities(),
          fetchModelRoutes(),
          fetchEvaluationBenchmarks(),
          fetchSourceReputations(),
        ]);
        setOverview(ovRes);
        setBackpressure(bpRes);
        setConnectors(connRes);
        setRegions(regRes);
        setCacheStats(cStatsRes);
        setIlmPolicies(ilmRes);
        setCentralities(centRes);
        setCommunities(commRes);
        setModelRoutes(mRoutesRes);
        setBenchmarks(benchRes);
        setReputations(repRes);

        if (connRes.length > 0) setSelectedConnector(connRes[0]);
        if (bpRes) setRateMultiplier(bpRes.ingestion_rate_multiplier);
      } catch (err) {
        console.error("Failed to load scale architecture telemetry:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  // Handlers for interactive actions
  const handleUpdateBackpressure = async (newMultiplier: number) => {
    setRateMultiplier(newMultiplier);
    const updated = await updateIngestionBackpressure(newMultiplier);
    setBackpressure(updated);
  };

  const handleToggleInstall = async (c: MarketplaceConnector) => {
    if (c.is_installed) {
      const res = await uninstallMarketplaceConnector(c.id);
      setConnectors((prev) => prev.map((item) => (item.id === c.id ? res : item)));
      if (selectedConnector?.id === c.id) setSelectedConnector(res);
    } else {
      const res = await installMarketplaceConnector(c.id);
      setConnectors((prev) => prev.map((item) => (item.id === c.id ? res : item)));
      if (selectedConnector?.id === c.id) setSelectedConnector(res);
    }
  };

  const handleResolveGeo = async () => {
    const res = await resolveGeoRoute(clientIpQuery);
    setGeoRouteResult(res);
  };

  const handleFailoverSim = async (failed: string, target: string) => {
    const res = await simulateRegionFailover(failed, target);
    setRegions(res);
  };

  const handleInvalidateTags = async () => {
    const res = await invalidateCacheTags([tagToInvalidate]);
    setInvalidateNotice(`Purged ${res.invalidated_keys_count} keys across L1/L2 matching tag [${tagToInvalidate}]`);
    setTimeout(() => setInvalidateNotice(null), 4000);
    const updatedStats = await fetchCacheTelemetry();
    setCacheStats(updatedStats);
  };

  const handleFederatedSearch = async () => {
    const res = await executeFederatedSearch(federatedQuery);
    setFederatedResults(res);
  };

  const handleCalculateBlastRadius = async () => {
    const res = await calculateBlastRadius(blastTarget);
    setBlastResult(res);
  };

  const handleRouteInference = async () => {
    const res = await routeModelInference(routerTaskType, routerPrompt, routerLatencyPriority);
    setRouteResult(res);
  };

  const handleTriggerBenchmark = async (suite: string) => {
    const newRun = await triggerEvaluationRun(suite, 75);
    setBenchmarks((prev) => [newRun, ...prev]);
  };

  const handleFeedbackReputation = async (sourceName: string, isCorroborated: boolean) => {
    const res = await submitSourceReputationFeedback(sourceName, isCorroborated, !isCorroborated, 115.0);
    setReputations((prev) => prev.map((s) => (s.source_name === sourceName ? res : s)));
  };

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/30 text-purple-400 font-mono text-[10px] font-bold uppercase tracking-wider">
                VERSION 4 • ENTERPRISE SCALE ARCHITECTURE
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 font-mono text-[10px] font-medium">
                STEP 48 OPERATIONAL
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Distributed Scale & High-Throughput Operations Hub
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
              Coordinating distributed worker partitions, community connector packaging, multi-region datacenter topologies, multi-tier cache telemetry, federated search, graph centrality, model gateway, and continuous Bayesian source quality learning.
            </p>
          </div>

          {/* KPI Stat Badges */}
          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-cyan-400 font-bold mr-1.5">{overview?.total_workers_active ?? 0}</span>
              <span className="text-slate-500">Workers</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-emerald-400 font-bold mr-1.5">{overview?.active_regions_count ?? 1}</span>
              <span className="text-slate-500">Regions</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-purple-400 font-bold mr-1.5">{overview?.marketplace_connectors_count ?? 0}</span>
              <span className="text-slate-500">Plugins</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-amber-400 font-bold mr-1.5">{(((cacheStats?.overall_hit_ratio ?? 0)) * 100).toFixed(1)}%</span>
              <span className="text-slate-500">Cache Hit</span>
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 shadow-sm">
              <span className="text-blue-400 font-bold mr-1.5">{overview?.average_benchmark_f1 ?? 0}</span>
              <span className="text-slate-500">Avg F1</span>
            </div>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-1.5 mt-6 border-b border-slate-800 overflow-x-auto pb-0.5 no-scrollbar">
          {[
            { id: "overview", label: "Overview", count: null },
            { id: "ingestion", label: "Distributed Ingestion", count: backpressure?.active_workers_count ?? 0 },
            { id: "marketplace", label: "Connector Marketplace", count: connectors.length },
            { id: "regions", label: "Multi-Region Topology", count: regions.length },
            { id: "caching", label: "Multi-Tier Caching", count: "L1/L2" },
            { id: "search", label: "Large-Scale Search & ILM", count: ilmPolicies.length },
            { id: "graph", label: "Graph Analytics", count: centralities.length },
            { id: "models", label: "Model Routing Gateway", count: modelRoutes.length },
            { id: "quality", label: "Automated Evaluation & Quality", count: reputations.length },
          ].map((tab) => {
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as ScaleTab)}
                className={`px-3.5 py-2 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all whitespace-nowrap flex items-center gap-1.5 ${
                  isActive
                    ? "border-purple-500 text-purple-300 bg-purple-950/20 font-bold"
                    : "border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700"
                }`}
              >
                <span>{tab.label}</span>
                {tab.count !== null && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded font-semibold ${
                      isActive ? "bg-purple-500/20 text-purple-300" : "bg-slate-800 text-slate-400"
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
      {/* TAB 1: SCALE OVERVIEW                                               */}
      {/* =================================================================== */}
      {activeTab === "overview" && (
        <div className="space-y-6">
          {/* Top Metrics Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Worker Partitions</span>
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {backpressure?.partitions.length || 4} Partitions
              </div>
              <p className="text-xs text-slate-500 font-mono">
                Throughput: ~{backpressure?.partitions.reduce((acc, p) => acc + p.current_throughput_eps, 0).toFixed(0)} events/sec
              </p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-emerald-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Global Regions</span>
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {regions.filter((r) => r.status === "healthy").length} Active
              </div>
              <p className="text-xs text-slate-500 font-mono">us-east, eu-central, ap-southeast</p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-purple-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Cache Efficiency</span>
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {((cacheStats?.overall_hit_ratio || 0.865) * 100).toFixed(1)}%
              </div>
              <p className="text-xs text-slate-500 font-mono">L1 LRU: 0.15ms • L2 Redis: 1.85ms</p>
            </div>

            <div className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-amber-500/40 transition-all">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono text-slate-400 uppercase">Gold Tier Feeds</span>
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 status-pulse" />
              </div>
              <div className="text-3xl font-bold font-mono text-white mb-1">
                {reputations.filter((r) => r.tier === "gold").length} Gold Feeds
              </div>
              <p className="text-xs text-slate-500 font-mono">CISA, NVD, CERT-EU (95%+ Trust)</p>
            </div>
          </div>

          {/* Partition Grid & Region Health Split */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Real-Time Worker Ingestion Partitions */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-cyan-400 text-lg">⚡</span>
                  <h3 className="text-sm font-bold text-white font-mono uppercase">Worker Partition Ring</h3>
                </div>
                <button
                  onClick={() => setActiveTab("ingestion")}
                  className="text-xs font-mono text-cyan-400 hover:underline"
                >
                  Manage Backpressure →
                </button>
              </div>

              <div className="space-y-2.5">
                {backpressure?.partitions.map((part) => (
                  <div
                    key={part.worker_id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-bold text-white">{part.worker_id}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          Partition #{part.partition_id}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                          {part.status}
                        </span>
                      </div>
                      <span className="text-slate-500 text-[11px]">
                        Sources: {part.assigned_sources_count} • Throughput: {part.current_throughput_eps} eps
                      </span>
                    </div>
                    <span className="text-cyan-400 text-[11px] font-bold">Online</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Multi-Datacenter Topology */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className="text-emerald-400 text-lg">🌐</span>
                  <h3 className="text-sm font-bold text-white font-mono uppercase">Datacenter Topology</h3>
                </div>
                <button
                  onClick={() => setActiveTab("regions")}
                  className="text-xs font-mono text-emerald-400 hover:underline"
                >
                  Geo-Routing & Failover →
                </button>
              </div>

              <div className="space-y-2.5">
                {regions.map((reg) => (
                  <div
                    key={reg.region_code}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex items-center justify-between gap-3 font-mono text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="font-bold text-white">{reg.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          {reg.region_code}
                        </span>
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${
                            reg.role === "primary"
                              ? "bg-purple-500/20 text-purple-300 border border-purple-500/40"
                              : "bg-slate-800 text-slate-400"
                          }`}
                        >
                          {reg.role}
                        </span>
                      </div>
                      <span className="text-slate-500 text-[11px]">
                        Latency: {reg.latency_ms}ms • Replication Lag: {reg.replication_lag_ms}ms
                      </span>
                    </div>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded uppercase font-semibold ${
                        reg.status === "healthy"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : "bg-red-500/10 text-red-400 border border-red-500/20"
                      }`}
                    >
                      {reg.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: DISTRIBUTED INGESTION & BACKPRESSURE                         */}
      {/* =================================================================== */}
      {activeTab === "ingestion" && (
        <div className="space-y-6">
          {/* Backpressure Controller Bar */}
          <div className="cyber-card rounded-xl p-5 border border-cyan-500/30 bg-slate-900/80 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                  DYNAMIC QUEUE REGULATOR
                </span>
                <h3 className="text-base sm:text-lg font-bold text-white font-mono">
                  Ingestion Backpressure & Throttle Controller
                </h3>
              </div>
              <div className="flex items-center gap-3 font-mono text-xs">
                <span className="text-slate-400">Current Queue Depth:</span>
                <span className="px-2.5 py-1 rounded bg-slate-800 text-cyan-300 font-bold">
                  {backpressure?.queue_depth || 145} items
                </span>
                <span className="text-slate-400 ml-2">High Watermark:</span>
                <span className="px-2.5 py-1 rounded bg-slate-800 text-red-400 font-bold">
                  {backpressure?.high_watermark || 500} items
                </span>
              </div>
            </div>

            {/* Interactive Throttle Slider */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300">
                  Ingestion Rate Multiplier: <strong className="text-cyan-400 font-bold">{rateMultiplier.toFixed(2)}x</strong>
                </span>
                <span className="text-slate-500">
                  {rateMultiplier < 0.9 ? "⚠️ Throttling Engaged" : "✓ Unthrottled Full Speed"}
                </span>
              </div>
              <input
                type="range"
                min="0.2"
                max="1.0"
                step="0.05"
                value={rateMultiplier}
                onChange={(e) => handleUpdateBackpressure(parseFloat(e.target.value))}
                className="w-full accent-cyan-500 cursor-pointer"
              />
              <div className="flex justify-between text-[10px] font-mono text-slate-500">
                <span>0.2x (Severe Throttle)</span>
                <span>0.5x (Half Speed)</span>
                <span>0.8x (Gentle Backpressure)</span>
                <span>1.0x (Normal Full Speed)</span>
              </div>
            </div>
          </div>

          {/* Worker Partition Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {backpressure?.partitions.map((part) => (
              <div
                key={part.worker_id}
                className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/40 transition-all space-y-3"
              >
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <span className="font-mono text-sm font-bold text-white">{part.worker_id}</span>
                  <span className="font-mono text-[10px] px-1.5 py-0.5 rounded uppercase bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    {part.status}
                  </span>
                </div>
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>Partition ID:</span>
                    <span className="text-slate-200 font-bold">#{part.partition_id}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Assigned Sources:</span>
                    <span className="text-slate-200 font-bold">{part.assigned_sources_count} feeds</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Throughput:</span>
                    <span className="text-cyan-300 font-bold">{part.current_throughput_eps} eps</span>
                  </div>
                  <div className="flex justify-between text-slate-500 text-[10px] pt-1">
                    <span>Heartbeat:</span>
                    <span>{formatTime(part.last_heartbeat)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: CONNECTOR MARKETPLACE                                        */}
      {/* =================================================================== */}
      {activeTab === "marketplace" && (
        <div className="space-y-6">
          <div className="cyber-card rounded-xl p-5 border border-purple-500/30 bg-slate-900/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-base font-bold text-white font-mono uppercase">Community Connector Store</h3>
              <p className="text-xs text-slate-400">
                Discover, install, and audit verified third-party OSINT plugins with sandboxed permission policies.
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Verified Plugins:</span>
              <span className="px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 font-mono text-xs font-bold">
                {connectors.filter((c) => c.is_verified).length} Verified
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {connectors.map((conn) => {
              const isSelected = selectedConnector?.id === conn.id;
              return (
                <div
                  key={conn.id}
                  onClick={() => setSelectedConnector(conn)}
                  className={`cyber-card rounded-xl p-5 border cursor-pointer transition-all space-y-3 ${
                    isSelected
                      ? "border-purple-500 bg-purple-950/20 shadow-lg shadow-purple-950/30"
                      : "border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <div className="flex items-center justify-between border-b border-slate-800/80 pb-2.5">
                    <div className="flex items-center gap-2">
                      <span className="w-2.5 h-2.5 rounded-full bg-purple-400 status-pulse" />
                      <h4 className="font-mono text-sm font-bold text-white line-clamp-1">{conn.name}</h4>
                    </div>
                    {conn.is_verified && (
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-bold">
                        ✓ Verified
                      </span>
                    )}
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">{conn.description}</p>

                  <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-slate-800/60">
                    <span className="text-slate-500">v{conn.version} • {conn.downloads_count} downloads</span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        handleToggleInstall(conn);
                      }}
                      className={`px-3 py-1 rounded font-bold transition-colors text-[11px] ${
                        conn.is_installed
                          ? "bg-red-500/20 text-red-300 hover:bg-red-500/30 border border-red-500/30"
                          : "bg-purple-600 text-white hover:bg-purple-500"
                      }`}
                    >
                      {conn.is_installed ? "Uninstall" : "Install"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Selected Connector Manifest Inspector */}
          {selectedConnector && (
            <div className="cyber-card rounded-xl p-6 border border-purple-500/40 bg-slate-900/90 shadow-2xl space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-purple-500/20 text-purple-300 font-mono text-xs font-bold border border-purple-500/40">
                    {selectedConnector.category}
                  </span>
                  <h3 className="text-xl font-bold text-white font-mono">{selectedConnector.name}</h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    v{selectedConnector.version} by {selectedConnector.author}
                  </span>
                </div>
                <button
                  onClick={() => setSelectedConnector(null)}
                  className="p-1 text-slate-400 hover:text-white text-xs font-mono"
                >
                  ✕ Close
                </button>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">{selectedConnector.description}</p>

              <div className="space-y-2">
                <span className="text-xs font-mono text-purple-400 font-semibold uppercase block">
                  🛡️ Security Manifest & Sandboxed Permissions
                </span>
                <pre className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-[11px] font-mono text-purple-300 overflow-x-auto">
                  <code>{JSON.stringify(selectedConnector.manifest, null, 2)}</code>
                </pre>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: MULTI-REGION TOPOLOGY & GEO-ROUTING                         */}
      {/* =================================================================== */}
      {activeTab === "regions" && (
        <div className="space-y-6">
          {/* Datacenter Nodes Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {regions.map((reg) => (
              <div
                key={reg.region_code}
                className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-emerald-500/40 transition-all space-y-3"
              >
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <span className="font-mono text-sm font-bold text-white">{reg.name}</span>
                  <span
                    className={`font-mono text-[10px] px-2 py-0.5 rounded uppercase font-bold ${
                      reg.role === "primary"
                        ? "bg-purple-500/20 text-purple-300 border border-purple-500/40"
                        : "bg-slate-800 text-slate-400"
                    }`}
                  >
                    {reg.role}
                  </span>
                </div>

                <div className="space-y-1.5 font-mono text-xs">
                  <div className="flex justify-between text-slate-400">
                    <span>Region Code:</span>
                    <span className="text-slate-200">{reg.region_code}</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Cluster Latency:</span>
                    <span className="text-emerald-300 font-bold">{reg.latency_ms}ms</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Replication Lag:</span>
                    <span className="text-slate-200 font-bold">{reg.replication_lag_ms}ms</span>
                  </div>
                  <div className="flex justify-between text-slate-400">
                    <span>Active Conns:</span>
                    <span className="text-slate-200">{reg.active_connections}</span>
                  </div>
                </div>

                {reg.role === "replica" && (
                  <button
                    onClick={() => handleFailoverSim("us-east-1", reg.region_code)}
                    className="w-full mt-2 py-1.5 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    Simulate Failover To Here ↗
                  </button>
                )}
              </div>
            ))}
          </div>

          {/* Interactive Geo-IP Proximity Resolver */}
          <div className="cyber-card rounded-xl p-5 border border-emerald-500/30 bg-slate-900/80 space-y-4">
            <span className="text-xs font-mono text-emerald-400 font-semibold uppercase block">
              Geo-Routing Resolver Simulator
            </span>
            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Enter test client IP (e.g. 198.51.100.44)..."
                value={clientIpQuery}
                onChange={(e) => setClientIpQuery(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500 font-mono w-full sm:w-80"
              />
              <button
                onClick={handleResolveGeo}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors"
              >
                Resolve Route 🌐
              </button>
            </div>

            {geoRouteResult && (
              <div className="p-4 rounded-lg bg-slate-950/80 border border-emerald-500/40 font-mono text-xs space-y-2">
                <div className="flex items-center gap-3">
                  <span className="text-slate-400">Resolved Destination:</span>
                  <span className="text-emerald-300 font-bold text-sm">{geoRouteResult.routed_region}</span>
                  <span className="text-slate-500 text-[11px]">({geoRouteResult.endpoint})</span>
                </div>
                <div className="text-slate-400">
                  Estimated Proximity Latency: <strong className="text-emerald-300">{geoRouteResult.estimated_latency_ms}ms</strong>
                </div>
                <p className="text-[11px] text-slate-500">{geoRouteResult.reason}</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 5: MULTI-TIER CACHING & TAG INVALIDATION                        */}
      {/* =================================================================== */}
      {activeTab === "caching" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* L1 Memory LRU */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-mono text-sm font-bold text-white">Tier 1: In-Memory LRU</span>
                <span className="text-xs font-mono text-cyan-400 font-bold">
                  {((cacheStats?.l1_stats.hit_ratio || 0.86) * 100).toFixed(1)}% Hit Rate
                </span>
              </div>
              <div className="space-y-1.5 font-mono text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Hits / Misses:</span>
                  <span className="text-slate-200">{cacheStats?.l1_stats.hits} / {cacheStats?.l1_stats.misses}</span>
                </div>
                <div className="flex justify-between">
                  <span>Cached Items:</span>
                  <span className="text-slate-200">{cacheStats?.l1_stats.item_count} hot objects</span>
                </div>
                <div className="flex justify-between">
                  <span>Average Access Latency:</span>
                  <span className="text-cyan-300 font-bold">{cacheStats?.l1_stats.avg_latency_ms}ms</span>
                </div>
              </div>
            </div>

            {/* L2 Distributed Redis */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-mono text-sm font-bold text-white">Tier 2: Distributed Redis</span>
                <span className="text-xs font-mono text-emerald-400 font-bold">
                  {((cacheStats?.l2_stats.hit_ratio || 0.80) * 100).toFixed(1)}% Hit Rate
                </span>
              </div>
              <div className="space-y-1.5 font-mono text-xs text-slate-400">
                <div className="flex justify-between">
                  <span>Hits / Misses:</span>
                  <span className="text-slate-200">{cacheStats?.l2_stats.hits} / {cacheStats?.l2_stats.misses}</span>
                </div>
                <div className="flex justify-between">
                  <span>Cached Items:</span>
                  <span className="text-slate-200">{cacheStats?.l2_stats.item_count} distributed keys</span>
                </div>
                <div className="flex justify-between">
                  <span>Average Access Latency:</span>
                  <span className="text-emerald-300 font-bold">{cacheStats?.l2_stats.avg_latency_ms}ms</span>
                </div>
              </div>
            </div>
          </div>

          {/* Tag-based Invalidation Console */}
          <div className="cyber-card rounded-xl p-5 border border-purple-500/30 bg-slate-900/80 space-y-4">
            <span className="text-xs font-mono text-purple-400 font-semibold uppercase block">
              Tag-Based Cache Invalidator (XFetch Stampede Protected)
            </span>
            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Enter tag to invalidate (e.g. cve:CVE-2023-4966 or actor:apt29)..."
                value={tagToInvalidate}
                onChange={(e) => setTagToInvalidate(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500 font-mono w-full sm:w-96"
              />
              <button
                onClick={handleInvalidateTags}
                className="px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors"
              >
                Purge Tag Keys ⚡
              </button>
            </div>

            {invalidateNotice && (
              <div className="p-3 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 font-mono text-xs">
                {invalidateNotice}
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 6: LARGE-SCALE SEARCH & ILM                                     */}
      {/* =================================================================== */}
      {activeTab === "search" && (
        <div className="space-y-6">
          {/* ILM Policy Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {ilmPolicies.map((ilm) => (
              <div
                key={ilm.tier}
                className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-cyan-500/30 transition-all space-y-2"
              >
                <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                  <span className="font-mono text-sm font-bold text-white">{ilm.tier} Tier</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                    {ilm.retention_days} Days
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs text-slate-400">
                  <div className="flex justify-between">
                    <span>Shards / Replicas:</span>
                    <span className="text-slate-200">{ilm.shard_count} / {ilm.replica_count}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Compression:</span>
                    <span className="text-slate-200">{ilm.compression}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Indexed Docs:</span>
                    <span className="text-slate-200 font-bold">{ilm.total_docs_indexed.toLocaleString()}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Storage Size:</span>
                    <span className="text-cyan-300 font-bold">{ilm.size_gb} GB</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Federated Search Tester */}
          <div className="cyber-card rounded-xl p-5 border border-cyan-500/30 bg-slate-900/80 space-y-4">
            <span className="text-xs font-mono text-cyan-400 font-semibold uppercase block">
              Multi-Cluster Federated Search Tester
            </span>
            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Search across all global clusters..."
                value={federatedQuery}
                onChange={(e) => setFederatedQuery(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-full sm:w-96"
              />
              <button
                onClick={handleFederatedSearch}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors"
              >
                Execute Federated Search 🔍
              </button>
            </div>

            {federatedResults && (
              <div className="space-y-3 pt-2">
                <div className="flex items-center justify-between font-mono text-xs text-slate-400">
                  <span>Total Hits: {federatedResults.total_hits}</span>
                  <span>Execution Time: {federatedResults.execution_time_ms}ms across 3 regions</span>
                </div>
                <div className="space-y-2">
                  {federatedResults.results.map((hit) => (
                    <div
                      key={hit.id}
                      className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-1 font-mono text-xs"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-white">{hit.title}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300">
                          {hit.region_origin}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[11px]">{hit.snippet}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 7: ADVANCED GRAPH ANALYTICS                                     */}
      {/* =================================================================== */}
      {activeTab === "graph" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* PageRank Centrality Leaderboard */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <span className="text-[10px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                  GRAPH CENTRALITY RANKINGS
                </span>
                <h3 className="text-base font-bold text-white font-mono">PageRank Threat & Vulnerability Hubs</h3>
              </div>

              <div className="space-y-2">
                {centralities.map((item) => (
                  <div
                    key={item.node_id}
                    className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between font-mono text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center font-bold text-[10px]">
                        #{item.rank}
                      </span>
                      <span className="text-slate-200 font-medium">{item.label}</span>
                    </div>
                    <span className="text-cyan-300 font-bold">{item.score.toFixed(3)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Community Clusters */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <span className="text-[10px] font-mono text-purple-400 uppercase tracking-wider block mb-1">
                  LOUVAIN MODULARITY
                </span>
                <h3 className="text-base font-bold text-white font-mono">Detected Threat Communities</h3>
              </div>

              <div className="space-y-3">
                {communities.map((comm) => (
                  <div
                    key={comm.cluster_id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{comm.cluster_name}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300">
                        {comm.size} Nodes
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {comm.dominant_actors.map((act, idx) => (
                        <span key={idx} className="px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-300 text-[10px]">
                          {act}
                        </span>
                      ))}
                      {comm.dominant_cves.map((cve, idx) => (
                        <span key={idx} className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-300 text-[10px]">
                          {cve}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Blast Radius Interactive Traversal */}
          <div className="cyber-card rounded-xl p-5 border border-red-500/30 bg-slate-900/80 space-y-4">
            <span className="text-xs font-mono text-red-400 font-semibold uppercase block">
              Multi-Hop Blast Radius Impact Simulator
            </span>
            <div className="flex flex-col sm:flex-row items-center gap-3">
              <input
                type="text"
                placeholder="Enter breached entity (e.g. CVE-2023-4966 or LockBit)..."
                value={blastTarget}
                onChange={(e) => setBlastTarget(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500 font-mono w-full sm:w-96"
              />
              <button
                onClick={handleCalculateBlastRadius}
                className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors"
              >
                Compute Blast Radius 💥
              </button>
            </div>

            {blastResult && (
              <div className="p-4 rounded-lg bg-slate-950/80 border border-red-500/40 font-mono text-xs space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">Target: <strong className="text-white">{blastResult.target_entity}</strong></span>
                  <span className="px-2.5 py-1 rounded bg-red-500/20 text-red-300 font-bold">
                    Impact Score: {blastResult.impact_score}%
                  </span>
                </div>
                <div className="space-y-1">
                  <span className="text-slate-500 text-[11px] block">Impacted Sectors:</span>
                  <div className="flex flex-wrap gap-1">
                    {blastResult.impacted_sectors.map((sec, idx) => (
                      <span key={idx} className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                        {sec}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="space-y-1">
                  <span className="text-slate-500 text-[11px] block">Downstream Attack Paths:</span>
                  {blastResult.attack_paths.map((path, idx) => (
                    <div key={idx} className="p-2 rounded bg-slate-900 text-[11px] text-slate-300 flex items-center gap-1.5">
                      {path.join(" ➔ ")}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 8: MODEL ROUTING GATEWAY                                        */}
      {/* =================================================================== */}
      {activeTab === "models" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {modelRoutes.map((route) => (
              <div
                key={route.task_type}
                className="cyber-card rounded-xl p-5 border border-slate-800 space-y-3"
              >
                <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                  <span className="font-mono text-sm font-bold text-white uppercase">{route.task_type}</span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    CB: {route.circuit_breaker_status}
                  </span>
                </div>
                <div className="space-y-1 font-mono text-xs text-slate-400">
                  <div className="flex justify-between">
                    <span>Primary Model:</span>
                    <span className="text-cyan-300 font-bold">{route.primary_model}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Fallback Model:</span>
                    <span className="text-slate-300">{route.fallback_model}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Latency SLA:</span>
                    <span className="text-slate-200">&lt;{route.max_latency_sla_ms}ms</span>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Model Query Router Tester */}
          <div className="cyber-card rounded-xl p-5 border border-cyan-500/30 bg-slate-900/80 space-y-4">
            <span className="text-xs font-mono text-cyan-400 font-semibold uppercase block">
              Inference Router Gateway Tester
            </span>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <input
                type="text"
                placeholder="Enter prompt to route..."
                value={routerPrompt}
                onChange={(e) => setRouterPrompt(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono sm:col-span-2"
              />
              <select
                value={routerTaskType}
                onChange={(e) => setRouterTaskType(e.target.value)}
                className="bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
              >
                <option value="entity_extraction">Entity Extraction</option>
                <option value="classification">Classification</option>
                <option value="summarization">Summarization</option>
                <option value="deep_research">Deep Research</option>
              </select>
            </div>

            <div className="flex items-center justify-between pt-1">
              <label className="flex items-center gap-2 font-mono text-xs text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={routerLatencyPriority}
                  onChange={(e) => setRouterLatencyPriority(e.target.checked)}
                  className="accent-cyan-500"
                />
                Enforce Ultra-Low Latency SLA Priority (&lt;50ms)
              </label>

              <button
                onClick={handleRouteInference}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold whitespace-nowrap transition-colors"
              >
                Route Query ⚡
              </button>
            </div>

            {routeResult && (
              <div className="p-4 rounded-lg bg-slate-950/80 border border-cyan-500/40 font-mono text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300">Selected Model: <strong className="text-cyan-300">{routeResult.selected_model}</strong></span>
                  <span className="text-emerald-400 font-bold">{routeResult.latency_ms}ms execution</span>
                </div>
                <div className="text-slate-400">Provider: <strong className="text-white">{routeResult.provider}</strong></div>
                <p className="text-[11px] text-slate-500">{routeResult.routed_reason}</p>
                <div className="p-2.5 rounded bg-slate-900 text-slate-300 text-[11px]">
                  {routeResult.simulated_result}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 9: AUTOMATED EVALUATION & SOURCE QUALITY LEARNING               */}
      {/* =================================================================== */}
      {activeTab === "quality" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Automated Benchmark Runs */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white font-mono uppercase">Pipeline Evaluation Benchmarks</h3>
                <button
                  onClick={() => handleTriggerBenchmark("Advisory Taxonomy Classification")}
                  className="text-xs font-mono text-purple-400 hover:underline"
                >
                  Run Benchmark ⚡
                </button>
              </div>

              <div className="space-y-3">
                {benchmarks.map((b) => (
                  <div
                    key={b.id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{b.suite_name}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 font-bold">
                        F1: {(b.f1_score * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="flex justify-between text-slate-400 text-[11px]">
                      <span>Precision: {(b.precision_score * 100).toFixed(1)}%</span>
                      <span>Recall: {(b.recall_score * 100).toFixed(1)}%</span>
                      <span>p95 Latency: {b.p95_latency_ms}ms</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Bayesian Source Credibility Leaderboard */}
            <div className="cyber-card rounded-xl p-5 border border-slate-800 space-y-4">
              <div className="border-b border-slate-800 pb-3">
                <h3 className="text-sm font-bold text-white font-mono uppercase">Bayesian Source Credibility Tiers</h3>
              </div>

              <div className="space-y-3">
                {reputations.map((src) => (
                  <div
                    key={src.id}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white line-clamp-1">{src.source_name}</span>
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded uppercase font-bold ${
                          src.tier === "gold"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                            : "bg-slate-800 text-slate-300"
                        }`}
                      >
                        {src.tier} • {src.reputation_score.toFixed(1)} pts
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Corroboration: {(src.corroboration_rate * 100).toFixed(1)}%</span>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleFeedbackReputation(src.source_name, true)}
                          className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 hover:bg-emerald-500/30"
                        >
                          + Corroborate
                        </button>
                        <button
                          onClick={() => handleFeedbackReputation(src.source_name, false)}
                          className="px-2 py-0.5 rounded bg-red-500/20 text-red-300 hover:bg-red-500/30"
                        >
                          - Flag FP
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
