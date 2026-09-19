"use client";

import React, { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  createGraphRelationship,
  FALLBACK_GRAPH_EDGES,
  FALLBACK_GRAPH_NODES,
  FALLBACK_GRAPH_STATS,
  getGraphPath,
  getGraphRelationships,
  getGraphStats,
  getGraphSubgraph,
} from "../../lib/api";
import {
  GraphEdge,
  GraphNode,
  GraphPath,
  GraphStats,
  GraphSubgraph,
  RelationshipItem,
} from "../../lib/types";

// Type-to-color mapping for cybersecurity ontology
const ENTITY_CONFIG: Record<
  string,
  { label: string; color: string; stroke: string; bg: string; text: string; icon: string }
> = {
  threat_actor: {
    label: "Threat Actor",
    color: "#d97706",
    stroke: "stroke-amber-600",
    bg: "bg-amber-100 border-amber-300",
    text: "text-amber-800",
    icon: "☠",
  },
  malware: {
    label: "Malware",
    color: "#b91c1c",
    stroke: "stroke-red-600",
    bg: "bg-red-100 border-red-300",
    text: "text-red-800",
    icon: "☣",
  },
  cve: {
    label: "CVE / Vuln",
    color: "#7c3aed",
    stroke: "stroke-purple-600",
    bg: "bg-purple-100 border-purple-300",
    text: "text-purple-800",
    icon: "🛡",
  },
  tool: {
    label: "Tool / Utility",
    color: "#2563eb",
    stroke: "stroke-blue-600",
    bg: "bg-blue-100 border-blue-300",
    text: "text-blue-800",
    icon: "🔧",
  },
  technique: {
    label: "Technique",
    color: "#0891b2",
    stroke: "stroke-cyan-600",
    bg: "bg-cyan-100 border-cyan-300",
    text: "text-cyan-800",
    icon: "🎯",
  },
  product: {
    label: "Product / Asset",
    color: "#2d7a4f",
    stroke: "stroke-emerald-600",
    bg: "bg-emerald-100 border-emerald-300",
    text: "text-emerald-800",
    icon: "📦",
  },
  vendor: {
    label: "Vendor",
    color: "#059669",
    stroke: "stroke-emerald-700",
    bg: "bg-emerald-100 border-emerald-300",
    text: "text-emerald-800",
    icon: "🏢",
  },
  organization: {
    label: "Organization",
    color: "#9333ea",
    stroke: "stroke-purple-700",
    bg: "bg-purple-100 border-purple-300",
    text: "text-purple-800",
    icon: "🏛",
  },
  person: {
    label: "Person",
    color: "#0284c7",
    stroke: "stroke-sky-600",
    bg: "bg-sky-100 border-sky-300",
    text: "text-sky-800",
    icon: "👤",
  },
  domain: {
    label: "Domain",
    color: "#0d9488",
    stroke: "stroke-teal-600",
    bg: "bg-teal-100 border-teal-300",
    text: "text-teal-800",
    icon: "🌐",
  },
  ip: {
    label: "IP Address",
    color: "#4f46e5",
    stroke: "stroke-indigo-600",
    bg: "bg-indigo-100 border-indigo-300",
    text: "text-indigo-800",
    icon: "🔢",
  },
  location: {
    label: "Location",
    color: "#ea580c",
    stroke: "stroke-orange-600",
    bg: "bg-orange-100 border-orange-300",
    text: "text-orange-800",
    icon: "📍",
  },
  technology: {
    label: "Technology",
    color: "#c2821a",
    stroke: "stroke-amber-700",
    bg: "bg-amber-100 border-amber-300",
    text: "text-amber-800",
    icon: "💻",
  },
  cwe: {
    label: "CWE Weakness",
    color: "#dc2626",
    stroke: "stroke-rose-600",
    bg: "bg-rose-100 border-rose-300",
    text: "text-rose-800",
    icon: "⚠️",
  },
  default: {
    label: "Entity",
    color: "#68655b",
    stroke: "stroke-neutral-500",
    bg: "bg-neutral-100 border-neutral-300",
    text: "text-neutral-700",
    icon: "◆",
  },
};

function getEntityConfig(type: string) {
  const norm = (type || "").toLowerCase().replace(/[\s-]/g, "_");
  return ENTITY_CONFIG[norm] || ENTITY_CONFIG.default;
}

export default function KnowledgeGraphPage() {
  // Navigation & view states
  const [activeTab, setActiveTab] = useState<"explorer" | "pathfinder" | "table">("explorer");
  const [centerEntityId, setCenterEntityId] = useState<number>(34); // Default to Microsoft (top hub ID 34)
  const [hopDepth, setHopDepth] = useState<number>(2);
  const [maxLimit, setMaxLimit] = useState<number>(40);
  const [filterType, setFilterType] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState<string>("");

  // Data states
  const [subgraph, setSubgraph] = useState<GraphSubgraph>({
    center_id: 34,
    depth: 2,
    nodes: FALLBACK_GRAPH_NODES,
    edges: FALLBACK_GRAPH_EDGES,
  });
  const [graphStats, setGraphStats] = useState<GraphStats>(FALLBACK_GRAPH_STATS);
  const [allRelationships, setAllRelationships] = useState<RelationshipItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // Inspector & selection states
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);

  // Path Finder states
  const [pathSourceId, setPathSourceId] = useState<number>(34); // Microsoft
  const [pathTargetId, setPathTargetId] = useState<number>(240); // Windows
  const [pathResult, setPathResult] = useState<GraphPath | null>(null);
  const [pathSearching, setPathSearching] = useState<boolean>(false);
  const [pathError, setPathError] = useState<string | null>(null);

  // Assert Relationship Modal
  const [assertModalOpen, setAssertModalOpen] = useState<boolean>(false);
  const [assertSourceId, setAssertSourceId] = useState<number>(34);
  const [assertVerb, setAssertVerb] = useState<string>("affects");
  const [assertTargetId, setAssertTargetId] = useState<number>(240);
  const [assertConfidence, setAssertConfidence] = useState<number>(0.95);
  const [assertSubmitting, setAssertSubmitting] = useState<boolean>(false);
  const [assertSuccessMsg, setAssertSuccessMsg] = useState<string | null>(null);

  // Load Graph Data
  const loadGraph = async (centerId: number, depth: number) => {
    setLoading(true);
    try {
      const [subRes, statsRes, relsRes] = await Promise.all([
        getGraphSubgraph(centerId, depth, maxLimit),
        getGraphStats(),
        getGraphRelationships({ limit: 100 }),
      ]);
      setSubgraph(subRes);
      setGraphStats(statsRes);
      setAllRelationships(relsRes);
      // Auto-select centered node
      const centerNode = subRes.nodes.find((n) => n.id === centerId) || subRes.nodes[0];
      if (centerNode) setSelectedNode(centerNode);
    } catch (err) {
      console.error("Failed to load knowledge graph data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadGraph(centerEntityId, hopDepth);
  }, [centerEntityId, hopDepth, maxLimit]);

  // Execute BFS Path Finding
  const handleFindPath = async () => {
    if (pathSourceId === pathTargetId) {
      setPathError("Source and target entities must be different.");
      return;
    }
    setPathSearching(true);
    setPathError(null);
    try {
      const res = await getGraphPath(pathSourceId, pathTargetId, 4);
      if (res) {
        setPathResult(res);
        // Switch to explorer view and highlight nodes in path
        setActiveTab("pathfinder");
      } else {
        setPathError(`No multi-hop path found between Entity #${pathSourceId} and #${pathTargetId}.`);
        setPathResult(null);
      }
    } catch (err: any) {
      setPathError(err.message || "Failed to traverse path.");
      setPathResult(null);
    } finally {
      setPathSearching(false);
    }
  };

  // Submit Manual Relationship Edge
  const handleAssertRelationship = async (e: React.FormEvent) => {
    e.preventDefault();
    setAssertSubmitting(true);
    setAssertSuccessMsg(null);
    try {
      await createGraphRelationship({
        source_entity_id: assertSourceId,
        relationship: assertVerb.trim().toLowerCase(),
        target_entity_id: assertTargetId,
        confidence: Number(assertConfidence),
      });
      setAssertSuccessMsg("Relationship asserted successfully!");
      // Reload current graph view
      await loadGraph(centerEntityId, hopDepth);
      setTimeout(() => {
        setAssertModalOpen(false);
        setAssertSuccessMsg(null);
      }, 1200);
    } catch (err: any) {
      alert("Error creating relationship: " + err.message);
    } finally {
      setAssertSubmitting(false);
    }
  };

  // Filtered nodes
  const displayNodes = useMemo(() => {
    return subgraph.nodes.filter((node) => {
      const matchesType = filterType === "all" || node.entity_type.toLowerCase() === filterType;
      const matchesSearch =
        !searchTerm ||
        node.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        node.entity_type.toLowerCase().includes(searchTerm.toLowerCase());
      return matchesType && matchesSearch;
    });
  }, [subgraph.nodes, filterType, searchTerm]);

  const displayNodeIds = useMemo(() => new Set(displayNodes.map((n) => n.id)), [displayNodes]);

  // Filtered edges that connect displayed nodes
  const displayEdges = useMemo(() => {
    return subgraph.edges.filter(
      (edge) => displayNodeIds.has(edge.source_id) && displayNodeIds.has(edge.target_id)
    );
  }, [subgraph.edges, displayNodeIds]);

  // Path edges set for highlighting
  const pathEdgeIds = useMemo(() => {
    if (!pathResult) return new Set<number>();
    return new Set(pathResult.edges.map((e) => e.id));
  }, [pathResult]);

  const pathNodeIds = useMemo(() => {
    if (!pathResult) return new Set<number>();
    return new Set(pathResult.nodes.map((n) => n.id));
  }, [pathResult]);

  // Dynamic Layout Coordinate Calculation
  // Places center node at center (450, 270), and radiating concentric rings based on distance / hop
  const nodePositions = useMemo(() => {
    const width = 900;
    const height = 540;
    const cx = width / 2;
    const cy = height / 2;
    const pos: Record<number, { x: number; y: number; isCenter: boolean }> = {};

    const centerNode = displayNodes.find((n) => n.id === centerEntityId) || displayNodes[0];
    if (centerNode) {
      pos[centerNode.id] = { x: cx, y: cy, isCenter: true };
    }

    const otherNodes = displayNodes.filter((n) => !centerNode || n.id !== centerNode.id);

    // Group other nodes into Hop 1 (direct neighbors) and Hop 2+
    const directNeighborIds = new Set<number>();
    if (centerNode) {
      displayEdges.forEach((e) => {
        if (e.source_id === centerNode.id) directNeighborIds.add(e.target_id);
        if (e.target_id === centerNode.id) directNeighborIds.add(e.source_id);
      });
    }

    const ring1 = otherNodes.filter((n) => directNeighborIds.has(n.id));
    const ring2 = otherNodes.filter((n) => !directNeighborIds.has(n.id));

    // Arrange Ring 1 (Radius 150)
    const r1 = Math.min(170, Math.min(width, height) * 0.32);
    ring1.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / Math.max(1, ring1.length) - Math.PI / 2;
      pos[node.id] = {
        x: cx + r1 * Math.cos(angle),
        y: cy + r1 * Math.sin(angle),
        isCenter: false,
      };
    });

    // Arrange Ring 2 (Radius 240)
    const r2 = Math.min(235, Math.min(width, height) * 0.44);
    ring2.forEach((node, i) => {
      const angle = (2 * Math.PI * i) / Math.max(1, ring2.length) - Math.PI / 4;
      pos[node.id] = {
        x: cx + r2 * Math.cos(angle),
        y: cy + r2 * Math.sin(angle),
        isCenter: false,
      };
    });

    return pos;
  }, [displayNodes, displayEdges, centerEntityId]);

  return (
    <div className="space-y-6">
      {/* =====================================================================
          Header & Section Title
      ===================================================================== */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
              IMPLEMENT.md Section 27
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
              RELATIONAL GRAPH ENGINE
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
            <span>Knowledge Graph Explorer</span>
            <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400 font-normal">
              {subgraph.nodes.length} Nodes • {subgraph.edges.length} Active Edges
            </span>
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Visualize cyber threat topologies, multi-hop actor-to-asset pathways, and automated
            entity linkages synthesized from ingested intelligence feeds.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setAssertModalOpen(true)}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-semibold font-mono text-xs shadow-lg shadow-cyan-500/20 transition-all"
          >
            <span>+ Assert Relationship</span>
          </button>
          <button
            onClick={() => loadGraph(centerEntityId, hopDepth)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 font-mono text-xs transition-colors"
            title="Refresh Graph"
          >
            <span>↻ Reload</span>
          </button>
        </div>
      </div>

      {/* =====================================================================
          Global Graph Topology Statistics
      ===================================================================== */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl cyber-glass border border-slate-800/80">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Total Entities
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {graphStats.total_nodes}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Across {Object.keys(graphStats.entity_types).length} ontology classes
          </div>
        </div>

        <div className="p-4 rounded-xl cyber-glass border border-slate-800/80">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Total Relationships
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">
            {graphStats.total_edges}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Co-occurrence & ATT&CK edges
          </div>
        </div>

        <div className="p-4 rounded-xl cyber-glass border border-slate-800/80">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Graph Density
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {graphStats.total_nodes > 1
              ? ((2 * graphStats.total_edges) / (graphStats.total_nodes * (graphStats.total_nodes - 1))).toFixed(3)
              : "0.000"}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">Connectedness index</div>
        </div>

        <div className="p-4 rounded-xl cyber-glass border border-slate-800/80">
          <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
            Top Central Hub
          </div>
          <div className="text-lg font-bold font-mono text-purple-400 mt-1 truncate">
            {graphStats.top_hubs[0]?.name || "APT29"}
          </div>
          <div className="text-[10px] text-slate-500 mt-1">
            Degree: {graphStats.top_hubs[0]?.degree || 4} linkages
          </div>
        </div>
      </div>

      {/* =====================================================================
          Primary Navigation Tabs & Controls
      ===================================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 p-1 rounded-lg bg-slate-900/90 border border-slate-800 self-start">
          <button
            onClick={() => setActiveTab("explorer")}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === "explorer"
                ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>🕸 Subgraph Explorer</span>
          </button>

          <button
            onClick={() => setActiveTab("pathfinder")}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === "pathfinder"
                ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>⚡ Path Finder (BFS)</span>
            {pathResult && (
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab("table")}
            className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-xs font-mono transition-all ${
              activeTab === "table"
                ? "bg-cyan-500/20 text-cyan-300 font-semibold border border-cyan-500/30"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>☰ Relationship Table</span>
          </button>
        </div>

        {/* Quick Hub Badges */}
        <div className="hidden xl:flex items-center gap-2 text-xs font-mono">
          <span className="text-slate-500">Quick Focus:</span>
          {graphStats.top_hubs.slice(0, 4).map((hub) => (
            <button
              key={hub.id}
              onClick={() => setCenterEntityId(hub.id)}
              className={`px-2 py-0.5 rounded border text-[11px] transition-colors ${
                centerEntityId === hub.id
                  ? "bg-cyan-500/20 border-cyan-400 text-cyan-300"
                  : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700"
              }`}
            >
              {hub.name} ({hub.degree})
            </button>
          ))}
        </div>
      </div>

      {/* =====================================================================
          PATH FINDER CONTROL PANEL (When in Pathfinder Mode)
      ===================================================================== */}
      {activeTab === "pathfinder" && (
        <div className="p-4 rounded-xl cyber-glass border border-cyan-500/30 bg-cyan-950/10 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-mono text-sm font-semibold">
                Multi-Hop Breadth-First Search (BFS) Traversal
              </span>
              <span className="text-xs text-slate-400">
                • Discovers the shortest directional attack chain between entities
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <div className="sm:col-span-5">
              <label className="block text-[11px] font-mono text-slate-400 mb-1">
                SOURCE ENTITY
              </label>
              <select
                value={pathSourceId}
                onChange={(e) => setPathSourceId(Number(e.target.value))}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              >
                {FALLBACK_GRAPH_NODES.map((n) => (
                  <option key={n.id} value={n.id}>
                    #{n.id} - {n.name} ({n.entity_type})
                  </option>
                ))}
              </select>
            </div>

            <div className="sm:col-span-2 flex items-center justify-center text-cyan-400 text-lg font-bold pb-2">
              ➔
            </div>

            <div className="sm:col-span-5">
              <label className="block text-[11px] font-mono text-slate-400 mb-1">
                TARGET ENTITY
              </label>
              <select
                value={pathTargetId}
                onChange={(e) => setPathTargetId(Number(e.target.value))}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
              >
                {FALLBACK_GRAPH_NODES.map((n) => (
                  <option key={n.id} value={n.id}>
                    #{n.id} - {n.name} ({n.entity_type})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between pt-1">
            <button
              onClick={handleFindPath}
              disabled={pathSearching}
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs transition-colors flex items-center gap-2"
            >
              {pathSearching ? "Traversing Graph..." : "⚡ Trace Attack Pathway"}
            </button>

            {pathResult && (
              <span className="text-xs font-mono text-emerald-400">
                ✓ Path Found: {pathResult.length} hops ({pathResult.nodes.length} entities)
              </span>
            )}
          </div>

          {pathError && (
            <div className="p-3 rounded-lg bg-red-950/30 border border-red-500/30 text-red-400 text-xs font-mono">
              ⚠ {pathError}
            </div>
          )}

          {/* Visual Path Breadcrumb */}
          {pathResult && pathResult.nodes.length > 0 && (
            <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                Extracted Multi-Hop Chain:
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {pathResult.nodes.map((node, idx) => {
                  const edge = pathResult.edges[idx];
                  const cfg = getEntityConfig(node.entity_type);
                  return (
                    <React.Fragment key={node.id}>
                      <button
                        onClick={() => {
                          setSelectedNode(node);
                          setCenterEntityId(node.id);
                        }}
                        className={`flex items-center gap-1.5 px-3 py-1 rounded-lg border text-xs font-mono transition-all hover:scale-105 ${cfg.bg} ${cfg.text}`}
                      >
                        <span>{cfg.icon}</span>
                        <span className="font-semibold">{node.name}</span>
                        <span className="text-[10px] opacity-75">({node.entity_type})</span>
                      </button>

                      {edge && (
                        <div className="flex items-center gap-1 text-[11px] font-mono text-cyan-300">
                          <span className="text-slate-600">──</span>
                          <span className="px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                            {edge.relationship}
                          </span>
                          <span className="text-slate-600">──➔</span>
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* =====================================================================
          MAIN GRAPH CANVAS & INSPECTOR GRID
      ===================================================================== */}
      {activeTab !== "table" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left / Center: Interactive SVG Graph Canvas */}
          <div className="lg:col-span-8 flex flex-col rounded-xl cyber-glass border border-slate-800/90 overflow-hidden">
            {/* Canvas Header & Filter Bar */}
            <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/60 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Expansion Hops:</span>
                {[1, 2, 3].map((d) => (
                  <button
                    key={d}
                    onClick={() => setHopDepth(d)}
                    className={`px-2.5 py-1 rounded font-mono text-xs transition-colors ${
                      hopDepth === d
                        ? "bg-cyan-500 text-slate-950 font-bold"
                        : "bg-slate-800 text-slate-300 hover:bg-slate-700"
                    }`}
                  >
                    {d} Hop{d > 1 ? "s" : ""}
                  </button>
                ))}
              </div>

              {/* Entity Type Filter */}
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Filter:</span>
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="all">All Entity Types</option>
                  <option value="threat_actor">Threat Actors</option>
                  <option value="malware">Malware</option>
                  <option value="cve">CVEs</option>
                  <option value="technique">Techniques</option>
                  <option value="tool">Tools</option>
                  <option value="product">Products</option>
                  <option value="organization">Organizations</option>
                </select>
              </div>

              {/* Live Search */}
              <div className="relative">
                <input
                  type="text"
                  placeholder="Filter nodes..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-36 sm:w-44"
                />
                {searchTerm && (
                  <button
                    onClick={() => setSearchTerm("")}
                    className="absolute right-2 top-1.5 text-xs text-slate-400 hover:text-white"
                  >
                    ✕
                  </button>
                )}
              </div>
            </div>

            {/* SVG Visual Graph Container */}
            <div className="relative w-full h-[540px] bg-[#050810] flex items-center justify-center select-none overflow-hidden">
              {loading ? (
                <div className="flex flex-col items-center gap-2 font-mono text-xs text-cyan-400">
                  <span className="animate-spin text-lg">⚙</span>
                  <span>Synthesizing Relational Subgraph...</span>
                </div>
              ) : displayNodes.length === 0 ? (
                <div className="text-center font-mono text-xs text-slate-500">
                  No nodes match current filter criteria.
                </div>
              ) : (
                <svg
                  viewBox="0 0 900 540"
                  className="w-full h-full"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  {/* SVG Definitions for Markers & Filters */}
                  <defs>
                    {/* Default Arrow */}
                    <marker
                      id="arrow-default"
                      viewBox="0 0 10 10"
                      refX="22"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
                    </marker>

                    {/* Highlighted Arrow */}
                    <marker
                      id="arrow-active"
                      viewBox="0 0 10 10"
                      refX="22"
                      refY="5"
                      markerWidth="6"
                      markerHeight="6"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#06b6d4" />
                    </marker>

                    {/* Path Arrow */}
                    <marker
                      id="arrow-path"
                      viewBox="0 0 10 10"
                      refX="22"
                      refY="5"
                      markerWidth="7"
                      markerHeight="7"
                      orient="auto-start-reverse"
                    >
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#f59e0b" />
                    </marker>

                    {/* Node Glow Filter */}
                    <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feComposite in="SourceGraphic" in2="blur" operator="over" />
                    </filter>
                  </defs>

                  {/* Background Grid Pattern */}
                  <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                    <circle cx="1" cy="1" r="1" fill="#1e293b" opacity="0.6" />
                  </pattern>
                  <rect width="900" height="540" fill="url(#grid)" />

                  {/* Edges Layer */}
                  <g className="edges">
                    {displayEdges.map((edge) => {
                      const src = nodePositions[edge.source_id];
                      const dst = nodePositions[edge.target_id];
                      if (!src || !dst) return null;

                      const isSelected = selectedEdge?.id === edge.id;
                      const isPath = pathEdgeIds.has(edge.id);

                      // Calculate midpoint for edge label badge
                      const midX = (src.x + dst.x) / 2;
                      const midY = (src.y + dst.y) / 2;

                      return (
                        <g
                          key={edge.id}
                          onClick={() => {
                            setSelectedEdge(edge);
                            setSelectedNode(null);
                          }}
                          className="cursor-pointer group"
                        >
                          {/* Invisible thicker hit-box */}
                          <line
                            x1={src.x}
                            y1={src.y}
                            x2={dst.x}
                            y2={dst.y}
                            stroke="transparent"
                            strokeWidth="18"
                          />
                          {/* Visible line */}
                          <line
                            x1={src.x}
                            y1={src.y}
                            x2={dst.x}
                            y2={dst.y}
                            stroke={
                              isPath
                                ? "#f59e0b"
                                : isSelected
                                ? "#06b6d4"
                                : "#334155"
                            }
                            strokeWidth={isPath ? 3 : isSelected ? 2.5 : 1.5}
                            strokeDasharray={isPath ? "6,4" : undefined}
                            markerEnd={
                              isPath
                                ? "url(#arrow-path)"
                                : isSelected
                                ? "url(#arrow-active)"
                                : "url(#arrow-default)"
                            }
                            className="transition-all"
                          />

                          {/* Relationship Badge in Midpoint */}
                          <g transform={`translate(${midX}, ${midY})`}>
                            <rect
                              x="-30"
                              y="-8"
                              width="60"
                              height="16"
                              rx="8"
                              fill="#0b0f19"
                              stroke={isPath ? "#f59e0b" : isSelected ? "#06b6d4" : "#1e293b"}
                              strokeWidth="1"
                            />
                            <text
                              x="0"
                              y="3"
                              textAnchor="middle"
                              fontSize="9"
                              fontFamily="monospace"
                              fill={isPath ? "#fbbf24" : isSelected ? "#67e8f9" : "#94a3b8"}
                              fontWeight="bold"
                            >
                              {edge.relationship}
                            </text>
                          </g>
                        </g>
                      );
                    })}
                  </g>

                  {/* Nodes Layer */}
                  <g className="nodes">
                    {displayNodes.map((node) => {
                      const pos = nodePositions[node.id];
                      if (!pos) return null;

                      const isCenter = node.id === centerEntityId;
                      const isSelected = selectedNode?.id === node.id;
                      const isPathNode = pathNodeIds.has(node.id);
                      const cfg = getEntityConfig(node.entity_type);

                      const radius = isCenter ? 24 : 18;

                      return (
                        <g
                          key={node.id}
                          transform={`translate(${pos.x}, ${pos.y})`}
                          onClick={() => {
                            setSelectedNode(node);
                            setSelectedEdge(null);
                          }}
                          onDoubleClick={() => {
                            setCenterEntityId(node.id);
                            setSelectedNode(node);
                          }}
                          className="cursor-pointer group"
                        >
                          {/* Pulsing Outer Halo for Center or Path Nodes */}
                          {(isCenter || isPathNode || isSelected) && (
                            <circle
                              r={radius + 7}
                              fill="none"
                              stroke={isCenter ? "#06b6d4" : isPathNode ? "#f59e0b" : cfg.color}
                              strokeWidth="1.5"
                              strokeDasharray="4,3"
                              opacity="0.8"
                              className="animate-spin"
                              style={{ transformOrigin: "0 0", animationDuration: "12s" }}
                            />
                          )}

                          {/* Node Main Circle */}
                          <circle
                            r={radius}
                            fill="#090d16"
                            stroke={isSelected ? "#ffffff" : cfg.color}
                            strokeWidth={isCenter ? 3 : 2}
                            filter="url(#glow)"
                            className="group-hover:stroke-white transition-colors"
                          />

                          {/* Node Icon / Symbol */}
                          <text
                            x="0"
                            y={isCenter ? 5 : 4}
                            textAnchor="middle"
                            fontSize={isCenter ? 14 : 11}
                            fill={cfg.color}
                            fontWeight="bold"
                            pointerEvents="none"
                          >
                            {cfg.icon}
                          </text>

                          {/* Degree Badge Pill */}
                          <g transform={`translate(${radius - 4}, ${-radius + 4})`}>
                            <circle r="6" fill="#0f172a" stroke="#334155" strokeWidth="1" />
                            <text
                              x="0"
                              y="2.5"
                              textAnchor="middle"
                              fontSize="7"
                              fontFamily="monospace"
                              fill="#94a3b8"
                              fontWeight="bold"
                            >
                              {node.degree}
                            </text>
                          </g>

                          {/* Name Label with Dark Background */}
                          <g transform={`translate(0, ${radius + 14})`}>
                            <rect
                              x={-Math.max(32, node.name.length * 3.8)}
                              y="-8"
                              width={Math.max(64, node.name.length * 7.6)}
                              height="16"
                              rx="4"
                              fill="#090d16"
                              fillOpacity="0.9"
                              stroke={isSelected ? "#06b6d4" : "#1e293b"}
                              strokeWidth="0.8"
                            />
                            <text
                              x="0"
                              y="3"
                              textAnchor="middle"
                              fontSize="9.5"
                              fontFamily="monospace"
                              fill={isSelected ? "#ffffff" : "#e2e8f0"}
                              fontWeight={isCenter || isSelected ? "bold" : "normal"}
                            >
                              {node.name.length > 16 ? node.name.slice(0, 14) + "…" : node.name}
                            </text>
                          </g>
                        </g>
                      );
                    })}
                  </g>
                </svg>
              )}

              {/* Canvas Corner Legend */}
              <div className="absolute bottom-3 left-3 p-2 rounded-lg bg-slate-950/85 border border-slate-800 text-[10px] font-mono text-slate-400 space-y-1 backdrop-blur pointer-events-none">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400" />
                  <span>Center Node (Double-click to re-center)</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  <span>Threat Actor</span>
                  <span className="w-2 h-2 rounded-full bg-red-400 ml-1" />
                  <span>Malware</span>
                  <span className="w-2 h-2 rounded-full bg-purple-400 ml-1" />
                  <span>CVE</span>
                  <span className="w-2 h-2 rounded-full bg-cyan-400 ml-1" />
                  <span>Technique</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right: Selected Node / Edge Detail Inspector */}
          <div className="lg:col-span-4 flex flex-col rounded-xl cyber-glass border border-slate-800/90 overflow-hidden">
            <div className="p-3.5 border-b border-slate-800/80 bg-slate-900/60 flex items-center justify-between">
              <span className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold flex items-center gap-2">
                <span>🔍</span> Inspector Drawer
              </span>
              {selectedNode && (
                <button
                  onClick={() => setCenterEntityId(selectedNode.id)}
                  className="px-2.5 py-1 rounded text-[11px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 hover:bg-cyan-500/30 transition-colors"
                >
                  Make Center
                </button>
              )}
            </div>

            <div className="p-4 flex-1 overflow-y-auto space-y-5 text-xs font-mono">
              {selectedNode ? (
                <>
                  {/* Node Profile */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span
                        className={`px-2.5 py-0.5 rounded border text-[11px] font-bold ${
                          getEntityConfig(selectedNode.entity_type).bg
                        } ${getEntityConfig(selectedNode.entity_type).text}`}
                      >
                        {getEntityConfig(selectedNode.entity_type).icon}{" "}
                        {getEntityConfig(selectedNode.entity_type).label}
                      </span>
                      <span className="text-slate-500 text-[11px]">ID #{selectedNode.id}</span>
                    </div>

                    <h3 className="text-base font-bold text-white tracking-tight">
                      {selectedNode.name}
                    </h3>
                    <div className="text-[11px] text-slate-400">
                      Normalized: <code className="text-cyan-300">{selectedNode.normalized_name}</code>
                    </div>
                  </div>

                  {/* Connected Linkages Breakdown */}
                  <div className="space-y-2 border-t border-slate-800/80 pt-3">
                    <div className="text-[11px] uppercase tracking-wider text-slate-400 font-semibold">
                      Direct Relationships ({selectedNode.degree})
                    </div>

                    <div className="space-y-1.5 max-h-52 overflow-y-auto pr-1">
                      {subgraph.edges
                        .filter(
                          (e) => e.source_id === selectedNode.id || e.target_id === selectedNode.id
                        )
                        .map((edge) => {
                          const isOutgoing = edge.source_id === selectedNode.id;
                          const otherId = isOutgoing ? edge.target_id : edge.source_id;
                          const otherNode = subgraph.nodes.find((n) => n.id === otherId);
                          const otherCfg = otherNode ? getEntityConfig(otherNode.entity_type) : null;

                          return (
                            <div
                              key={edge.id}
                              onClick={() => {
                                setSelectedEdge(edge);
                                if (otherNode) setSelectedNode(otherNode);
                              }}
                              className="p-2 rounded bg-slate-900/80 hover:bg-slate-850 border border-slate-800 hover:border-cyan-500/40 cursor-pointer transition-colors"
                            >
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] text-cyan-400 font-bold uppercase">
                                  {isOutgoing ? `── ${edge.relationship} ➔` : `➔ ${edge.relationship} ──`}
                                </span>
                                <span className="text-[10px] text-slate-500">
                                  {(edge.confidence * 100).toFixed(0)}% conf
                                </span>
                              </div>
                              <div className="text-white text-[11px] font-semibold mt-0.5 flex items-center gap-1">
                                <span>{otherCfg?.icon}</span>
                                <span>{otherNode?.name || `Entity #${otherId}`}</span>
                              </div>
                            </div>
                          );
                        })}
                    </div>
                  </div>

                  {/* Actions & Navigation */}
                  <div className="border-t border-slate-800/80 pt-3 space-y-2">
                    <Link
                      href={`/entities/${selectedNode.id}`}
                      className="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 text-xs transition-colors"
                    >
                      <span>View Full Entity Profile</span>
                      <span>➔</span>
                    </Link>

                    <button
                      onClick={() => {
                        setPathSourceId(selectedNode.id);
                        setActiveTab("pathfinder");
                      }}
                      className="w-full flex items-center justify-center gap-2 px-3 py-1.5 rounded-lg bg-cyan-950/60 hover:bg-cyan-900/60 border border-cyan-800 text-cyan-300 text-xs transition-colors"
                    >
                      <span>Set as Path Source</span>
                    </button>
                  </div>
                </>
              ) : selectedEdge ? (
                <>
                  {/* Edge Profile */}
                  <div className="space-y-2">
                    <span className="px-2.5 py-0.5 rounded border text-[11px] font-bold bg-cyan-500/15 border-cyan-500/30 text-cyan-300">
                      RELATIONSHIP EDGE #{selectedEdge.id}
                    </span>
                    <h3 className="text-base font-bold text-white tracking-tight uppercase">
                      {selectedEdge.relationship}
                    </h3>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-500">Confidence Score:</span>
                      <span className="text-emerald-400 font-bold">
                        {(selectedEdge.confidence * 100).toFixed(1)}%
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 rounded-full h-1.5">
                      <div
                        className="bg-emerald-400 h-1.5 rounded-full"
                        style={{ width: `${selectedEdge.confidence * 100}%` }}
                      />
                    </div>
                  </div>

                  {selectedEdge.source_content_title && (
                    <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider">
                        Source Provenance
                      </div>
                      <div className="text-slate-200 text-[11px] font-semibold">
                        {selectedEdge.source_content_title}
                      </div>
                      {selectedEdge.source_content_id && (
                        <Link
                          href={`/news/${selectedEdge.source_content_id}`}
                          className="text-cyan-400 hover:underline text-[11px] block mt-1"
                        >
                          Read Source Article ➔
                        </Link>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="py-12 text-center text-slate-500 space-y-2">
                  <span className="text-2xl">🕸</span>
                  <p>Click any node or relationship edge in the graph canvas to inspect attributes.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          RELATIONSHIP TABLE VIEW
      ===================================================================== */}
      {activeTab === "table" && (
        <div className="rounded-xl cyber-glass border border-slate-800 overflow-hidden">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-bold font-mono text-white">
                All Relational Knowledge Graph Edges
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Database records in <code>entity_relationships</code> table
              </p>
            </div>
            <span className="text-xs font-mono text-slate-400">
              {allRelationships.length} Total Records
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px]">
                <tr>
                  <th className="py-3 px-4">Edge ID</th>
                  <th className="py-3 px-4">Source Entity</th>
                  <th className="py-3 px-4">Relationship Verb</th>
                  <th className="py-3 px-4">Target Entity</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Provenance</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {allRelationships.map((rel) => {
                  const srcNode = subgraph.nodes.find((n) => n.id === rel.source_entity_id) || FALLBACK_GRAPH_NODES.find((n) => n.id === rel.source_entity_id);
                  const dstNode = subgraph.nodes.find((n) => n.id === rel.target_entity_id) || FALLBACK_GRAPH_NODES.find((n) => n.id === rel.target_entity_id);
                  const srcCfg = srcNode ? getEntityConfig(srcNode.entity_type) : null;
                  const dstCfg = dstNode ? getEntityConfig(dstNode.entity_type) : null;

                  return (
                    <tr key={rel.id} className="hover:bg-slate-900/50 transition-colors">
                      <td className="py-3 px-4 text-slate-500">#{rel.id}</td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 font-semibold text-white">
                          <span>{srcCfg?.icon}</span>
                          <span>{srcNode?.name || `Entity #${rel.source_entity_id}`}</span>
                          <span className="text-[10px] text-slate-500 font-normal">
                            ({srcNode?.entity_type || "entity"})
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800 text-cyan-300 font-bold uppercase text-[10px]">
                          {rel.relationship}
                        </span>
                      </td>

                      <td className="py-3 px-4">
                        <div className="flex items-center gap-1.5 font-semibold text-white">
                          <span>{dstCfg?.icon}</span>
                          <span>{dstNode?.name || `Entity #${rel.target_entity_id}`}</span>
                          <span className="text-[10px] text-slate-500 font-normal">
                            ({dstNode?.entity_type || "entity"})
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4 text-emerald-400 font-semibold">
                        {(rel.confidence * 100).toFixed(0)}%
                      </td>

                      <td className="py-3 px-4 text-slate-400">
                        {rel.source_content_id ? (
                          <Link
                            href={`/news/${rel.source_content_id}`}
                            className="text-cyan-400 hover:underline"
                          >
                            Article #{rel.source_content_id}
                          </Link>
                        ) : (
                          <span className="text-slate-600">Manual Assertion</span>
                        )}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => {
                            setCenterEntityId(rel.source_entity_id);
                            setActiveTab("explorer");
                          }}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                        >
                          Focus Graph
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* =====================================================================
          MODAL: ASSERT NEW RELATIONSHIP
      ===================================================================== */}
      {assertModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fadeIn">
          <div className="w-full max-w-md rounded-xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold font-mono text-white flex items-center gap-2">
                <span>+</span> Assert Graph Relationship Edge
              </h3>
              <button
                onClick={() => setAssertModalOpen(false)}
                className="text-slate-400 hover:text-white font-mono text-sm"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAssertRelationship} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-400 mb-1">SOURCE ENTITY</label>
                <select
                  value={assertSourceId}
                  onChange={(e) => setAssertSourceId(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  {FALLBACK_GRAPH_NODES.map((n) => (
                    <option key={n.id} value={n.id}>
                      #{n.id} - {n.name} ({n.entity_type})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">RELATIONSHIP VERB</label>
                <select
                  value={assertVerb}
                  onChange={(e) => setAssertVerb(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="uses">uses (Threat Actor / Malware → Tool / Technique)</option>
                  <option value="operates">operates (Threat Actor → Malware)</option>
                  <option value="exploits">exploits (Malware / Actor → CVE)</option>
                  <option value="affects">affects (CVE → Product / Vendor)</option>
                  <option value="targets">targets (Actor / Malware → Org / Asset)</option>
                  <option value="implements">implements (Malware → Technique)</option>
                  <option value="associated_with">associated_with (Tool / Entity → Campaign)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">TARGET ENTITY</label>
                <select
                  value={assertTargetId}
                  onChange={(e) => setAssertTargetId(Number(e.target.value))}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-white focus:outline-none focus:border-cyan-500"
                >
                  {FALLBACK_GRAPH_NODES.map((n) => (
                    <option key={n.id} value={n.id}>
                      #{n.id} - {n.name} ({n.entity_type})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-slate-400 mb-1">
                  CONFIDENCE SCORE ({Number(assertConfidence).toFixed(2)})
                </label>
                <input
                  type="range"
                  min="0.5"
                  max="1.0"
                  step="0.05"
                  value={assertConfidence}
                  onChange={(e) => setAssertConfidence(Number(e.target.value))}
                  className="w-full accent-cyan-400"
                />
              </div>

              {assertSuccessMsg && (
                <div className="p-2 rounded bg-emerald-950/40 border border-emerald-500/30 text-emerald-400 text-center">
                  ✓ {assertSuccessMsg}
                </div>
              )}

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setAssertModalOpen(false)}
                  className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={assertSubmitting}
                  className="px-4 py-2 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-colors"
                >
                  {assertSubmitting ? "Asserting..." : "Assert Edge"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
