"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  fetchThreatIntelligence,
  getMitreGroups,
  getMitreMatrix,
  getMitreSoftware,
} from "../../lib/api";
import {
  AttackGroup,
  AttackMatrixColumn,
  AttackMatrixResponse,
  AttackSoftware,
  AttackTechnique,
  ThreatIntelligenceItem,
} from "../../lib/types";

export default function IntelligencePage() {
  const [activeTab, setActiveTab] = useState<"matrix" | "groups" | "software" | "campaigns">("matrix");
  const [matrixData, setMatrixData] = useState<AttackMatrixResponse | null>(null);
  const [groups, setGroups] = useState<AttackGroup[]>([]);
  const [software, setSoftware] = useState<AttackSoftware[]>([]);
  const [intelList, setIntelList] = useState<ThreatIntelligenceItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  // Filters & selection state
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedTacticId, setSelectedTacticId] = useState<string>("all");
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const [expandedTechniques, setExpandedTechniques] = useState<Record<string, boolean>>({});

  useEffect(() => {
    async function loadData() {
      setLoading(true);
      try {
        const [mRes, gRes, sRes, iRes] = await Promise.all([
          getMitreMatrix(),
          getMitreGroups(),
          getMitreSoftware(),
          fetchThreatIntelligence(),
        ]);
        setMatrixData(mRes);
        setGroups(gRes);
        setSoftware(sRes);
        setIntelList(iRes);
      } catch (err) {
        console.error("Failed to load MITRE intelligence:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  const toggleExpand = (techId: string) => {
    setExpandedTechniques((prev) => ({ ...prev, [techId]: !prev[techId] }));
  };

  // Filtered Matrix Columns
  const filteredMatrix: AttackMatrixColumn[] = useMemo(() => {
    if (!matrixData) return [];
    return matrixData.matrix
      .filter((col) => selectedTacticId === "all" || col.tactic.id === selectedTacticId)
      .map((col) => {
        if (!searchQuery.trim()) return col;
        const q = searchQuery.toLowerCase().trim();
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
  }, [matrixData, selectedTacticId, searchQuery]);

  // Find relationships for selected technique
  const techniqueRelations = useMemo(() => {
    if (!selectedTechnique) return null;
    const tid = selectedTechnique.id;
    const parentId = selectedTechnique.parent_technique_id;

    const usingGroups = groups.filter((g) =>
      g.associated_techniques.some((t) => t === tid || (parentId && t === parentId))
    );

    const implementingSoftware = software.filter((s) =>
      s.associated_techniques.some((t) => t === tid || (parentId && t === parentId))
    );

    return {
      threat_actors: usingGroups,
      software: implementingSoftware,
    };
  }, [selectedTechnique, groups, software]);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block mb-1">
              MITRE ATT&CK® ENTERPRISE FRAMEWORK
            </span>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Adversary Tactic & Technique Matrix
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Enterprise attack surface navigator mapping 14 tactical phases, technique mechanisms, threat actor profiles, and defensive mitigations.
            </p>
          </div>

          <div className="flex items-center gap-3 font-mono text-xs">
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
              <span className="text-cyan-400 font-bold">{matrixData?.total_tactics || 14}</span> Tactics
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
              <span className="text-emerald-400 font-bold">{matrixData?.total_techniques || 23}</span> Techniques
            </div>
            <div className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-300">
              <span className="text-amber-400 font-bold">{groups.length || 6}</span> Groups
            </div>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center gap-2 mt-6 border-b border-slate-800">
          <button
            onClick={() => setActiveTab("matrix")}
            className={`px-4 py-2.5 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all ${
              activeTab === "matrix"
                ? "border-cyan-500 text-cyan-400 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            ATT&CK Matrix ({filteredMatrix.length} Tactics)
          </button>
          <button
            onClick={() => setActiveTab("groups")}
            className={`px-4 py-2.5 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all ${
              activeTab === "groups"
                ? "border-cyan-500 text-cyan-400 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Threat Actors ({groups.length})
          </button>
          <button
            onClick={() => setActiveTab("software")}
            className={`px-4 py-2.5 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all ${
              activeTab === "software"
                ? "border-cyan-500 text-cyan-400 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Software & Malware ({software.length})
          </button>
          <button
            onClick={() => setActiveTab("campaigns")}
            className={`px-4 py-2.5 text-xs font-mono font-medium rounded-t-lg border-b-2 transition-all ${
              activeTab === "campaigns"
                ? "border-cyan-500 text-cyan-400 bg-cyan-950/20"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            Campaign Intelligence ({intelList.length})
          </button>
        </div>
      </div>

      {/* =================================================================== */}
      {/* TAB 1: MITRE ATT&CK ENTERPRISE MATRIX                               */}
      {/* =================================================================== */}
      {activeTab === "matrix" && (
        <div className="space-y-4">
          {/* Controls Bar */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-slate-900/60 border border-slate-800">
            <div className="relative w-full sm:w-80">
              <input
                type="text"
                placeholder="Search technique (e.g. T1190, Phishing, PowerShell)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-2.5 top-1.5 text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              )}
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <span className="text-xs font-mono text-slate-400">Tactic:</span>
              <select
                value={selectedTacticId}
                onChange={(e) => setSelectedTacticId(e.target.value)}
                className="bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-1.5 text-xs text-slate-300 font-mono focus:outline-none focus:border-cyan-500"
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

          {/* Matrix Columns View (Horizontal Scrollable Grid) */}
          <div className="overflow-x-auto pb-4">
            <div className="flex gap-3 min-w-max">
              {filteredMatrix.map((col) => (
                <div
                  key={col.tactic.id}
                  className="w-64 flex-shrink-0 flex flex-col rounded-xl bg-slate-900/50 border border-slate-800 overflow-hidden"
                >
                  {/* Tactic Column Header */}
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

                  {/* Technique Cards */}
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
                                      toggleExpand(pt.id);
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

                            {/* Sub-techniques Accordion */}
                            {hasSubs && isExpanded && (
                              <div className="px-2 pb-2 pt-1 border-t border-slate-800/60 space-y-1.5 bg-slate-900/40">
                                {item.subtechniques.map((st) => {
                                  const isSubSelected = selectedTechnique?.id === st.id;
                                  return (
                                    <div
                                      key={st.id}
                                      onClick={() => setSelectedTechnique(st)}
                                      className={`p-1.5 rounded cursor-pointer transition-colors text-[11px] ${
                                        isSubSelected
                                          ? "bg-cyan-500/20 text-cyan-200 border border-cyan-500/40"
                                          : "hover:bg-slate-800/60 text-slate-300"
                                      }`}
                                    >
                                      <span className="font-mono text-[10px] text-cyan-400 font-medium block">
                                        {st.id}
                                      </span>
                                      <span className="line-clamp-1">{st.name}</span>
                                    </div>
                                  );
                                })}
                              </div>
                            )}
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Selected Technique Inspector Drawer */}
          {selectedTechnique && (
            <div className="cyber-card rounded-xl p-6 border border-cyan-500/40 bg-slate-900/90 shadow-2xl space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div className="flex items-center gap-3">
                  <span className="px-2.5 py-1 rounded bg-cyan-500/20 text-cyan-300 font-mono text-xs font-bold border border-cyan-500/40">
                    {selectedTechnique.id}
                  </span>
                  <h3 className="text-lg font-bold text-white">{selectedTechnique.name}</h3>
                  {selectedTechnique.is_subtechnique && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                      Sub-technique
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  {selectedTechnique.url && (
                    <a
                      href={selectedTechnique.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="px-3 py-1 text-xs font-mono rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                    >
                      MITRE Page ↗
                    </a>
                  )}
                  <button
                    onClick={() => setSelectedTechnique(null)}
                    className="p-1 text-slate-400 hover:text-white text-xs font-mono"
                  >
                    ✕ Close
                  </button>
                </div>
              </div>

              <p className="text-sm text-slate-300 leading-relaxed">{selectedTechnique.description}</p>

              {/* Relationship Grid (Section 26 Requirements) */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 pt-2 font-mono text-xs">
                {/* 1. Threat Actors (Threat Actor -> uses -> Technique) */}
                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-amber-400 block mb-2 font-semibold uppercase text-[11px]">
                    Threat Actors (uses)
                  </span>
                  {techniqueRelations && techniqueRelations.threat_actors.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {techniqueRelations.threat_actors.map((g) => (
                        <span
                          key={g.id}
                          className="px-2 py-1 rounded bg-amber-500/10 text-amber-300 border border-amber-500/20 font-medium"
                        >
                          {g.name} ({g.id})
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500 text-[11px]">No mapped threat actors in baseline</span>
                  )}
                </div>

                {/* 2. Malware & Tools (Malware -> implements -> Technique) */}
                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-red-400 block mb-2 font-semibold uppercase text-[11px]">
                    Software / Malware (implements)
                  </span>
                  {techniqueRelations && techniqueRelations.software.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {techniqueRelations.software.map((s) => (
                        <span
                          key={s.id}
                          className="px-2 py-1 rounded bg-red-500/10 text-red-300 border border-red-500/20 font-medium"
                        >
                          {s.name} ({s.id})
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500 text-[11px]">No mapped software in baseline</span>
                  )}
                </div>

                {/* 3. Detecting Data Sources (Technique -> detected_by -> Data Source) */}
                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-cyan-400 block mb-2 font-semibold uppercase text-[11px]">
                    Telemetry Data Sources (detected_by)
                  </span>
                  {selectedTechnique.data_sources && selectedTechnique.data_sources.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {selectedTechnique.data_sources.map((ds, idx) => (
                        <span
                          key={idx}
                          className="px-2 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                        >
                          {ds}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-500 text-[11px]">Host / Network Telemetry</span>
                  )}
                </div>

                {/* 4. Target Platforms */}
                <div className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800">
                  <span className="text-emerald-400 block mb-2 font-semibold uppercase text-[11px]">
                    Target Platforms
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {selectedTechnique.platforms.map((p, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 2: THREAT ACTOR GROUPS VIEW                                     */}
      {/* =================================================================== */}
      {activeTab === "groups" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {groups.map((group) => (
            <div
              key={group.id}
              className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-amber-500/30 transition-all space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-3">
                  <span className="w-2.5 h-2.5 rounded-full bg-amber-400 status-pulse" />
                  <h3 className="text-base font-bold text-white font-mono">{group.name}</h3>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-400">
                    {group.id}
                  </span>
                </div>
                {group.url && (
                  <a
                    href={group.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-slate-400 hover:text-white"
                  >
                    MITRE ↗
                  </a>
                )}
              </div>

              {group.aliases && group.aliases.length > 0 && (
                <div className="text-xs font-mono">
                  <span className="text-slate-500 mr-2">Aliases:</span>
                  <span className="text-slate-300">{group.aliases.join(", ")}</span>
                </div>
              )}

              <p className="text-xs text-slate-400 leading-relaxed">{group.description}</p>

              <div className="space-y-2 pt-2 border-t border-slate-800/60 font-mono text-xs">
                <div>
                  <span className="text-slate-500 block mb-1 uppercase text-[10px]">
                    Techniques Used ({group.associated_techniques.length})
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {group.associated_techniques.map((tid) => (
                      <span
                        key={tid}
                        className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[11px]"
                      >
                        {tid}
                      </span>
                    ))}
                  </div>
                </div>

                {group.associated_software.length > 0 && (
                  <div>
                    <span className="text-slate-500 block mb-1 uppercase text-[10px]">
                      Software Deployed ({group.associated_software.length})
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {group.associated_software.map((sid) => (
                        <span
                          key={sid}
                          className="px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20 text-[11px]"
                        >
                          {sid}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 3: SOFTWARE & MALWARE FAMILIES VIEW                            */}
      {/* =================================================================== */}
      {activeTab === "software" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {software.map((sw) => (
            <div
              key={sw.id}
              className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-red-500/30 transition-all space-y-4"
            >
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-3">
                  <span
                    className={`w-2.5 h-2.5 rounded-full ${
                      sw.software_type === "malware" ? "bg-red-400" : "bg-purple-400"
                    }`}
                  />
                  <h3 className="text-base font-bold text-white font-mono">{sw.name}</h3>
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    {sw.id}
                  </span>
                  <span
                    className={`text-[10px] font-mono px-2 py-0.5 rounded uppercase ${
                      sw.software_type === "malware"
                        ? "bg-red-500/10 text-red-400 border border-red-500/20"
                        : "bg-purple-500/10 text-purple-400 border border-purple-500/20"
                    }`}
                  >
                    {sw.software_type}
                  </span>
                </div>
                {sw.url && (
                  <a
                    href={sw.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-slate-400 hover:text-white"
                  >
                    MITRE ↗
                  </a>
                )}
              </div>

              {sw.aliases && sw.aliases.length > 0 && (
                <div className="text-xs font-mono">
                  <span className="text-slate-500 mr-2">Aliases:</span>
                  <span className="text-slate-300">{sw.aliases.join(", ")}</span>
                </div>
              )}

              <p className="text-xs text-slate-400 leading-relaxed">{sw.description}</p>

              <div className="pt-2 border-t border-slate-800/60 font-mono text-xs">
                <span className="text-slate-500 block mb-1 uppercase text-[10px]">
                  Techniques Implemented ({sw.associated_techniques.length})
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {sw.associated_techniques.map((tid) => (
                    <span
                      key={tid}
                      className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 text-[11px]"
                    >
                      {tid}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* =================================================================== */}
      {/* TAB 4: ADVERSARY CAMPAIGNS (CORRELATED INTEL)                       */}
      {/* =================================================================== */}
      {activeTab === "campaigns" && (
        <div className="space-y-4">
          {intelList.map((item) => (
            <div
              key={item.id}
              className="cyber-card rounded-xl p-6 border border-slate-800 hover:border-amber-500/40 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800/80">
                <div className="flex items-center gap-3">
                  <span className="w-3 h-3 rounded-full bg-amber-400 status-pulse" />
                  <h3 className="text-lg font-bold text-white font-mono">{item.threat_actor}</h3>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-400 border border-amber-500/20">
                    {(item.confidence * 100).toFixed(0)}% Confidence
                  </span>
                </div>
                <span className="text-xs font-mono text-slate-500">Source: {item.source}</span>
              </div>

              <h4 className="text-base font-semibold text-slate-200 mb-2">{item.title}</h4>
              <p className="text-sm text-slate-400 mb-5 leading-relaxed">{item.summary}</p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono text-xs">
                <div>
                  <span className="text-slate-500 block mb-2 uppercase">Targeted Sectors</span>
                  <div className="flex flex-wrap gap-1.5">
                    {item.target_sectors?.map((sec, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800"
                      >
                        {sec}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block mb-2 uppercase">Associated Malware</span>
                  <div className="flex flex-wrap gap-1.5">
                    {item.malware_families?.map((m, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <span className="text-slate-500 block mb-2 uppercase">MITRE ATT&CK</span>
                  <div className="flex flex-wrap gap-1.5">
                    {item.mitre_techniques?.map((t, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
