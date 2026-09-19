"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import {
  askResearchQuestion,
  fetchRecentContent,
  getSuggestedResearchQueries,
} from "../../lib/api";
import {
  ContentItem,
  ResearchEvidenceItem,
  ResearchResponse,
  SuggestedResearchQuery,
} from "../../lib/types";
import { ContentCard } from "../../components/ContentCard";
import { ContentModal } from "../../components/ContentModal";
import { SourceQualityBadge } from "../../components/SourceQualityBadge";

export default function ResearchPage() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [researchResult, setResearchResult] = useState<ResearchResponse | null>(null);
  const [suggestedQueries, setSuggestedQueries] = useState<SuggestedResearchQuery[]>([]);
  const [selectedCitation, setSelectedCitation] = useState<number | null>(null);
  const [archiveItems, setArchiveItems] = useState<ContentItem[]>([]);
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);

  useEffect(() => {
    // Load suggested questions and paper archive
    getSuggestedResearchQueries().then(setSuggestedQueries);
    fetchRecentContent("research,paper,advisory,article", undefined, 50).then((all) => {
      setArchiveItems(all);
    });

    // Auto-run default Kubernetes question per IMPLEMENT.md Section 30
    handleRunQuery("What are the latest security developments involving Kubernetes?");
  }, []);

  const handleRunQuery = async (questionText: string) => {
    if (!questionText.trim() || loading) return;
    setQuery(questionText);
    setLoading(true);
    try {
      const res = await askResearchQuestion(questionText);
      setResearchResult(res);
      setSelectedCitation(null);
    } catch (err) {
      console.error("Research query failed:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    handleRunQuery(query);
  };

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header Banner */}
      <div className="border-b border-slate-800 pb-5">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider">
            AI DEEP RESEARCH ASSISTANT • IMPLEMENT.MD SECTION 30
          </span>
          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 uppercase font-semibold">
            9-Stage Pipeline
          </span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-black text-white tracking-tight">
          Evidence-Bounded Security Research
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
          Conduct deep multi-modal inquiries synthesized strictly from retrieved primary telemetry,
          threat advisories, and CVE data. General internal AI speculation is strictly prohibited.
        </p>
      </div>

      {/* Interactive Search Bar & Prompt Suggestions */}
      <div className="space-y-4">
        <form onSubmit={handleFormSubmit} className="flex gap-2">
          <div className="relative flex-1">
            <span className="absolute left-4 top-1/2 -translate-y-1/2 text-cyan-400 font-mono text-sm">
              ◈
            </span>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Ask an OSINT question e.g. 'What are the latest security developments involving Kubernetes?'"
              className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900/90 border border-slate-700 text-white placeholder-slate-500 text-sm font-sans focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-colors shadow-inner"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs flex items-center gap-2 transition-all shrink-0 shadow-lg shadow-cyan-500/20 disabled:opacity-50"
          >
            {loading ? (
              <>
                <span className="animate-spin inline-block">⟳</span>
                <span>Synthesizing...</span>
              </>
            ) : (
              <>
                <span>⚡</span>
                <span>Execute Research</span>
              </>
            )}
          </button>
        </form>

        {/* Suggested Quick Prompts */}
        {suggestedQueries.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-mono text-slate-500 mr-1">Suggested Inquiries:</span>
            {suggestedQueries.map((sq) => (
              <button
                key={sq.id}
                onClick={() => handleRunQuery(sq.question)}
                className="text-xs font-mono px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800 hover:border-cyan-500/40 transition-colors text-left"
              >
                &rarr; {sq.title}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Active Research Report & 9-Stage Stepper */}
      {researchResult && (
        <div className="space-y-6">
          {/* 9-Stage Pipeline Status Tracker */}
          <div className="p-4 rounded-xl cyber-card border border-slate-800 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-xs font-mono font-bold text-slate-300 uppercase">
                <span>⚡</span>
                <span>9-Stage AI Research Pipeline Telemetry</span>
              </div>
              <span className="text-xs font-mono text-cyan-400">
                Total Latency: {researchResult.execution_time_ms}ms
              </span>
            </div>

            <div className="grid grid-cols-3 sm:grid-cols-5 md:grid-cols-9 gap-2">
              {researchResult.pipeline_stages.map((stage) => (
                <div
                  key={stage.stage_number}
                  className="p-2 rounded-lg bg-slate-950/80 border border-slate-800 flex flex-col justify-between text-center"
                >
                  <div className="text-[10px] font-mono text-cyan-400 font-bold">
                    #{stage.stage_number}
                  </div>
                  <div className="text-[11px] font-mono text-slate-200 truncate my-1">
                    {stage.stage_name}
                  </div>
                  <div className="text-[9px] font-mono text-emerald-400">
                    ✓ {stage.item_count} {stage.item_count === 1 ? "item" : "items"}
                  </div>
                </div>
              ))}
            </div>

            {/* Query Expansion Terms */}
            {researchResult.expansion.expanded_terms.length > 0 && (
              <div className="pt-2 border-t border-slate-800/80 flex items-center gap-2 flex-wrap text-xs font-mono">
                <span className="text-slate-500">Expanded Concepts:</span>
                {researchResult.expansion.expanded_terms.slice(0, 10).map((t, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-violet-950/50 text-violet-300 border border-violet-500/30 text-[11px]"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Main Synthesized Report & Side-by-side Evidence Ledger */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Synthesized Brief (8 Columns) */}
            <div className="lg:col-span-7 space-y-6">
              <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-900/95 to-slate-950 border border-slate-700/80 backdrop-blur-md shadow-xl space-y-6">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-emerald-400 font-mono">◈</span>
                    <h2 className="text-base font-mono uppercase font-bold text-white tracking-wide">
                      Synthesized Intelligence Brief
                    </h2>
                  </div>
                  <span className="text-xs font-mono px-2.5 py-1 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/30">
                    {(researchResult.synthesis.confidence * 100).toFixed(0)}% Evidence Grounded
                  </span>
                </div>

                {/* Executive Answer Narrative */}
                <div className="text-slate-200 text-sm sm:text-base leading-relaxed whitespace-pre-wrap font-sans">
                  {researchResult.synthesis.executive_answer}
                </div>

                {/* Key Findings */}
                {researchResult.synthesis.key_findings.length > 0 && (
                  <div className="space-y-3 pt-4 border-t border-slate-800">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                      <span>✓</span> Key Verified Findings
                    </h3>
                    <ul className="space-y-2 text-xs sm:text-sm text-slate-300 font-sans">
                      {researchResult.synthesis.key_findings.map((finding, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-cyan-400 mt-0.5 shrink-0">•</span>
                          <span>{finding}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Threat Activity & Observed Vulnerabilities */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-4 border-t border-slate-800">
                  {researchResult.synthesis.threat_activity.length > 0 && (
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-purple-500/30 space-y-2">
                      <span className="text-xs font-mono font-bold text-purple-400 uppercase tracking-wide block">
                        ✦ Threat Actor Activity
                      </span>
                      <ul className="space-y-1 text-xs text-slate-300">
                        {researchResult.synthesis.threat_activity.map((ta, idx) => (
                          <li key={idx} className="flex items-start gap-1.5">
                            <span className="text-purple-400 shrink-0">&rarr;</span>
                            <span>{ta}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {researchResult.synthesis.vulnerabilities.length > 0 && (
                    <div className="p-4 rounded-xl bg-slate-950/70 border border-amber-500/30 space-y-2">
                      <span className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wide block">
                        ⚠ Vulnerabilities & Impact
                      </span>
                      <ul className="space-y-1 text-xs text-slate-300">
                        {researchResult.synthesis.vulnerabilities.map((vuln, idx) => (
                          <li key={idx} className="flex items-start gap-1.5">
                            <span className="text-amber-400 shrink-0">&rarr;</span>
                            <span>{vuln}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* Actionable Mitigations */}
                {researchResult.synthesis.mitigations.length > 0 && (
                  <div className="space-y-3 pt-4 border-t border-slate-800">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-1.5">
                      <span>🛡</span> Tactical Mitigations & Controls
                    </h3>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {researchResult.synthesis.mitigations.map((mit, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-emerald-400 shrink-0">&rarr;</span>
                          <span>{mit}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Strict Grounding Guardrail: Evidence Gap Analysis */}
                {researchResult.synthesis.evidence_gaps.length > 0 && (
                  <div className="p-4 rounded-xl bg-indigo-950/30 border border-indigo-500/30 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-indigo-300 uppercase tracking-wide">
                        Evidence Gap Analysis (Preserved Uncertainty)
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-900/60 text-indigo-300 border border-indigo-500/20">
                        Strict Grounding
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">
                      Per Section 30 guardrails, the AI reports unaddressed gaps rather than inventing details.
                    </p>
                    <ul className="space-y-1 text-xs text-slate-300">
                      {researchResult.synthesis.evidence_gaps.map((gap, idx) => (
                        <li key={idx} className="flex items-start gap-2">
                          <span className="text-indigo-400 shrink-0">•</span>
                          <span>{gap}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>

            {/* Citations & Evidence Ledger (5 Columns) */}
            <div className="lg:col-span-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-1.5">
                  <span>◈</span> Numbered Citations & Evidence ({researchResult.evidence.length})
                </h3>
                <span className="text-[11px] font-mono text-slate-500">Ranked by Authority</span>
              </div>

              <div className="space-y-3">
                {researchResult.evidence.map((item) => (
                  <div
                    key={item.citation_id}
                    id={`citation-${item.citation_id}`}
                    onClick={() =>
                      setSelectedCitation(
                        selectedCitation === item.citation_id ? null : item.citation_id
                      )
                    }
                    className={`p-4 rounded-xl border transition-all cursor-pointer ${
                      selectedCitation === item.citation_id
                        ? "bg-slate-900 border-cyan-500 ring-1 ring-cyan-500 shadow-lg shadow-cyan-500/10"
                        : "cyber-card border-slate-800 hover:border-slate-700"
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-500/30">
                          [{item.citation_id}]
                        </span>
                        <span className="text-xs font-mono font-bold text-white">
                          {item.source_name}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 text-emerald-400 border border-emerald-500/20">
                        {item.quality_tier}
                      </span>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-200 mb-2 line-clamp-2">
                      {item.title}
                    </h4>

                    {/* Verbatim snippet */}
                    <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800/80 text-xs text-slate-300 leading-relaxed font-sans italic mb-3">
                      &ldquo;{item.snippet}&rdquo;
                    </div>

                    {/* Matched Entities Chips */}
                    {item.matched_entities.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mb-3">
                        {item.matched_entities.map((ent, eIdx) => (
                          <span
                            key={eIdx}
                            className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800"
                          >
                            {ent}
                          </span>
                        ))}
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-2 border-t border-slate-800/80 text-[11px] font-mono">
                      <Link
                        href={`/content/${item.content_id}`}
                        className="text-cyan-400 hover:underline flex items-center gap-1"
                      >
                        <span>View Repository Record #{item.content_id}</span>
                        <span>&rarr;</span>
                      </Link>
                      <a
                        href={item.canonical_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-slate-400 hover:text-white transition-colors"
                      >
                        External Source &nearr;
                      </a>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Bottom Archive of Academic Papers & Vulnerability Research */}
      <div className="space-y-4 pt-8 border-t border-slate-800">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-violet-400 font-mono">◈</span> Academic & Exploit Research Archive
            </h2>
            <p className="text-xs text-slate-400">
              Technical whitepapers, exploit PoCs, and formal protocol security analyses.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">{archiveItems.length} records</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {archiveItems.map((item) => (
            <ContentCard key={item.id} item={item} onSelect={setSelectedItem} />
          ))}
        </div>
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
