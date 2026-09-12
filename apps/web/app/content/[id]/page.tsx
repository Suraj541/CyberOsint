"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import {
  fetchContentById,
  fetchRelatedContent,
  generateContentSummary,
  getContentSummary,
  fetchRecommendations,
  fetchRelatedTopics,
  recordInteraction,
} from "../../../lib/api";
import {
  ContentItem,
  ContentSummary,
  RecommendationItem,
  TopicRecommendation,
} from "../../../lib/types";
import { SeverityBadge } from "../../../components/SeverityBadge";
import { ContentCard } from "../../../components/ContentCard";
import { SourceQualityBadge } from "../../../components/SourceQualityBadge";

export default function ContentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const idStr = Array.isArray(params?.id) ? params.id[0] : params?.id;
  const contentId = parseInt(idStr || "1", 10);

  const [item, setItem] = useState<ContentItem | null>(null);
  const [related, setRelated] = useState<ContentItem[]>([]);
  const [summary, setSummary] = useState<ContentSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [regenerating, setRegenerating] = useState(false);

  // Section 31 (Step 30): Recommendations & Bookmark State
  const [isSaved, setIsSaved] = useState<boolean>(false);
  const [relatedTopics, setRelatedTopics] = useState<TopicRecommendation[]>([]);
  const [recommendedNext, setRecommendedNext] = useState<RecommendationItem[]>([]);

  useEffect(() => {
    async function loadItem() {
      setLoading(true);
      try {
        const [target, relatedItems, aiSummary, recFeed] = await Promise.all([
          fetchContentById(contentId),
          fetchRelatedContent(contentId),
          getContentSummary(contentId),
          fetchRecommendations({ currentContentId: contentId, limit: 4 }),
        ]);
        setItem(target);
        setRelated(relatedItems);
        setRecommendedNext(recFeed.items);

        if (target?.ai_summary) {
          setSummary(target.ai_summary);
        } else if (aiSummary) {
          setSummary(aiSummary);
        }

        // Fetch semantic related topics matching target's title or primary tags
        const seedTopic = target?.tags?.[0] || target?.title || "Kubernetes Security";
        const topics = await fetchRelatedTopics(seedTopic, 5);
        setRelatedTopics(topics);

        // Section 31: Record viewing telemetry event
        recordInteraction("view", contentId, undefined, {
          title: target?.title,
          category: target?.category,
          content_type: target?.content_type,
        });
      } finally {
        setLoading(false);
      }
    }
    if (contentId) {
      loadItem();
    }
  }, [contentId]);

  const handleToggleSave = async () => {
    const nextSaved = !isSaved;
    setIsSaved(nextSaved);
    await recordInteraction(nextSaved ? "save" : "unsave", contentId, undefined, {
      title: item?.title,
    });
  };

  const handleRegenerateSummary = async () => {
    if (!contentId || regenerating) return;
    setRegenerating(true);
    try {
      const updated = await generateContentSummary(contentId, true);
      if (updated) {
        setSummary(updated);
      }
    } catch (err) {
      console.error("Failed to regenerate summary:", err);
    } finally {
      setRegenerating(false);
    }
  };

  if (loading) {
    return (
      <div className="py-20 text-center font-mono text-sm text-slate-500 animate-pulse">
        Retrieving intelligence record #{contentId}...
      </div>
    );
  }

  if (!item) {
    return (
      <div className="cyber-card rounded-2xl p-12 text-center max-w-xl mx-auto my-12">
        <h2 className="text-xl font-bold text-white mb-2 font-mono">Record Not Found</h2>
        <p className="text-sm text-slate-400 mb-6">
          The requested intelligence record could not be retrieved from the repository.
        </p>
        <Link
          href="/"
          className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-bold font-mono text-xs inline-block"
        >
          &larr; Return to Dashboard
        </Link>
      </div>
    );
  }

  const formattedDate = item.published_at
    ? new Date(item.published_at).toLocaleString("en-US", {
        dateStyle: "full",
        timeStyle: "medium",
      })
    : "Unknown Publication Timestamp";

  return (
    <article className="space-y-8 animate-in fade-in duration-200 max-w-5xl mx-auto">
      {/* Back button & Breadcrumbs */}
      <div className="flex items-center justify-between text-xs font-mono text-slate-500 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2">
          <button
            onClick={() => router.back()}
            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
          >
            &larr; Back
          </button>
          <span>/</span>
          <span className="text-slate-400 uppercase">{item.content_type}</span>
          <span>/</span>
          <span className="text-slate-600">ID #{item.id}</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleToggleSave}
            className={`px-3 py-1 rounded-lg border text-xs font-mono transition-all flex items-center gap-1.5 ${
              isSaved
                ? "bg-amber-500/20 text-amber-300 border-amber-500/40 font-bold"
                : "bg-slate-900 text-slate-400 hover:text-amber-300 border-slate-800"
            }`}
          >
            <span>{isSaved ? "★ Saved in Library" : "☆ Bookmark Intel"}</span>
          </button>
          <a
            href={item.canonical_url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
          >
            Original Source Link &nearr;
          </a>
        </div>
      </div>

      {/* Header Area */}
      <div className="space-y-4">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs uppercase font-mono px-2.5 py-1 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-bold">
            {item.source}
          </span>
          <SourceQualityBadge quality={item.source_quality} sourceName={item.source} size="xs" />
          <span className="text-xs uppercase font-mono px-2.5 py-1 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
            {item.category?.replace(/_/g, " ") || "general"}
          </span>
          <span className="text-xs font-mono px-2.5 py-1 rounded bg-violet-500/10 text-violet-300 border border-violet-500/20 uppercase">
            {item.content_type}
          </span>
          {item.severity && <SeverityBadge severity={item.severity} score={item.cvss_score} />}
        </div>

        <h1 className="text-2xl sm:text-4xl font-black text-white tracking-tight leading-tight">
          {item.title}
        </h1>
      </div>

      {/* Provenance Metadata Bar (IMPLEMENT.md Section 22: Title, Source, Published Date, Author, Category) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 p-5 rounded-xl cyber-card text-xs font-mono">
        <div>
          <span className="text-slate-500 block mb-1">PUBLISHED DATE</span>
          <span className="text-slate-200">{formattedDate}</span>
        </div>
        <div>
          <span className="text-slate-500 block mb-1">AUTHOR / ANALYST</span>
          <span className="text-slate-200">{item.author || "Intelligence Team"}</span>
        </div>
        <div>
          <span className="text-slate-500 block mb-1">PROVENANCE SOURCE</span>
          <div className="flex items-center gap-1.5">
            <span className="text-cyan-400 font-semibold">{item.source}</span>
            <SourceQualityBadge quality={item.source_quality} sourceName={item.source} size="xs" />
          </div>
        </div>
        <div>
          <span className="text-slate-500 block mb-1">TAXONOMY CATEGORY</span>
          <span className="text-emerald-400 uppercase">
            {item.category?.replace(/_/g, " ") || "General"}
          </span>
        </div>
      </div>

      {/* Section 29: AI Grounded Executive Intelligence Summary */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-1 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <span className="text-cyan-400 font-mono text-base">◈</span>
            <h2 className="text-sm font-mono uppercase tracking-wider text-white font-bold">
              AI Grounded Executive Summary
            </h2>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 uppercase font-semibold">
              Grounded NLP
            </span>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {summary && (
              <>
                <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 text-slate-300 border border-slate-700">
                  Model: <span className="text-cyan-400">{summary.model}</span> ({summary.model_version})
                </span>
                <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 text-slate-300 border border-slate-700">
                  Prompt: <span className="text-violet-400">{summary.prompt_version}</span>
                </span>
                <span
                  className={`text-[11px] font-mono px-2.5 py-1 rounded border font-semibold ${
                    summary.validation_status === "passed"
                      ? "bg-emerald-950/50 text-emerald-300 border-emerald-500/30"
                      : "bg-amber-950/50 text-amber-300 border-amber-500/30"
                  }`}
                >
                  Validation: {summary.validation_status.toUpperCase()} ({(summary.validation_score * 100).toFixed(0)}%)
                </span>
                <span className="text-[11px] font-mono px-2.5 py-1 rounded bg-slate-900 text-emerald-400 border border-slate-700">
                  {(summary.confidence * 100).toFixed(0)}% Conf.
                </span>
              </>
            )}

            <button
              onClick={handleRegenerateSummary}
              disabled={regenerating}
              className="px-3 py-1 rounded-lg bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 hover:text-cyan-200 border border-cyan-500/30 text-xs font-mono font-medium flex items-center gap-1.5 transition-all disabled:opacity-50"
            >
              <span className={regenerating ? "animate-spin inline-block" : ""}>⟳</span>
              <span>{regenerating ? "Synthesizing..." : summary ? "Regenerate" : "Generate Summary"}</span>
            </button>
          </div>
        </div>

        {summary ? (
          <div className="p-6 rounded-2xl bg-gradient-to-b from-slate-900/90 to-slate-950 border border-slate-700/80 backdrop-blur-md shadow-xl space-y-6">
            {/* Core Grounded Narrative */}
            <div className="text-slate-200 text-sm sm:text-base leading-relaxed whitespace-pre-wrap font-sans border-b border-slate-800 pb-5">
              {summary.executive_summary}
            </div>

            {/* Strict Guardrail Separation: Reported Facts vs Analytical Inferences */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
              {/* Reported Facts Box (Rule 1, 2, 5) */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-emerald-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-400 uppercase tracking-wide">
                    <span>✓</span>
                    <span>Verified Reported Facts</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-500/20">
                    Source-Grounded
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Verifiable technical data extracted directly from primary reporting without alteration.
                </p>
                <ul className="space-y-2 text-xs text-slate-300 font-sans">
                  {summary.reported_facts && summary.reported_facts.length > 0 ? (
                    summary.reported_facts.map((fact, fIdx) => (
                      <li key={fIdx} className="flex items-start gap-2">
                        <span className="text-emerald-400 mt-0.5 shrink-0">•</span>
                        <span>{fact}</span>
                      </li>
                    ))
                  ) : (
                    <li className="text-slate-500 italic">No isolated fact points cataloged.</li>
                  )}
                </ul>
              </div>

              {/* Analytical Inferences Box (Rule 5) */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-purple-500/30 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-purple-400 uppercase tracking-wide">
                    <span>✦</span>
                    <span>Analytical Inferences</span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-500/20">
                    Interpretation
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  Model-derived risk projections and tactical implications separated from direct observations.
                </p>
                <ul className="space-y-2 text-xs text-slate-300 font-sans">
                  {summary.inferences && summary.inferences.length > 0 ? (
                    summary.inferences.map((inf, iIdx) => (
                      <li key={iIdx} className="flex items-start gap-2">
                        <span className="text-purple-400 mt-0.5 shrink-0">•</span>
                        <span>{inf}</span>
                      </li>
                    ))
                  ) : (
                    <li className="text-slate-500 italic">No analytical projections formulated.</li>
                  )}
                </ul>
              </div>
            </div>

            {/* Preserved Uncertainties (Rule 3) */}
            {summary.uncertainties && summary.uncertainties.length > 0 && (
              <div className="p-4 rounded-xl bg-amber-950/20 border border-amber-500/30 flex items-start gap-3">
                <span className="text-amber-400 text-sm font-bold font-mono shrink-0 mt-0.5">⚠</span>
                <div className="space-y-1.5 w-full">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-amber-300 uppercase tracking-wide">
                      Preserved Uncertainties & Unverified Claims
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-500/30">
                      Rule 3 Active
                    </span>
                  </div>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {summary.uncertainties.map((unc, uIdx) => (
                      <li key={uIdx} className="flex items-start gap-2">
                        <span className="text-amber-400 shrink-0">&rarr;</span>
                        <span>{unc}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            )}

            {/* Key Takeaways */}
            {summary.key_takeaways && summary.key_takeaways.length > 0 && (
              <div className="pt-2 border-t border-slate-800/80 space-y-2">
                <span className="text-xs font-mono uppercase text-slate-400 font-bold block">
                  Actionable Takeaways
                </span>
                <div className="flex flex-wrap gap-2">
                  {summary.key_takeaways.map((takeaway, tIdx) => (
                    <span
                      key={tIdx}
                      className="px-3 py-1 rounded-lg bg-slate-900 text-slate-300 border border-slate-800 text-xs font-mono"
                    >
                      {takeaway}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Attribution & Provenance Footer (Rule 4) */}
            <div className="pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row items-start sm:items-center justify-between text-[11px] font-mono text-slate-500 gap-2">
              <div>
                Attributed Source: <span className="text-cyan-400 font-semibold">{summary.source_attribution || item.source}</span>
              </div>
              <div className="flex items-center gap-2 text-slate-500">
                <span>Generated: {new Date(summary.generated_at).toLocaleString()}</span>
                <span>•</span>
                <span>Strict 5-Rule Grounding Enforced</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-700/80 text-slate-200 text-base leading-relaxed backdrop-blur-md shadow-lg space-y-4">
            <p>{item.summary || item.description || "No analytical summary generated."}</p>
            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Standard raw ingestion summary</span>
              <button
                onClick={handleRegenerateSummary}
                disabled={regenerating}
                className="px-3 py-1 rounded bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 font-bold border border-cyan-500/40 transition-colors"
              >
                {regenerating ? "Generating..." : "⚡ Generate Grounded AI Summary"}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detailed Content / Context */}
      {item.description && item.description !== item.summary && (
        <div className="space-y-3">
          <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-2">
            <span>◈</span> Analytical Context & Body
          </h2>
          <div className="p-6 rounded-2xl cyber-card text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">
            {item.description}
          </div>
        </div>
      )}

      {/* Section 24: Video Intelligence Chapters & Timestamps */}
      {item.video_metadata?.timestamps && item.video_metadata.timestamps.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-2">
              <span>◈</span> Conference Video Chapters & Key Timestamps
            </h2>
            {item.video_metadata.duration_formatted && (
              <span className="text-xs font-mono text-slate-400">
                Duration: {item.video_metadata.duration_formatted}
              </span>
            )}
          </div>
          <div className="p-5 rounded-2xl bg-slate-950/90 border border-amber-500/30 space-y-2">
            {item.video_metadata.timestamps.map((ts, idx) => (
              <div
                key={idx}
                className="p-3 rounded-xl bg-slate-900/70 border border-slate-800 flex items-center justify-between gap-3 hover:border-amber-500/50 transition-colors"
              >
                <div className="flex items-center gap-3 font-mono text-xs">
                  <span className="px-2.5 py-1 rounded bg-amber-950/50 text-amber-300 font-bold border border-amber-500/30">
                    {ts.timestamp_str}
                  </span>
                  <span className="text-slate-200 font-medium">&rarr; {ts.topic}</span>
                </div>
                {ts.entities && ts.entities.length > 0 && (
                  <div className="flex items-center gap-1.5 shrink-0">
                    {ts.entities.map((ent, eIdx) => (
                      <span
                        key={eIdx}
                        className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 text-emerald-400 border border-emerald-500/20"
                      >
                        {ent}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Section 25: Document Intelligence Outline & Semantic Chunks */}
      {item.document_metadata && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
              <span>◈</span> Document Intelligence & Structural Breakdown
            </h2>
            <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
              <span className="px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-300 border border-cyan-500/30 uppercase font-bold">
                {item.document_metadata.document_type}
              </span>
              {item.document_metadata.page_count && (
                <span>{item.document_metadata.page_count} Pages</span>
              )}
            </div>
          </div>
          <div className="p-5 rounded-2xl bg-slate-950/90 border border-cyan-900/40 space-y-4">
            {item.document_metadata.authors && item.document_metadata.authors.length > 0 && (
              <div className="text-xs text-slate-400 font-mono">
                <span className="text-slate-500">Document Authors: </span>
                <span className="text-slate-300">{item.document_metadata.authors.join(", ")}</span>
              </div>
            )}
            {item.document_metadata.section_headings && item.document_metadata.section_headings.length > 0 && (
              <div>
                <span className="text-xs font-mono uppercase text-slate-400 block mb-2">Section Outline</span>
                <div className="flex flex-wrap gap-2">
                  {item.document_metadata.section_headings.map((heading, hIdx) => (
                    <span
                      key={hIdx}
                      className="px-2.5 py-1 rounded-lg bg-slate-900 text-slate-300 border border-slate-800 text-xs font-mono"
                    >
                      § {heading}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {item.document_metadata.chunks_preview && item.document_metadata.chunks_preview.length > 0 && (
              <div>
                <span className="text-xs font-mono uppercase text-slate-400 block mb-2">
                  Extracted Semantic Chunks ({item.document_metadata.chunks_count || item.document_metadata.chunks_preview.length})
                </span>
                <div className="space-y-2">
                  {item.document_metadata.chunks_preview.map((chk, cIdx) => (
                    <div
                      key={cIdx}
                      className="p-3 rounded-xl bg-slate-900/60 border border-slate-800 text-xs font-mono text-slate-300"
                    >
                      <span className="text-cyan-400 font-semibold block mb-1">
                        Chunk #{chk.chunk_index + 1}: {chk.heading}
                      </span>
                      <p className="text-slate-400 leading-relaxed">{chk.text}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Section 22: Extracted Entities */}
      {item.entities && item.entities.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-2">
              <span>◈</span> Extracted Cyber Entities ({item.entities.length})
            </h2>
            <Link
              href="/graph"
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
            >
              <span>🕸 Explore in Knowledge Graph</span>
              <span>&rarr;</span>
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
            {item.entities.map((ent, idx) => (
              <Link
                key={idx}
                href={`/entities/${ent.id || encodeURIComponent(ent.name)}`}
                className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-emerald-500/40 transition-colors flex items-center justify-between font-mono text-xs group"
              >
                <div>
                  <span className="font-bold text-white group-hover:text-emerald-400 block text-sm transition-colors">
                    {ent.name}
                  </span>
                  <span className="text-[11px] text-emerald-400 uppercase tracking-wider">
                    {ent.entity_type}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {ent.confidence !== undefined && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                      {(ent.confidence * 100).toFixed(0)}% Conf.
                    </span>
                  )}
                  <span className="text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity">
                    &rarr;
                  </span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Section 22: Tags */}
      {item.tags && item.tags.length > 0 && (
        <div className="space-y-3">
          <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold flex items-center gap-2">
            <span>◈</span> Taxonomy Tags
          </h2>
          <div className="flex flex-wrap gap-2">
            {item.tags.map((tag, idx) => (
              <span
                key={idx}
                className="px-3 py-1 rounded-lg bg-slate-900 text-cyan-300 border border-cyan-500/20 text-xs font-mono font-medium"
              >
                #{tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Section 22: Original Source Callout */}
      <div className="p-6 rounded-2xl bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-950 border border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <span className="text-xs font-mono uppercase text-cyan-400 block mb-1">
            VERIFIED PROVENANCE
          </span>
          <p className="text-sm text-slate-300">
            Original reporting archived from{" "}
            <span className="font-bold text-white">{item.source}</span>.
          </p>
        </div>
        <a
          href={item.canonical_url}
          target="_blank"
          rel="noopener noreferrer"
          className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold font-mono text-xs flex items-center gap-2 transition-colors shrink-0 shadow-lg shadow-cyan-500/10"
        >
          <span>Inspect Original Source</span>
          <span>&nearr;</span>
        </a>
      </div>

      {/* Section 31: Semantic Topic Exploration (Canonical Example: Kubernetes Security -> Container, Docker, Cloud, K8s Threat Detection, Runtime) */}
      {relatedTopics && relatedTopics.length > 0 && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-950 to-slate-900 border border-cyan-500/30 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-cyan-400 font-mono">◈</span>
              <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                Semantic Topic Graph Recommendations
              </h3>
            </div>
            <span className="text-[11px] font-mono text-cyan-400/80">Section 31 Knowledge Graph</span>
          </div>

          <p className="text-xs text-slate-400">
            Based on this intelligence record, analysts also explore these correlated threat domains:
          </p>

          <div className="flex items-center gap-2.5 flex-wrap">
            {relatedTopics.map((top, idx) => (
              <Link
                key={idx}
                href={`/search?q=${encodeURIComponent(top.topic)}`}
                className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-cyan-500/50 hover:bg-cyan-500/10 text-xs font-mono transition-all flex items-center gap-2 group"
              >
                <span className="text-cyan-300 font-semibold group-hover:text-cyan-200">
                  {top.topic}
                </span>
                <span className="text-[10px] text-cyan-500/60 font-mono">
                  {(top.score * 100).toFixed(0)}%
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Section 31: Recommended Next Intelligence */}
      {recommendedNext && recommendedNext.length > 0 && (
        <div className="space-y-4 pt-6 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold">
                  AI RECOMMENDATION ENGINE
                </span>
              </div>
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <span className="text-cyan-400 font-mono">⚡</span> Recommended Next to Read
              </h2>
            </div>
            <span className="text-xs font-mono text-slate-500">
              Personalized multi-factor scoring
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
            {recommendedNext.map((rec) => (
              <Link
                key={rec.content_id}
                href={`/content/${rec.content_id}`}
                className="p-4 rounded-xl cyber-card border border-slate-800 hover:border-cyan-500/50 transition-all block flex flex-col justify-between group"
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono mb-2">
                    <span className="uppercase px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {rec.content_type}
                    </span>
                    <span className="text-cyan-400">{rec.difficulty_level}</span>
                  </div>
                  <h4 className="text-xs font-bold text-white group-hover:text-cyan-300 line-clamp-2 mb-1.5 transition-colors">
                    {rec.title}
                  </h4>
                  <p className="text-[11px] text-slate-400 line-clamp-2 mb-2">
                    {rec.summary || rec.description}
                  </p>
                </div>
                <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] font-mono text-slate-500">
                  <span className="truncate max-w-[100px]">{rec.source}</span>
                  <span className="text-cyan-400 group-hover:underline">&rarr;</span>
                </div>
              </Link>
            ))}
          </div>
        </div>
      )}

      {/* Section 22: Related Content */}
      {related.length > 0 && (
        <div className="space-y-4 pt-6 border-t border-slate-800">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-violet-400 font-mono">◈</span> Related Intelligence Content
            </h2>
            <span className="text-xs font-mono text-slate-500">{related.length} items linked</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
            {related.map((rel) => (
              <Link key={rel.id} href={`/content/${rel.id}`} className="block">
                <ContentCard item={rel} />
              </Link>
            ))}
          </div>
        </div>
      )}
    </article>
  );
}
