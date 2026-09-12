"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { fetchContentById, fetchRelatedContent } from "../../../lib/api";
import { ContentItem } from "../../../lib/types";
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
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadItem() {
      setLoading(true);
      try {
        const [target, relatedItems] = await Promise.all([
          fetchContentById(contentId),
          fetchRelatedContent(contentId),
        ]);
        setItem(target);
        setRelated(relatedItems);
      } finally {
        setLoading(false);
      }
    }
    if (contentId) {
      loadItem();
    }
  }, [contentId]);

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

        <a
          href={item.canonical_url}
          target="_blank"
          rel="noopener noreferrer"
          className="text-cyan-400 hover:underline flex items-center gap-1 font-semibold"
        >
          Original Source Link &nearr;
        </a>
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

      {/* Section 22: Summary Component */}
      <div className="space-y-3">
        <h2 className="text-xs font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
          <span>◈</span> Executive Intelligence Summary
        </h2>
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-slate-700/80 text-slate-200 text-base leading-relaxed backdrop-blur-md shadow-lg">
          {item.summary || item.description || "No analytical summary generated."}
        </div>
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
