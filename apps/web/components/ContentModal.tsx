import React from "react";
import Link from "next/link";
import { ContentItem } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { formatDateTime } from "../lib/formatters";

interface Props {
  item: ContentItem | null;
  onClose: () => void;
}

export const ContentModal: React.FC<Props> = ({ item, onClose }) => {
  if (!item) return null;

  const formattedDate = formatDateTime(item.published_at, "Unknown date");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-paper-ink/50 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="w-full max-w-3xl rounded-2xl max-h-[90vh] flex flex-col border-2 border-paper-border shadow-2xl overflow-hidden bg-paper-card">
        {/* Modal Header */}
        <div className="p-6 border-b border-paper-border bg-paper-panel flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-paper-bg text-paper-accent border border-paper-border font-bold">
                {item.source || "OSINT"}
              </span>
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-paper-bg text-paper-muted border border-paper-border">
                {(typeof item.category === "string" && item.category ? item.category : "general").replace(/_/g, " ")}
              </span>
              {item.severity && <SeverityBadge severity={item.severity} score={item.cvss_score} />}
            </div>
            <h2 className="text-xl font-serif font-bold text-paper-ink leading-tight">{item.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-paper-muted hover:text-paper-ink p-2 rounded-lg bg-paper-card hover:bg-paper-border/30 border border-paper-border text-sm font-mono transition-colors"
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-paper-ink text-sm leading-relaxed">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 p-4 rounded-xl bg-paper-panel border border-paper-border font-mono text-xs">
            <div>
              <span className="text-paper-muted block mb-1">PUBLISHED DATE</span>
              <span className="text-paper-ink font-semibold">{formattedDate}</span>
            </div>
            <div>
              <span className="text-paper-muted block mb-1">AUTHOR</span>
              <span className="text-paper-ink font-semibold">{item.author || "Intelligence Analyst"}</span>
            </div>
            <div>
              <span className="text-paper-muted block mb-1">CONTENT TYPE</span>
              <span className="text-paper-accent uppercase font-bold">{item.content_type}</span>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-xs uppercase font-mono tracking-wider text-paper-muted mb-2 font-bold">
              Executive Summary
            </h4>
            <div className="p-4 rounded-xl bg-paper-bg border border-paper-border text-paper-ink font-sans leading-relaxed">
              {item.summary || item.description || "No summarized overview provided."}
            </div>
          </div>

          {/* Full Description / Overview */}
          {item.description && item.description !== item.summary && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-paper-muted mb-2 font-bold">
                Detailed Context
              </h4>
              <p className="text-paper-muted font-sans leading-relaxed">{item.description}</p>
            </div>
          )}

          {/* Extracted Entities */}
          {item.entities && item.entities.length > 0 && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-paper-muted mb-2 font-bold">
                Identified Security Entities
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {item.entities.map((e, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-paper-panel border border-paper-border text-xs font-mono"
                  >
                    <span className="text-paper-ink font-semibold">{e.name}</span>
                    <span className="text-paper-accent text-[11px] uppercase">{e.entity_type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Video Intelligence Timestamps */}
          {item.video_metadata?.timestamps && item.video_metadata.timestamps.length > 0 && (
            <div>
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs uppercase font-mono tracking-wider text-paper-accent font-bold flex items-center gap-1.5">
                  <span>◈</span> Video Chapters & Key Timestamps
                </h4>
                {item.video_metadata.duration_formatted && (
                  <span className="text-[11px] font-mono text-paper-muted">
                    Duration: {item.video_metadata.duration_formatted}
                  </span>
                )}
              </div>
              <div className="space-y-1.5 font-mono text-xs">
                {item.video_metadata.timestamps.map((ts, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-paper-panel border border-paper-border flex items-center justify-between gap-3 hover:border-paper-accent transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-paper-bg text-paper-accent font-bold border border-paper-border shrink-0">
                        {ts.timestamp_str}
                      </span>
                      <span className="text-paper-ink">&rarr; {ts.topic}</span>
                    </div>
                    {ts.entities && ts.entities.length > 0 && (
                      <div className="flex items-center gap-1 shrink-0">
                        {ts.entities.slice(0, 2).map((ent, eIdx) => (
                          <span
                            key={eIdx}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-paper-card text-paper-accent border border-paper-border"
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

          {/* Document Intelligence: Headings & Chunks */}
          {item.document_metadata && (
            <div className="p-4 rounded-xl bg-paper-panel border border-paper-border space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-paper-border pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider bg-paper-card text-paper-accent border border-paper-border">
                    {item.document_metadata.document_type}
                  </span>
                  <h4 className="text-xs uppercase font-mono tracking-wider text-paper-ink font-bold">
                    Document Intelligence
                  </h4>
                </div>
                <div className="flex items-center gap-3 text-[11px] font-mono text-paper-muted">
                  {item.document_metadata.page_count && (
                    <span>{item.document_metadata.page_count} Pages</span>
                  )}
                  {item.document_metadata.word_count && (
                    <span>{item.document_metadata.word_count.toLocaleString()} Words</span>
                  )}
                  <span className="px-1.5 py-0.5 rounded bg-paper-card text-paper-muted border border-paper-border uppercase text-[10px]">
                    {item.document_metadata.retention_mode || "full_text"}
                  </span>
                </div>
              </div>

              {item.document_metadata.authors && item.document_metadata.authors.length > 0 && (
                <div className="text-xs text-paper-muted">
                  <span className="font-mono">Authors: </span>
                  <span className="text-paper-ink">{item.document_metadata.authors.join(", ")}</span>
                </div>
              )}

              {/* Section Outline */}
              {item.document_metadata.section_headings && item.document_metadata.section_headings.length > 0 && (
                <div>
                  <span className="text-[11px] font-mono uppercase tracking-wider text-paper-muted block mb-1.5">
                    Section Outline
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {item.document_metadata.section_headings.map((head, hIdx) => (
                      <span
                        key={hIdx}
                        className="text-[11px] px-2 py-1 rounded bg-paper-card text-paper-ink border border-paper-border font-mono"
                      >
                        § {head}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Chunks Preview */}
              {item.document_metadata.chunks_preview && item.document_metadata.chunks_preview.length > 0 && (
                <div>
                  <span className="text-[11px] font-mono uppercase tracking-wider text-paper-muted block mb-1.5">
                    Semantic Document Chunks ({item.document_metadata.chunks_count || item.document_metadata.chunks_preview.length} total)
                  </span>
                  <div className="space-y-1.5">
                    {item.document_metadata.chunks_preview.map((chk, cIdx) => (
                      <div
                        key={cIdx}
                        className="p-2.5 rounded bg-paper-card border border-paper-border text-xs font-mono text-paper-ink"
                      >
                        <span className="text-paper-accent font-semibold block mb-0.5">
                          Chunk {chk.chunk_index + 1}: {chk.heading}
                        </span>
                        <p className="text-paper-muted line-clamp-2">{chk.text}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tags */}
          {item.tags && item.tags.length > 0 && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-paper-muted mb-2 font-bold">Taxonomy Tags</h4>
              <div className="flex flex-wrap gap-2">
                {item.tags.map((t, idx) => (
                  <span
                    key={idx}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-paper-panel text-paper-ink border border-paper-border"
                  >
                    #{t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-paper-border bg-paper-panel flex items-center justify-between gap-4">
          <span className="text-xs text-paper-muted font-mono">Provenance ID: #{item.id}</span>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-paper-card text-paper-ink hover:bg-paper-border/30 border border-paper-border text-xs font-mono transition-colors"
            >
              Dismiss
            </button>
            <Link
              href={`/content/${item.id}`}
              className="px-4 py-2 rounded-lg bg-paper-card hover:bg-paper-border/30 text-paper-accent border border-paper-border text-xs font-mono transition-colors"
            >
              Full Content Page &rarr;
            </Link>
            {item.canonical_url && (
              <a
                href={item.canonical_url}
                target="_blank"
                rel="noopener noreferrer"
                className="px-4 py-2 rounded-lg bg-paper-accent hover:bg-amber-700 text-white font-semibold text-xs font-mono flex items-center gap-1.5 transition-colors"
              >
                Open Original Source &nearr;
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
