import React from "react";
import Link from "next/link";
import { ContentItem } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  item: ContentItem | null;
  onClose: () => void;
}

export const ContentModal: React.FC<Props> = ({ item, onClose }) => {
  if (!item) return null;

  const formattedDate = item.published_at
    ? new Date(item.published_at).toLocaleString("en-US", {
        dateStyle: "medium",
        timeStyle: "short",
      })
    : "Unknown date";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-150">
      <div className="cyber-card w-full max-w-3xl rounded-2xl max-h-[90vh] flex flex-col border border-slate-700/80 shadow-2xl overflow-hidden bg-slate-900/95">
        {/* Modal Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                {item.source}
              </span>
              <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800/80 text-slate-300 border border-slate-700">
                {item.category.replace(/_/g, " ")}
              </span>
              {item.severity && <SeverityBadge severity={item.severity} score={item.cvss_score} />}
            </div>
            <h2 className="text-xl font-bold text-white leading-tight">{item.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-2 rounded-lg bg-slate-800/60 hover:bg-slate-800 border border-slate-700 text-sm font-mono"
            aria-label="Close modal"
          >
            ✕
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-slate-300 text-sm leading-relaxed">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 p-4 rounded-xl bg-slate-950/60 border border-slate-800/80 font-mono text-xs">
            <div>
              <span className="text-slate-500 block mb-1">PUBLISHED DATE</span>
              <span className="text-slate-300">{formattedDate}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-1">AUTHOR</span>
              <span className="text-slate-300">{item.author || "Intelligence Analyst"}</span>
            </div>
            <div>
              <span className="text-slate-500 block mb-1">CONTENT TYPE</span>
              <span className="text-cyan-400 uppercase">{item.content_type}</span>
            </div>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2">Executive Summary</h4>
            <div className="p-4 rounded-xl bg-slate-950/40 border border-slate-800 text-slate-200">
              {item.summary || item.description || "No summarized overview provided."}
            </div>
          </div>

          {/* Full Description / Overview */}
          {item.description && item.description !== item.summary && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2">Detailed Context</h4>
              <p className="text-slate-400">{item.description}</p>
            </div>
          )}

          {/* Extracted Entities */}
          {item.entities && item.entities.length > 0 && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2">
                Identified Security Entities
              </h4>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {item.entities.map((e, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs font-mono"
                  >
                    <span className="text-emerald-400 font-semibold">{e.name}</span>
                    <span className="text-slate-500 uppercase">{e.entity_type}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tags */}
          {item.tags && item.tags.length > 0 && (
            <div>
              <h4 className="text-xs uppercase font-mono tracking-wider text-slate-400 mb-2">Taxonomy Tags</h4>
              <div className="flex flex-wrap gap-2">
                {item.tags.map((t, idx) => (
                  <span
                    key={idx}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800/80 text-cyan-300 border border-cyan-500/20"
                  >
                    #{t}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between gap-4">
          <span className="text-xs text-slate-500 font-mono">Provenance ID: #{item.id}</span>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-slate-800 text-slate-300 hover:text-white border border-slate-700 text-xs font-mono"
            >
              Dismiss
            </button>
            <Link
              href={`/content/${item.id}`}
              className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-cyan-500/30 text-xs font-mono transition-colors"
            >
              Full Content Page &rarr;
            </Link>
            <a
              href={item.canonical_url}
              target="_blank"
              rel="noopener noreferrer"
              className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs font-mono flex items-center gap-1.5 transition-colors"
            >
              Open Original Source &nearr;
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};
