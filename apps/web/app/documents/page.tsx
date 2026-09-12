"use client";

import React, { useEffect, useState } from "react";
import { fetchRecentContent } from "../../lib/api";
import { ContentItem } from "../../lib/types";
import { ContentCard } from "../../components/ContentCard";
import { ContentModal } from "../../components/ContentModal";

export default function DocumentsPage() {
  const [documents, setDocuments] = useState<ContentItem[]>([]);
  const [selectedFormat, setSelectedFormat] = useState<string>("all");
  const [selectedItem, setSelectedItem] = useState<ContentItem | null>(null);

  useEffect(() => {
    fetchRecentContent().then((all) => {
      const filtered = all.filter(
        (i) =>
          i.content_type === "document" ||
          i.content_type === "paper" ||
          i.content_type === "advisory" ||
          Boolean(i.document_metadata)
      );
      setDocuments(filtered.length > 0 ? filtered : all);
    });
  }, []);

  const formatFilteredDocs = documents.filter((doc) => {
    if (selectedFormat === "all") return true;
    const docType = doc.document_metadata?.document_type?.toLowerCase() || "";
    return docType === selectedFormat.toLowerCase();
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="border-b border-slate-800 pb-5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-wider block mb-1">
              DOCUMENT INTELLIGENCE & RESEARCH PAPERS
            </span>
            <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
              Whitepapers, Research Papers & Threat Advisories
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Automated ingestion across PDF, HTML, Markdown, TXT, DOCX, and PPTX with section-preserving semantic chunking.
            </p>
          </div>

          {/* Format Filter Chips */}
          <div className="flex flex-wrap gap-2">
            {[
              { id: "all", label: "All Formats" },
              { id: "pdf", label: "PDF" },
              { id: "docx", label: "DOCX" },
              { id: "markdown", label: "Markdown" },
              { id: "pptx", label: "PPTX" },
            ].map((fmt) => (
              <button
                key={fmt.id}
                onClick={() => setSelectedFormat(fmt.id)}
                className={`text-xs font-mono px-3 py-1.5 rounded-lg border transition-colors ${
                  selectedFormat === fmt.id
                    ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-sm shadow-cyan-500/10 font-bold"
                    : "bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200"
                }`}
              >
                {fmt.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {formatFilteredDocs.map((item) => (
          <div key={item.id} className="relative group">
            <ContentCard item={item} onSelect={setSelectedItem} />
            {item.document_metadata && (
              <div className="mt-1.5 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800/80 text-[11px] font-mono flex items-center justify-between text-slate-400">
                <span className="uppercase font-bold text-cyan-400">
                  {item.document_metadata.document_type}
                </span>
                {item.document_metadata.page_count && (
                  <span>{item.document_metadata.page_count} Pages</span>
                )}
                {item.document_metadata.chunks_count && (
                  <span className="text-slate-500">{item.document_metadata.chunks_count} Chunks</span>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      <ContentModal item={selectedItem} onClose={() => setSelectedItem(null)} />
    </div>
  );
}
