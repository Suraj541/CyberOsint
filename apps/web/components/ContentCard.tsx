import React from "react";
import { ContentItem } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";
import { formatDate } from "../lib/formatters";

interface Props {
  item: ContentItem;
  onSelect?: (item: ContentItem) => void;
}

export const ContentCard: React.FC<Props> = ({ item, onSelect }) => {
  const formattedDate = formatDate(item.published_at);

  return (
    <div
      onClick={() => onSelect && onSelect(item)}
      className="cyber-card rounded-2xl p-5 cursor-pointer group flex flex-col justify-between bg-[#FFFDF5] dark:bg-[#0F1218] border border-[#E4DBC8] dark:border-[#222734] shadow-sm hover:border-[#C2821A] dark:hover:border-[#E5A93B] transition-all"
    >
      <div>
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-[#F1EBD8] dark:bg-[#161B26] text-[#C2821A] dark:text-[#E5A93B] border border-[#E4DBC8] dark:border-[#2D3446] font-bold">
              {item.source || "OSINT"}
            </span>
            <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-[#F1EBD8] dark:bg-[#161B26] text-[#68655B] dark:text-[#CBD5E1] border border-[#E4DBC8] dark:border-[#2D3446]">
              {(typeof item.category === "string" && item.category ? item.category : "general").replace(/_/g, " ")}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#F1EBD8] dark:bg-[#161B26] text-[#171714] dark:text-white border border-[#E4DBC8] dark:border-[#2D3446]">
              {item.content_type || "intel"}
            </span>
          </div>
          {item.severity && <SeverityBadge severity={item.severity} score={item.cvss_score} />}
        </div>

        <h3 className="text-base font-bold text-[#171714] dark:text-white group-hover:text-[#C2821A] dark:group-hover:text-[#E5A93B] transition-colors line-clamp-2 mb-2 leading-snug font-sans">
          {item.title}
        </h3>

        <p className="text-sm text-[#68655B] dark:text-slate-300 line-clamp-3 mb-4 leading-relaxed">
          {item.summary || item.description || "Threat intelligence report details."}
        </p>
      </div>

      <div>
        {item.entities && item.entities.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {item.entities.slice(0, 3).map((e, idx) => (
              <span
                key={idx}
                className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#2D7A4F]/10 text-[#2D7A4F] dark:text-[#4ADE80] border border-[#2D7A4F]/25 font-semibold"
              >
                {e.name}
              </span>
            ))}
            {item.entities.length > 3 && (
              <span className="text-[11px] font-mono px-1.5 py-0.5 text-[#8C887B] dark:text-[#94A3B8]">
                +{item.entities.length - 3} more
              </span>
            )}
          </div>
        )}

        <div className="flex items-center justify-between text-xs text-[#68655B] dark:text-slate-400 border-t border-[#E4DBC8] dark:border-[#222734] pt-3 font-mono">
          <span>{formattedDate}</span>
          <span className="text-[#C2821A] dark:text-[#E5A93B] group-hover:underline flex items-center gap-1 font-bold">
            Inspect intel &rarr;
          </span>
        </div>
      </div>
    </div>
  );
};
