import React from "react";
import { ContentItem } from "../lib/types";
import { SeverityBadge } from "./SeverityBadge";

interface Props {
  item: ContentItem;
  onSelect?: (item: ContentItem) => void;
}

export const ContentCard: React.FC<Props> = ({ item, onSelect }) => {
  const formattedDate = item.published_at
    ? new Date(item.published_at).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : "Recent";

  return (
    <div
      onClick={() => onSelect && onSelect(item)}
      className="cyber-card rounded-xl p-5 cursor-pointer group flex flex-col justify-between"
    >
      <div>
        <div className="flex items-center justify-between gap-2 mb-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
              {item.source}
            </span>
            <span className="text-xs uppercase font-mono px-2 py-0.5 rounded bg-slate-800/60 text-slate-400 border border-slate-700/50">
              {item.category.replace(/_/g, " ")}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-violet-500/10 text-violet-300 border border-violet-500/20">
              {item.content_type}
            </span>
          </div>
          {item.severity && <SeverityBadge severity={item.severity} score={item.cvss_score} />}
        </div>

        <h3 className="text-base font-semibold text-slate-100 group-hover:text-cyan-300 transition-colors line-clamp-2 mb-2 leading-snug">
          {item.title}
        </h3>

        <p className="text-sm text-slate-400 line-clamp-3 mb-4 leading-relaxed">
          {item.summary || item.description || "Threat intelligence report details."}
        </p>
      </div>

      <div>
        {item.entities && item.entities.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {item.entities.slice(0, 3).map((e, idx) => (
              <span
                key={idx}
                className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800/80 text-emerald-400 border border-emerald-500/20"
              >
                {e.name}
              </span>
            ))}
            {item.entities.length > 3 && (
              <span className="text-[11px] font-mono px-1.5 py-0.5 text-slate-500">
                +{item.entities.length - 3} more
              </span>
            )}
          </div>
        )}

        <div className="flex items-center justify-between text-xs text-slate-500 border-t border-slate-800/60 pt-3">
          <span className="font-mono">{formattedDate}</span>
          <span className="text-cyan-400 group-hover:underline flex items-center gap-1">
            Inspect intel &rarr;
          </span>
        </div>
      </div>
    </div>
  );
};
