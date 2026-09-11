import React from "react";
import { SeverityLevel } from "../lib/types";

interface Props {
  severity?: SeverityLevel | string;
  score?: number;
}

export const SeverityBadge: React.FC<Props> = ({ severity = "INFO", score }) => {
  const norm = (severity || "INFO").toUpperCase();

  const colors = {
    CRITICAL: "bg-red-500/10 text-red-400 border-red-500/30",
    HIGH: "bg-amber-500/10 text-amber-400 border-amber-500/30",
    MEDIUM: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
    LOW: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
    INFO: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  }[norm] || "bg-slate-500/10 text-slate-400 border-slate-500/30";

  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium border ${colors}`}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {norm}
      {score !== undefined && score !== null && ` (${score.toFixed(1)})`}
    </span>
  );
};
