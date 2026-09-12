"use client";

import React, { useState } from "react";
import { SourceQuality } from "../lib/types";

interface SourceQualityBadgeProps {
  quality?: SourceQuality;
  sourceName?: string;
  size?: "xs" | "sm" | "md";
  interactive?: boolean;
}

export const SourceQualityBadge: React.FC<SourceQualityBadgeProps> = ({
  quality,
  sourceName,
  size = "sm",
  interactive = true,
}) => {
  const [open, setOpen] = useState(false);

  // Default fallback quality if not populated
  const q = quality || {
    source_id: 0,
    source_name: sourceName || "Intelligence Source",
    authority: 0.80,
    accuracy: 0.85,
    technical_depth: 0.75,
    originality: 0.80,
    historical_reliability: 0.85,
    overall_score: 0.81,
    quality_tier: "Tier 2 (High)",
    indicator_symbol: "B+",
    disclaimer: "Internal analytical ranking indicator — not an absolute truth score",
  };

  const isTier1 = q.overall_score >= 0.85;
  const isTier2 = q.overall_score >= 0.70 && q.overall_score < 0.85;
  const isTier3 = q.overall_score >= 0.50 && q.overall_score < 0.70;

  const styleConfig = isTier1
    ? {
        border: "border-emerald-500/40 hover:border-emerald-400",
        bg: "bg-emerald-950/40 text-emerald-300",
        pill: "bg-emerald-500/20 text-emerald-300",
        indicatorColor: "#10b981",
        label: "TIER 1 • AUTHORITATIVE",
      }
    : isTier2
    ? {
        border: "border-cyan-500/40 hover:border-cyan-400",
        bg: "bg-cyan-950/40 text-cyan-300",
        pill: "bg-cyan-500/20 text-cyan-300",
        indicatorColor: "#06b6d4",
        label: "TIER 2 • HIGH",
      }
    : isTier3
    ? {
        border: "border-amber-500/40 hover:border-amber-400",
        bg: "bg-amber-950/40 text-amber-300",
        pill: "bg-amber-500/20 text-amber-300",
        indicatorColor: "#f59e0b",
        label: "TIER 3 • STANDARD",
      }
    : {
        border: "border-slate-700 hover:border-slate-600",
        bg: "bg-slate-900/80 text-slate-400",
        pill: "bg-slate-800 text-slate-400",
        indicatorColor: "#94a3b8",
        label: "TIER 4 • UNVERIFIED",
      };

  const sizeClasses =
    size === "xs"
      ? "text-[10px] px-1.5 py-0.5 gap-1"
      : size === "md"
      ? "text-xs px-3 py-1.5 gap-2"
      : "text-[11px] px-2.5 py-1 gap-1.5";

  return (
    <div className="relative inline-block font-mono">
      <button
        type="button"
        onClick={() => interactive && setOpen(!open)}
        onMouseEnter={() => interactive && setOpen(true)}
        onMouseLeave={() => interactive && setOpen(false)}
        className={`inline-flex items-center rounded-lg border transition-all ${styleConfig.border} ${styleConfig.bg} ${sizeClasses} shadow-sm`}
        title="View Source Reliability Breakdown"
      >
        <span
          className="w-1.5 h-1.5 rounded-full animate-pulse"
          style={{ backgroundColor: styleConfig.indicatorColor }}
        />
        <span className="font-bold tracking-tight">{q.indicator_symbol}</span>
        <span className="opacity-60">•</span>
        <span>{(q.overall_score * 100).toFixed(0)}%</span>
        {size !== "xs" && (
          <span className="text-[9px] opacity-75 hidden sm:inline uppercase tracking-wider">
            {isTier1 ? "Authoritative" : isTier2 ? "High" : isTier3 ? "Standard" : "Unverified"}
          </span>
        )}
      </button>

      {/* Interactive 5-Dimension Metric Breakdown Popover */}
      {open && (
        <div className="absolute left-0 sm:left-auto sm:right-0 mt-2 w-72 z-50 p-4 rounded-xl bg-slate-950/95 border border-slate-700/80 shadow-2xl backdrop-blur-xl space-y-3 pointer-events-auto">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div>
              <div className="text-[10px] uppercase text-slate-400">Source Reliability</div>
              <div className="text-xs font-bold text-white truncate max-w-[180px]">
                {q.source_name}
              </div>
            </div>
            <span
              className={`px-2 py-0.5 rounded text-[10px] font-bold ${styleConfig.pill} border border-current`}
            >
              {q.indicator_symbol} ({styleConfig.label})
            </span>
          </div>

          {/* Overall Composite Score Bar */}
          <div>
            <div className="flex justify-between text-[11px] mb-1">
              <span className="text-slate-400">Composite Score:</span>
              <span className="font-bold text-white">{(q.overall_score * 100).toFixed(1)} / 100</span>
            </div>
            <div className="w-full bg-slate-800 rounded-full h-2">
              <div
                className="h-2 rounded-full transition-all"
                style={{
                  width: `${q.overall_score * 100}%`,
                  backgroundColor: styleConfig.indicatorColor,
                }}
              />
            </div>
          </div>

          {/* 5-Dimension Breakdown */}
          <div className="space-y-1.5 text-[10px]">
            <div className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">
              Five Quality Dimensions (IMPLEMENT.md §28)
            </div>

            {/* 1. Authority */}
            <div>
              <div className="flex justify-between text-slate-300">
                <span>Authority (25%):</span>
                <span>{(q.authority * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-slate-850 rounded-full h-1 mt-0.5">
                <div
                  className="bg-cyan-400 h-1 rounded-full"
                  style={{ width: `${q.authority * 100}%` }}
                />
              </div>
            </div>

            {/* 2. Accuracy */}
            <div>
              <div className="flex justify-between text-slate-300">
                <span>Accuracy (25%):</span>
                <span>{(q.accuracy * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-slate-850 rounded-full h-1 mt-0.5">
                <div
                  className="bg-emerald-400 h-1 rounded-full"
                  style={{ width: `${q.accuracy * 100}%` }}
                />
              </div>
            </div>

            {/* 3. Technical Depth */}
            <div>
              <div className="flex justify-between text-slate-300">
                <span>Technical Depth (20%):</span>
                <span>{(q.technical_depth * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-slate-850 rounded-full h-1 mt-0.5">
                <div
                  className="bg-purple-400 h-1 rounded-full"
                  style={{ width: `${q.technical_depth * 100}%` }}
                />
              </div>
            </div>

            {/* 4. Originality */}
            <div>
              <div className="flex justify-between text-slate-300">
                <span>Originality (15%):</span>
                <span>{(q.originality * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-slate-850 rounded-full h-1 mt-0.5">
                <div
                  className="bg-amber-400 h-1 rounded-full"
                  style={{ width: `${q.originality * 100}%` }}
                />
              </div>
            </div>

            {/* 5. Historical Reliability */}
            <div>
              <div className="flex justify-between text-slate-300">
                <span>Historical Reliability (15%):</span>
                <span>{(q.historical_reliability * 100).toFixed(0)}%</span>
              </div>
              <div className="w-full bg-slate-850 rounded-full h-1 mt-0.5">
                <div
                  className="bg-blue-400 h-1 rounded-full"
                  style={{ width: `${q.historical_reliability * 100}%` }}
                />
              </div>
            </div>
          </div>

          {/* Mandatory Disclaimer */}
          <div className="pt-2 border-t border-slate-800/80 text-[9px] text-slate-500 italic leading-snug">
            ⚠ Internal ranking mechanism — not an unquestionable truth score.
          </div>
        </div>
      )}
    </div>
  );
};
