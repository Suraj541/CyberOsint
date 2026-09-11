import React from "react";

interface Props {
  title: string;
  value: string | number;
  change?: string;
  isPositive?: boolean;
  accentColor?: "cyan" | "emerald" | "amber" | "crimson" | "violet";
  iconText?: string;
}

export const StatCard: React.FC<Props> = ({
  title,
  value,
  change,
  isPositive = true,
  accentColor = "cyan",
  iconText = "◈",
}) => {
  const accentBorders = {
    cyan: "border-cyan-500/20 hover:border-cyan-500/50",
    emerald: "border-emerald-500/20 hover:border-emerald-500/50",
    amber: "border-amber-500/20 hover:border-amber-500/50",
    crimson: "border-red-500/20 hover:border-red-500/50",
    violet: "border-violet-500/20 hover:border-violet-500/50",
  }[accentColor];

  const accentIcons = {
    cyan: "text-cyan-400 bg-cyan-500/10",
    emerald: "text-emerald-400 bg-emerald-500/10",
    amber: "text-amber-400 bg-amber-500/10",
    crimson: "text-red-400 bg-red-500/10",
    violet: "text-violet-400 bg-violet-500/10",
  }[accentColor];

  return (
    <div
      className={`cyber-card rounded-xl p-5 relative overflow-hidden transition-all duration-200 ${accentBorders}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</span>
        <span className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-sm ${accentIcons}`}>
          {iconText}
        </span>
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-bold tracking-tight text-white font-mono">{value}</span>
        {change && (
          <span
            className={`text-xs font-medium font-mono ${
              isPositive ? "text-emerald-400" : "text-red-400"
            }`}
          >
            {isPositive ? "+" : ""}
            {change}
          </span>
        )}
      </div>
    </div>
  );
};
