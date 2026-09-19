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
    cyan: "border-[#E4DBC8] hover:border-[#C2821A]",
    emerald: "border-[#E4DBC8] hover:border-[#2D7A4F]",
    amber: "border-[#E4DBC8] hover:border-[#D97706]",
    crimson: "border-[#E4DBC8] hover:border-[#B91C1C]",
    violet: "border-[#E4DBC8] hover:border-[#7C3AED]",
  }[accentColor];

  const accentIcons = {
    cyan: "text-[#C2821A] bg-[#F1EBD8]",
    emerald: "text-[#2D7A4F] bg-[#2D7A4F]/10",
    amber: "text-[#D97706] bg-[#F1EBD8]",
    crimson: "text-[#B91C1C] bg-[#B91C1C]/10",
    violet: "text-[#7C3AED] bg-[#7C3AED]/10",
  }[accentColor];

  return (
    <div
      className={`cyber-card rounded-2xl p-5 relative overflow-hidden transition-all duration-200 bg-[#FFFDF5] border shadow-sm ${accentBorders}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#68655B] font-mono">{title}</span>
        <span className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-sm border border-[#E4DBC8] ${accentIcons}`}>
          {iconText}
        </span>
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-extrabold tracking-tight text-[#171714] font-mono">{value}</span>
        {change && (
          <span
            className={`text-xs font-medium font-mono ${
              isPositive ? "text-[#2D7A4F]" : "text-[#B91C1C]"
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
