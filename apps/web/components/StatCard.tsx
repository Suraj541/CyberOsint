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
    cyan: "border-[#E4DBC8] dark:border-[#222734] hover:border-[#C2821A] dark:hover:border-[#E5A93B]",
    emerald: "border-[#E4DBC8] dark:border-[#222734] hover:border-[#2D7A4F] dark:hover:border-[#4ADE80]",
    amber: "border-[#E4DBC8] dark:border-[#222734] hover:border-[#D97706] dark:hover:border-[#F59E0B]",
    crimson: "border-[#E4DBC8] dark:border-[#222734] hover:border-[#B91C1C] dark:hover:border-[#EF4444]",
    violet: "border-[#E4DBC8] dark:border-[#222734] hover:border-[#7C3AED] dark:hover:border-[#A855F7]",
  }[accentColor];

  const accentIcons = {
    cyan: "text-[#C2821A] dark:text-[#E5A93B] bg-[#F1EBD8] dark:bg-[#161B26]",
    emerald: "text-[#2D7A4F] dark:text-[#4ADE80] bg-[#2D7A4F]/10",
    amber: "text-[#D97706] dark:text-[#F59E0B] bg-[#F1EBD8] dark:bg-[#161B26]",
    crimson: "text-[#B91C1C] dark:text-[#EF4444] bg-[#B91C1C]/10",
    violet: "text-[#7C3AED] dark:text-[#A855F7] bg-[#7C3AED]/10",
  }[accentColor];

  return (
    <div
      className={`cyber-card rounded-2xl p-5 relative overflow-hidden transition-all duration-200 bg-[#FFFDF5] dark:bg-[#0F1218] border shadow-sm ${accentBorders}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#68655B] dark:text-slate-300 font-mono">{title}</span>
        <span className={`w-8 h-8 rounded-lg flex items-center justify-center font-mono text-sm border border-[#E4DBC8] dark:border-[#2D3446] ${accentIcons}`}>
          {iconText}
        </span>
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-3xl font-extrabold tracking-tight text-[#171714] dark:text-white font-mono">{value}</span>
        {change && (
          <span
            className={`text-xs font-medium font-mono ${
              isPositive ? "text-[#2D7A4F] dark:text-[#4ADE80]" : "text-[#B91C1C] dark:text-[#EF4444]"
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
