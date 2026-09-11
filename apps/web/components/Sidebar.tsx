"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: "❖", badge: null },
  { href: "/search", label: "Search Engine", icon: "⌕", badge: "RRF" },
  { href: "/news", label: "News Feed", icon: "📰", badge: null },
  { href: "/research", label: "Research", icon: "🔬", badge: null },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: "🛡", badge: "KEV" },
  { href: "/tools", label: "Tools", icon: "⚙", badge: null },
  { href: "/videos", label: "Videos", icon: "▶", badge: null },
  { href: "/documents", label: "Documents", icon: "📄", badge: null },
  { href: "/intelligence", label: "Intelligence", icon: "⚡", badge: "ACTORS" },
  { href: "/sources", label: "Sources", icon: "🖧", badge: null },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen sticky top-0 hidden md:flex flex-col bg-[#070b12] border-r border-slate-800/80 select-none z-30">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-mono font-black text-slate-950 text-base shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
            ⚡
          </div>
          <div>
            <span className="font-bold tracking-tight text-white text-sm block">
              CYBER<span className="text-cyan-400">OSINT</span>
            </span>
            <span className="text-[10px] font-mono text-slate-500 tracking-wider block">
              INTEL CENTER
            </span>
          </div>
        </Link>
        <span className="w-2 h-2 rounded-full bg-emerald-500 status-pulse" title="System Operational" />
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
        <div className="px-3 pb-2 text-[11px] font-mono uppercase tracking-wider text-slate-500">
          Navigation
        </div>
        {NAV_ITEMS.map((item) => {
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-mono transition-all ${
                isActive
                  ? "bg-cyan-500/10 text-cyan-300 font-semibold border border-cyan-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-sm opacity-80">{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </div>

      {/* Footer / Telemetry status */}
      <div className="p-4 border-t border-slate-800/80 bg-slate-950/40 text-xs font-mono">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="text-[11px]">INSPECTION MODE</span>
          <span className="text-emerald-400 text-[11px]">ONLINE</span>
        </div>
        <div className="text-[10px] text-slate-600">v1.0.0 &bull; Section 20 Conformance</div>
      </div>
    </aside>
  );
};
