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
  { href: "/documents", label: "Documents", icon: "📄", badge: null },
  { href: "/intelligence", label: "Intelligence", icon: "⚡", badge: "ACTORS" },
  { href: "/graph", label: "Knowledge Graph", icon: "🕸", badge: "GRAPH" },
  { href: "/watchlists", label: "Watchlists", icon: "🎯", badge: "INTEL" },
  { href: "/notifications", label: "Notifications", icon: "🔔", badge: "ALERTS" },
  { href: "/sources", label: "Sources", icon: "🖧", badge: null },
  { href: "/secrets", label: "Secret Vault", icon: "🔒", badge: "SEC 35" },
  { href: "/security", label: "Security Center", icon: "🛡️", badge: "SEC 36" },
  { href: "/scale", label: "Scale & Arch", icon: "🌐", badge: "V4" },
  { href: "/readiness", label: "System Readiness", icon: "✓", badge: "DoD" },
];

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  return (
    <aside className="w-64 h-screen sticky top-0 hidden md:flex flex-col bg-[#F1EBD8] border-r border-[#E4DBC8] select-none z-30">
      {/* Brand Header */}
      <div className="p-5 border-b border-[#E4DBC8] flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-[#C2821A] flex items-center justify-center font-mono font-black text-white text-base shadow-sm group-hover:scale-105 transition-transform">
            ⚡
          </div>
          <div>
            <span className="font-bold tracking-tight text-[#171714] text-sm block">
              CYBER<span className="text-[#C2821A]">OSINT</span>
            </span>
            <span className="text-[10px] font-mono text-[#68655B] tracking-wider block font-semibold">
              INTEL WORKSTATION
            </span>
          </div>
        </Link>
        <span className="w-2.5 h-2.5 rounded-full bg-[#2D7A4F] status-pulse" title="System Operational" />
      </div>

      {/* Navigation Links */}
      <div className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
        <div className="px-3 pb-2 text-[11px] font-mono uppercase tracking-wider text-[#68655B] font-bold">
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
                  ? "bg-[#FFFDF5] text-[#171714] font-bold border border-[#E4DBC8] shadow-sm"
                  : "text-[#68655B] hover:text-[#171714] hover:bg-[#EAE3CE]"
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-sm opacity-90">{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#E4DBC8] text-[#55524A] border border-[#D8CEB9] font-medium">
                  {item.badge}
                </span>
              )}
            </Link>
          );
        })}
      </div>

      {/* Footer / Telemetry status */}
      <div className="p-4 border-t border-[#E4DBC8] bg-[#EAE3CE]/50 text-xs font-mono">
        <div className="flex items-center justify-between text-[#68655B] mb-1">
          <span className="text-[11px] uppercase tracking-wider">ARCHIVAL DOSSIER</span>
          <span className="text-[#2D7A4F] font-bold text-[11px]">ONLINE</span>
        </div>
        <div className="text-[10px] text-[#8C887B]">PostgreSQL 16 &bull; Hybrid RRF</div>
      </div>
    </aside>
  );
};
