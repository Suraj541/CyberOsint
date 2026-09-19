"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { NAV_ITEMS } from "./Sidebar";

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const router = useRouter();

  return (
    <header className="sticky top-0 z-20 bg-[#FFFDF5]/90 backdrop-blur-md border-b border-[#E4DBC8] h-16 flex items-center justify-between px-4 sm:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile menu hamburger */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-2 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8] text-[#171714] font-mono text-sm"
          aria-label="Toggle Navigation"
        >
          {mobileMenuOpen ? "✕" : "☰"}
        </button>

        <Link href="/" className="md:hidden flex items-center gap-2">
          <span className="w-7 h-7 rounded-md bg-[#C2821A] flex items-center justify-center font-mono font-bold text-white text-xs">
            ⚡
          </span>
          <span className="font-bold text-sm text-[#171714]">CYBER-OSINT</span>
        </Link>

        {/* Live Ingestion Alert / Ticker */}
        <div className="hidden lg:flex items-center gap-2 px-3.5 py-1.5 rounded-full bg-[#F1EBD8] border border-[#E4DBC8] text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-[#C2821A] animate-pulse" />
          <span className="text-[#68655B] font-semibold">INGESTION MONITOR:</span>
          <span className="text-[#171714]">CISA, NVD, MITRE & RSS Feeds Active</span>
        </div>
      </div>

      {/* Right Action Icons */}
      <div className="flex items-center gap-3">
        <Link
          href="/watchlists"
          className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] text-xs font-mono transition-colors"
        >
          <span>🎯 Watchlists</span>
        </Link>

        <Link
          href="/notifications"
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#B91C1C]/10 hover:bg-[#B91C1C]/15 border border-[#B91C1C]/25 text-[#B91C1C] text-xs font-mono transition-colors relative"
          title="Security Notifications & Alerts"
        >
          <span>🔔 Alerts</span>
          <span className="flex h-2 w-2 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#B91C1C] opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-[#B91C1C]"></span>
          </span>
        </Link>

        <Link
          href="/search"
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] text-xs font-mono transition-colors"
        >
          <span>⌕ Quick Search</span>
          <kbd className="hidden sm:inline px-1.5 py-0.5 rounded bg-[#E4DBC8] text-[#68655B] text-[10px] border border-[#D8CEB9]">
            Ctrl+K
          </kbd>
        </Link>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#2D7A4F]/10 border border-[#2D7A4F]/30 text-[#2D7A4F] text-xs font-mono font-semibold">
          <span className="w-2 h-2 rounded-full bg-[#2D7A4F]" />
          <span className="hidden sm:inline">FASTAPI</span> OK
        </div>
      </div>

      {/* Mobile Drawer Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden absolute top-16 left-0 right-0 bg-[#FFFDF5] border-b border-[#E4DBC8] p-4 space-y-1 shadow-xl">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono text-[#171714] hover:bg-[#F1EBD8]"
            >
              <div className="flex items-center gap-2">
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#E4DBC8] text-[#68655B]">
                  {item.badge}
                </span>
              )}
            </Link>
          ))}
        </div>
      )}
    </header>
  );
};
