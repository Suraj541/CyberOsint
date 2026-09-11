"use client";

import React, { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { NAV_ITEMS } from "./Sidebar";

export const Navbar: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const router = useRouter();

  return (
    <header className="sticky top-0 z-20 cyber-glass h-16 flex items-center justify-between px-4 sm:px-6">
      <div className="flex items-center gap-3">
        {/* Mobile menu hamburger */}
        <button
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="md:hidden p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 font-mono text-sm"
          aria-label="Toggle Navigation"
        >
          {mobileMenuOpen ? "✕" : "☰"}
        </button>

        <Link href="/" className="md:hidden flex items-center gap-2">
          <span className="w-7 h-7 rounded-md bg-cyan-500 flex items-center justify-center font-mono font-bold text-slate-950 text-xs">
            ⚡
          </span>
          <span className="font-bold text-sm text-white">CYBER-OSINT</span>
        </Link>

        {/* Live Ingestion Alert / Ticker */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-full bg-slate-900/90 border border-slate-800 text-xs font-mono">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          <span className="text-slate-400">INGESTION MONITOR:</span>
          <span className="text-cyan-300">CISA, NVD, RSS Feeds Active</span>
        </div>
      </div>

      {/* Right Action Icons */}
      <div className="flex items-center gap-3">
        <Link
          href="/search"
          className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-slate-800 text-slate-300 hover:text-white text-xs font-mono transition-colors"
        >
          <span>⌕ Quick Search</span>
          <kbd className="hidden sm:inline px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px] border border-slate-700">
            Ctrl+K
          </kbd>
        </Link>

        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-mono">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="hidden sm:inline">FASTAPI</span> OK
        </div>
      </div>

      {/* Mobile Drawer Dropdown */}
      {mobileMenuOpen && (
        <div className="md:hidden absolute top-16 left-0 right-0 bg-slate-950/95 border-b border-slate-800 p-4 space-y-1 shadow-2xl backdrop-blur-xl">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setMobileMenuOpen(false)}
              className="flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono text-slate-300 hover:bg-slate-900"
            >
              <div className="flex items-center gap-2">
                <span>{item.icon}</span>
                <span>{item.label}</span>
              </div>
              {item.badge && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
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
