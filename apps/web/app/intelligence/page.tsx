"use client";

import React, { useEffect, useState } from "react";
import { fetchThreatIntelligence } from "../../lib/api";
import { ThreatIntelligenceItem } from "../../lib/types";

export default function IntelligencePage() {
  const [intelList, setIntelList] = useState<ThreatIntelligenceItem[]>([]);

  useEffect(() => {
    fetchThreatIntelligence().then(setIntelList);
  }, []);

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="border-b border-slate-800 pb-5">
        <span className="text-xs font-mono text-amber-400 uppercase tracking-wider block mb-1">
          THREAT ACTORS & ADVERSARY TTPs
        </span>
        <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
          Adversary Profiles & Campaign Intelligence
        </h1>
        <p className="text-xs sm:text-sm text-slate-400 mt-1">
          Detailed behavioral profiles of nation-state APTs, cybercrime syndicates, targeted infrastructure, and MITRE ATT&CK techniques.
        </p>
      </div>

      <div className="space-y-6">
        {intelList.map((item) => (
          <div
            key={item.id}
            className="cyber-card rounded-xl p-6 border border-slate-800 hover:border-amber-500/40 transition-colors"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4 pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-3">
                <span className="w-3 h-3 rounded-full bg-amber-400 status-pulse" />
                <h3 className="text-lg font-bold text-white font-mono">{item.threat_actor}</h3>
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-amber-400 border border-amber-500/20">
                  {(item.confidence * 100).toFixed(0)}% Confidence
                </span>
              </div>
              <span className="text-xs font-mono text-slate-500">Source: {item.source}</span>
            </div>

            <h4 className="text-base font-semibold text-slate-200 mb-2">{item.title}</h4>
            <p className="text-sm text-slate-400 mb-5 leading-relaxed">{item.summary}</p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 rounded-lg bg-slate-950/60 border border-slate-800/80 font-mono text-xs">
              {/* Target Sectors */}
              <div>
                <span className="text-slate-500 block mb-2 uppercase">Targeted Sectors</span>
                <div className="flex flex-wrap gap-1.5">
                  {item.target_sectors?.map((sec, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-800"
                    >
                      {sec}
                    </span>
                  ))}
                </div>
              </div>

              {/* Malware Families */}
              <div>
                <span className="text-slate-500 block mb-2 uppercase">Associated Malware</span>
                <div className="flex flex-wrap gap-1.5">
                  {item.malware_families?.map((m, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 border border-red-500/20"
                    >
                      {m}
                    </span>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK */}
              <div>
                <span className="text-slate-500 block mb-2 uppercase">MITRE ATT&CK</span>
                <div className="flex flex-wrap gap-1.5">
                  {item.mitre_techniques?.map((t, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
