"use client";

import React, { useEffect, useState } from "react";
import { fetchVulnerabilities } from "../../lib/api";
import { VulnerabilityItem } from "../../lib/types";
import { SeverityBadge } from "../../components/SeverityBadge";

export default function VulnerabilitiesPage() {
  const [cves, setCves] = useState<VulnerabilityItem[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterKevOnly, setFilterKevOnly] = useState(false);

  useEffect(() => {
    fetchVulnerabilities().then(setCves);
  }, []);

  const displayed = cves.filter((c) => {
    const matchSev = filterSeverity === "ALL" ? true : c.severity === filterSeverity;
    const matchKev = filterKevOnly ? c.is_exploited : true;
    return matchSev && matchKev;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <span className="text-xs font-mono text-red-400 uppercase tracking-wider block mb-1">
            CVE SURVEILLANCE & KEV FEED
          </span>
          <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
            Vulnerability Tracker
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Tracking actively exploited zero-days, CVSS v3.1 impact scores, and vendor patch advisories.
          </p>
        </div>

        {/* Filter Bar */}
        <div className="flex items-center gap-2 flex-wrap">
          {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
                filterSeverity === sev
                  ? "bg-red-500/20 text-red-300 font-bold border border-red-500/40"
                  : "bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800"
              }`}
            >
              {sev}
            </button>
          ))}
          <button
            onClick={() => setFilterKevOnly(!filterKevOnly)}
            className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
              filterKevOnly
                ? "bg-amber-500 text-slate-950 font-bold"
                : "bg-slate-900 text-amber-400 border border-amber-500/30"
            }`}
          >
            ★ CISA KEV Only
          </button>
        </div>
      </div>

      {/* CVE Table / Cards */}
      <div className="space-y-4">
        {displayed.map((cve) => (
          <div
            key={cve.cve_id}
            className="cyber-card rounded-xl p-5 border border-slate-800 hover:border-red-500/40 transition-colors"
          >
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-base font-bold font-mono text-cyan-300">
                  {cve.cve_id}
                </span>
                <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
                {cve.cwe_id && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
                    {cve.cwe_id}
                  </span>
                )}
                {cve.is_exploited && (
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 font-bold">
                    ACTIVE IN THE WILD
                  </span>
                )}
              </div>
              <span className="text-xs font-mono text-slate-500">
                Published: {new Date(cve.published_at).toLocaleDateString()}
              </span>
            </div>

            <p className="text-sm text-slate-300 mb-4 leading-relaxed">{cve.description}</p>

            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-800/80 text-xs font-mono">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-slate-500">AFFECTED:</span>
                {cve.affected_products && cve.affected_products.length > 0 ? (
                  cve.affected_products.map((p, idx) => (
                    <span
                      key={idx}
                      className="px-2 py-0.5 rounded bg-slate-900 text-emerald-400 border border-emerald-500/20"
                    >
                      {p}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-400">{cve.vendor || "Enterprise Appliances"}</span>
                )}
              </div>

              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-cyan-400 hover:underline flex items-center gap-1"
              >
                NVD Record &nearr;
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
