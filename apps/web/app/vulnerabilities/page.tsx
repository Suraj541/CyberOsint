"use client";

import React, { useEffect, useState } from "react";
import { fetchVulnerabilities } from "../../lib/api";
import { VulnerabilityItem } from "../../lib/types";
import { SeverityBadge } from "../../components/SeverityBadge";
import { formatDate } from "../../lib/formatters";

export default function VulnerabilitiesPage() {
  const [cves, setCves] = useState<VulnerabilityItem[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string>("ALL");
  const [filterKevOnly, setFilterKevOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");

  useEffect(() => {
    fetchVulnerabilities(100).then(setCves);
  }, []);

  const displayed = cves.filter((c) => {
    const matchSev = filterSeverity === "ALL" ? true : c.severity === filterSeverity;
    const matchKev = filterKevOnly ? c.is_exploited : true;
    const matchQuery = searchQuery.trim()
      ? c.cve_id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.description?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.vendor && c.vendor.toLowerCase().includes(searchQuery.toLowerCase()))
      : true;
    return matchSev && matchKev && matchQuery;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 border-b border-paper-border pb-5">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2.5 h-2.5 rounded-full bg-paper-danger animate-pulse" />
            <span className="text-[11px] font-mono tracking-widest uppercase text-paper-danger font-semibold">
              CVE SURVEILLANCE & KEV FEED
            </span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-serif font-bold text-paper-ink tracking-tight">
            Vulnerability Surveillance Dossier
          </h1>
          <p className="text-xs sm:text-sm text-paper-muted mt-1 max-w-2xl">
            Tracking actively exploited zero-days, CVSS v3.1 impact scores, and vendor patch advisories across national and vendor registries.
          </p>
        </div>

        {/* Search */}
        <div className="w-full md:w-64">
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter CVE or keyword..."
            className="w-full bg-paper-card border border-paper-border rounded-lg px-3 py-2 text-xs font-mono text-paper-ink placeholder:text-paper-muted focus:outline-none focus:border-paper-accent"
          />
        </div>
      </div>

      {/* Filter Bar */}
      <div className="flex items-center gap-2 flex-wrap bg-paper-panel border border-paper-border rounded-xl p-3">
        <span className="text-xs font-mono text-paper-muted mr-1 font-semibold">SEVERITY:</span>
        {["ALL", "CRITICAL", "HIGH", "MEDIUM"].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
              filterSeverity === sev
                ? "bg-paper-ink text-paper-card font-bold"
                : "bg-paper-card text-paper-muted hover:text-paper-ink border border-paper-border"
            }`}
          >
            {sev}
          </button>
        ))}

        <div className="h-4 w-px bg-paper-border mx-1" />

        <button
          onClick={() => setFilterKevOnly(!filterKevOnly)}
          className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors ${
            filterKevOnly
              ? "bg-amber-600 text-white font-bold"
              : "bg-paper-card text-amber-700 border border-amber-300 hover:bg-amber-50"
          }`}
        >
          ★ CISA KEV Exploited Only
        </button>

        <span className="ml-auto text-xs font-mono text-paper-muted">
          Showing {displayed.length} of {cves.length} vulnerabilities
        </span>
      </div>

      {/* CVE Table / Cards */}
      <div className="space-y-4">
        {displayed.length === 0 ? (
          <div className="text-center py-16 bg-paper-card border border-paper-border rounded-xl p-8">
            <p className="text-xs font-mono text-paper-muted">No vulnerability records match current filters.</p>
          </div>
        ) : (
          displayed.map((cve) => (
            <div
              key={cve.cve_id}
              className="bg-paper-card rounded-xl p-5 border border-paper-border hover:border-paper-accent shadow-sm transition-all"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="text-base font-bold font-mono text-paper-ink">
                    {cve.cve_id}
                  </span>
                  <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
                  {cve.cwe_id && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-paper-panel text-paper-muted border border-paper-border">
                      {cve.cwe_id}
                    </span>
                  )}
                  {cve.is_exploited && (
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-red-100 text-red-800 border border-red-200 font-bold">
                      ACTIVE IN THE WILD
                    </span>
                  )}
                </div>
                <span className="text-xs font-mono text-paper-muted">
                  Published: {formatDate(cve.published_at)}
                </span>
              </div>

              <p className="text-sm text-paper-ink/80 mb-4 leading-relaxed font-sans">{cve.description}</p>

              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-paper-border text-xs font-mono">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-paper-muted">AFFECTED:</span>
                  {cve.affected_products && cve.affected_products.length > 0 ? (
                    cve.affected_products.map((p, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-paper-panel text-paper-success border border-paper-border"
                      >
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-paper-muted">{cve.vendor || "General / Unspecified"}</span>
                  )}
                </div>

                <a
                  href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-paper-accent hover:underline flex items-center gap-1 font-semibold"
                >
                  NVD Official Record &nearr;
                </a>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
