"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { fetchEntityById } from "../../../lib/api";
import { EntityDetail, SeverityLevel } from "../../../lib/types";
import { SeverityBadge } from "../../../components/SeverityBadge";
import { ContentCard } from "../../../components/ContentCard";

export default function EntityDetailPage() {
  const params = useParams();
  const router = useRouter();
  const rawId = Array.isArray(params?.id) ? params.id[0] : params?.id;
  const entityParam = decodeURIComponent(rawId || "");

  const [entity, setEntity] = useState<EntityDetail | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadEntity() {
      if (!entityParam) return;
      setLoading(true);
      try {
        const data = await fetchEntityById(entityParam);
        setEntity(data);
      } catch (err) {
        console.error("Failed to load entity:", err);
      } finally {
        setLoading(false);
      }
    }
    loadEntity();
  }, [entityParam]);

  if (loading) {
    return (
      <div className="py-24 text-center font-mono text-sm text-slate-500 animate-pulse">
        Retrieving entity intelligence profile for &apos;{entityParam}&apos;...
      </div>
    );
  }

  if (!entity) {
    return (
      <div className="cyber-card rounded-2xl p-12 text-center max-w-xl mx-auto my-12">
        <h2 className="text-xl font-bold text-white mb-2 font-mono">Entity Profile Not Found</h2>
        <p className="text-sm text-slate-400 mb-6">
          The requested entity &apos;{entityParam}&apos; could not be resolved from active intelligence records.
        </p>
        <Link
          href="/"
          className="px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-bold font-mono text-xs inline-block"
        >
          &larr; Return to Dashboard
        </Link>
      </div>
    );
  }

  const isCVE = entity.entity_type.toLowerCase() === "cve";
  const isMalware = ["malware", "threat_actor"].includes(entity.entity_type.toLowerCase());

  return (
    <article className="space-y-8 animate-in fade-in duration-200 max-w-5xl mx-auto pb-16">
      {/* Breadcrumbs & Navigation */}
      <div className="flex items-center justify-between text-xs font-mono text-slate-500 border-b border-slate-800/80 pb-4">
        <div className="flex items-center gap-2">
          <button
            onClick={() => router.back()}
            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-semibold"
          >
            &larr; Back
          </button>
          <span>/</span>
          <span className="text-slate-400 uppercase">Entities</span>
          <span>/</span>
          <span className="text-emerald-400 uppercase">{entity.entity_type}</span>
          <span>/</span>
          <span className="text-slate-300 font-bold">{entity.name}</span>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-[11px] px-2.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
            {entity.content_count} Correlated Intelligence Records
          </span>
        </div>
      </div>

      {/* Entity Header Banner */}
      <div className="p-6 md:p-8 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-950 to-slate-900 border border-slate-800 shadow-xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 relative z-10">
          <div className="space-y-3 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono uppercase px-2.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-bold tracking-wider">
                {isCVE ? "VULNERABILITY INTELLIGENCE" : isMalware ? "THREAT INTELLIGENCE PROFILE" : "ENTITY INTELLIGENCE"}
              </span>
              <span className="text-xs font-mono text-slate-400 px-2 py-0.5 rounded bg-slate-800 border border-slate-700">
                ID #{entity.id}
              </span>
              <span className="text-xs font-mono text-emerald-400 px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-500/30">
                Normalized: {entity.normalized_name}
              </span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight font-mono">
              {entity.name}
            </h1>

            {/* Overview Section */}
            <div className="pt-2">
              <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold mb-1">
                Overview
              </h2>
              <p className="text-sm md:text-base text-slate-300 leading-relaxed">
                {entity.description || "No extended profile description recorded in knowledge graph."}
              </p>
            </div>
          </div>

          {/* Quick Stats / CVSS Highlight */}
          {isCVE && entity.severity && (
            <div className="shrink-0 p-4 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col items-center text-center min-w-[150px]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 mb-1">
                Severity Rating
              </span>
              <div className="my-1">
                <SeverityBadge
                  severity={(entity.severity.severity_rating as SeverityLevel) || "CRITICAL"}
                  score={entity.severity.cvss_score}
                />
              </div>
              {entity.severity.cvss_score !== undefined && (
                <span className="text-2xl font-mono font-extrabold text-white mt-1">
                  {entity.severity.cvss_score.toFixed(1)}
                  <span className="text-xs text-slate-500 font-normal"> / 10.0</span>
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. CVE SPECIFIC SECTIONS                                                  */}
      {/* Conforms strictly to IMPLEMENT.md Section 23:                             */}
      {/* Overview, Severity, Affected Products, References, Articles, Reports,     */}
      {/* Related Entities, Timeline                                                */}
      {/* ========================================================================= */}
      {isCVE && (
        <div className="space-y-8">
          {/* Section: Severity Details */}
          {entity.severity && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
                  <span>◈</span> Vulnerability Severity Metrics
                </h2>
                <span className="text-xs font-mono text-slate-500">CVSS v3.1 / v2.0 Standard</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs font-mono text-slate-400 block mb-1">Base Score & Rating</span>
                  <div className="flex items-center gap-3">
                    <span className="text-xl font-mono font-bold text-white">
                      {entity.severity.cvss_score !== undefined ? entity.severity.cvss_score.toFixed(1) : "N/A"}
                    </span>
                    {entity.severity.severity_rating && (
                      <SeverityBadge severity={entity.severity.severity_rating as SeverityLevel} />
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs font-mono text-slate-400 block mb-1">CWE Weakness Type</span>
                  <span className="text-sm font-mono font-bold text-emerald-400">
                    {entity.severity.cwe_id || "Unclassified Weakness"}
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
                  <span className="text-xs font-mono text-slate-400 block mb-1">Exploitability Vector</span>
                  <span className="text-xs font-mono text-slate-300 break-all">
                    {entity.severity.vector_string || "Vector string not provided"}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* Section: Affected Products */}
          {entity.affected_products && entity.affected_products.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
                  <span>◈</span> Affected Products & Platforms
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.affected_products.length} Impacted Assets
                </span>
              </div>

              <div className="flex flex-wrap gap-2.5">
                {entity.affected_products.map((prod, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono flex items-center gap-2 hover:border-cyan-500/40 transition-colors"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                    {prod}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Section: References */}
          {entity.references && entity.references.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
                  <span>◈</span> Official References & Advisories
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.references.length} Authoritative Links
                </span>
              </div>

              <ul className="divide-y divide-slate-800/60 font-mono text-xs">
                {entity.references.map((refUrl, idx) => (
                  <li key={idx} className="py-2.5 flex items-center justify-between gap-4">
                    <a
                      href={refUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-cyan-400 hover:text-cyan-300 hover:underline truncate max-w-2xl flex items-center gap-1.5"
                    >
                      <span>&nearr;</span>
                      <span className="truncate">{refUrl}</span>
                    </a>
                    <span className="text-slate-500 shrink-0 uppercase text-[10px]">Verified Link</span>
                  </li>
                ))}
              </ul>
            </section>
          )}

          {/* Section: Articles */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <span className="text-cyan-400 font-mono">◈</span> Correlated Articles & News
              </h2>
              <span className="text-xs font-mono text-slate-500">
                {entity.articles?.length || 0} Articles Linked
              </span>
            </div>

            {entity.articles && entity.articles.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {entity.articles.map((art) => (
                  <Link key={art.id} href={`/content/${art.id}`} className="block">
                    <ContentCard item={art} />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="cyber-card rounded-xl p-6 text-center text-xs font-mono text-slate-500">
                No external news reporting articles directly associated with this CVE.
              </div>
            )}
          </section>

          {/* Section: Reports */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <span className="text-violet-400 font-mono">◈</span> Technical Reports & Security Bulletins
              </h2>
              <span className="text-xs font-mono text-slate-500">
                {entity.reports?.length || 0} Reports Linked
              </span>
            </div>

            {entity.reports && entity.reports.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {entity.reports.map((rep) => (
                  <Link key={rep.id} href={`/content/${rep.id}`} className="block">
                    <ContentCard item={rep} />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="cyber-card rounded-xl p-6 text-center text-xs font-mono text-slate-500">
                No dedicated research advisories or bulletin reports linked yet.
              </div>
            )}
          </section>

          {/* Section: Related Entities */}
          {entity.related_entities && entity.related_entities.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-2">
                  <span>◈</span> Related Entities in Knowledge Graph
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.related_entities.length} Associations
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
                {entity.related_entities.map((rel) => (
                  <Link
                    key={rel.id}
                    href={`/entities/${rel.id}`}
                    className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-emerald-500/40 transition-colors flex items-center justify-between group"
                  >
                    <div>
                      <span className="font-bold text-slate-200 group-hover:text-emerald-400 block transition-colors">
                        {rel.name}
                      </span>
                      <span className="text-[10px] text-slate-500 uppercase">{rel.entity_type}</span>
                    </div>
                    {rel.mention_count && rel.mention_count > 1 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                        {rel.mention_count}x co-occur
                      </span>
                    )}
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Section: Timeline */}
          {entity.timeline && entity.timeline.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-2">
                  <span>◈</span> Vulnerability Activity Timeline
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.timeline.length} Milestones
                </span>
              </div>

              <div className="relative pl-6 border-l border-slate-800 space-y-6 font-mono text-xs">
                {entity.timeline.map((evt, idx) => (
                  <div key={idx} className="relative group">
                    <div className="absolute -left-[31px] top-0.5 w-3 h-3 rounded-full bg-slate-900 border-2 border-amber-400 group-hover:bg-amber-400 transition-colors" />
                    <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                      <span className="font-bold text-slate-200 text-sm">{evt.title}</span>
                      <span className="text-[11px] text-slate-500">{evt.date ? new Date(evt.date).toLocaleDateString() : "Undated"}</span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="px-2 py-0.5 rounded bg-slate-900 text-amber-300/80 border border-slate-800 uppercase">
                        {evt.event_type}
                      </span>
                      {evt.url && (
                        <a
                          href={evt.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline flex items-center gap-0.5"
                        >
                          Source &nearr;
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. MALWARE SPECIFIC SECTIONS                                              */}
      {/* Conforms strictly to IMPLEMENT.md Section 23:                             */}
      {/* Overview, Aliases, Threat Actors, Campaigns, Techniques, Reports, Tools,  */}
      {/* Timeline                                                                  */}
      {/* ========================================================================= */}
      {isMalware && (
        <div className="space-y-8">
          {/* Section: Aliases */}
          {entity.aliases && entity.aliases.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-cyan-400 font-bold flex items-center gap-2">
                  <span>◈</span> Known Aliases & Strain Names
                </h2>
                <span className="text-xs font-mono text-slate-500">{entity.aliases.length} Known Variations</span>
              </div>

              <div className="flex flex-wrap gap-2">
                {entity.aliases.map((alias, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-cyan-300 text-xs font-mono font-medium"
                  >
                    {alias}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Section: Threat Actors */}
          {entity.threat_actors && entity.threat_actors.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-rose-400 font-bold flex items-center gap-2">
                  <span>◈</span> Associated Threat Actors & Syndicates
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.threat_actors.length} Operators
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                {entity.threat_actors.map((actor) => (
                  <Link
                    key={actor.id}
                    href={`/entities/${actor.id}`}
                    className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-rose-500/40 transition-colors flex items-center justify-between group"
                  >
                    <div>
                      <span className="font-bold text-white group-hover:text-rose-400 block text-sm transition-colors">
                        {actor.name}
                      </span>
                      <span className="text-[11px] text-slate-400 line-clamp-1">
                        {actor.description || "State-sponsored or cybercrime syndicate"}
                      </span>
                    </div>
                    <span className="text-rose-400 text-sm group-hover:translate-x-1 transition-transform">
                      &rarr;
                    </span>
                  </Link>
                ))}
              </div>
            </section>
          )}

          {/* Section: Campaigns */}
          {entity.campaigns && entity.campaigns.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-2">
                  <span>◈</span> Active & Historical Campaigns
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.campaigns.length} Operations
                </span>
              </div>

              <div className="flex flex-wrap gap-2.5">
                {entity.campaigns.map((camp, idx) => (
                  <span
                    key={idx}
                    className="px-3.5 py-1.5 rounded-lg bg-amber-950/20 border border-amber-500/30 text-amber-300 text-xs font-mono font-medium flex items-center gap-2"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                    {camp}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Section: Techniques (MITRE ATT&CK) */}
          {entity.techniques && entity.techniques.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-violet-400 font-bold flex items-center gap-2">
                  <span>◈</span> MITRE ATT&CK Techniques Employed
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.techniques.length} Techniques Mapped
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 font-mono text-xs">
                {entity.techniques.map((tech) => (
                  <div
                    key={tech.id}
                    className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between"
                  >
                    <div>
                      <span className="font-bold text-violet-300 block">{tech.name}</span>
                      <span className="text-[10px] text-slate-500">Tactics, Techniques & Procedures</span>
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-violet-950/40 text-violet-300 border border-violet-500/30">
                      TTP
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Section: Reports */}
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                <span className="text-cyan-400 font-mono">◈</span> Threat Intelligence & DFIR Reports
              </h2>
              <span className="text-xs font-mono text-slate-500">
                {entity.reports?.length || 0} Reports Available
              </span>
            </div>

            {entity.reports && entity.reports.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {entity.reports.map((rep) => (
                  <Link key={rep.id} href={`/content/${rep.id}`} className="block">
                    <ContentCard item={rep} />
                  </Link>
                ))}
              </div>
            ) : (
              <div className="cyber-card rounded-xl p-6 text-center text-xs font-mono text-slate-500">
                No technical reverse-engineering reports linked yet.
              </div>
            )}
          </section>

          {/* Section: Tools */}
          {entity.tools && entity.tools.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-2">
                  <span>◈</span> Associated Post-Exploitation & Hacking Tools
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.tools.length} Tools Identified
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 font-mono text-xs">
                {entity.tools.map((t) => (
                  <div
                    key={t.id}
                    className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col justify-between"
                  >
                    <span className="font-bold text-emerald-400 block mb-1">{t.name}</span>
                    <span className="text-[10px] text-slate-400 line-clamp-2">
                      {t.description || "Adversary utility / dual-use tool"}
                    </span>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* Section: Timeline */}
          {entity.timeline && entity.timeline.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-2">
                  <span>◈</span> Threat Evolution Timeline
                </h2>
                <span className="text-xs font-mono text-slate-500">
                  {entity.timeline.length} Recorded Milestones
                </span>
              </div>

              <div className="relative pl-6 border-l border-slate-800 space-y-6 font-mono text-xs">
                {entity.timeline.map((evt, idx) => (
                  <div key={idx} className="relative group">
                    <div className="absolute -left-[31px] top-0.5 w-3 h-3 rounded-full bg-slate-900 border-2 border-amber-400 group-hover:bg-amber-400 transition-colors" />
                    <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                      <span className="font-bold text-slate-200 text-sm">{evt.title}</span>
                      <span className="text-[11px] text-slate-500">{evt.date ? new Date(evt.date).toLocaleDateString() : "Undated"}</span>
                    </div>
                    <div className="flex items-center gap-2 text-[11px]">
                      <span className="px-2 py-0.5 rounded bg-slate-900 text-amber-300/80 border border-slate-800 uppercase">
                        {evt.event_type}
                      </span>
                      {evt.url && (
                        <a
                          href={evt.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-cyan-400 hover:underline flex items-center gap-0.5"
                        >
                          Details &nearr;
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. GENERIC / OTHER ENTITIES FALLBACK                                      */}
      {/* ========================================================================= */}
      {!isCVE && !isMalware && (
        <div className="space-y-8">
          {/* Articles & Reports */}
          <section className="space-y-4">
            <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-cyan-400 font-mono">◈</span> Correlated Intelligence Items
            </h2>

            {entity.linked_content && entity.linked_content.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {entity.linked_content.map((link) => (
                  <Link key={link.content_id} href={`/content/${link.content_id}`} className="block">
                    <div className="cyber-card rounded-xl p-5 hover:border-cyan-500/40 transition-colors">
                      <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-2">
                        <span className="uppercase text-cyan-400">{link.content_type}</span>
                        <span>{link.published_at ? new Date(link.published_at).toLocaleDateString() : "Recent"}</span>
                      </div>
                      <h3 className="font-bold text-white mb-2 line-clamp-2">{link.title}</h3>
                      {link.context_snippet && (
                        <p className="text-xs text-slate-400 line-clamp-2 font-mono">
                          {link.context_snippet}
                        </p>
                      )}
                    </div>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="cyber-card rounded-xl p-6 text-center text-xs font-mono text-slate-500">
                No items directly correlated with this entity.
              </div>
            )}
          </section>

          {/* Related Entities */}
          {entity.related_entities && entity.related_entities.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <h2 className="text-sm font-mono uppercase tracking-wider text-emerald-400 font-bold flex items-center gap-2">
                <span>◈</span> Co-Occurring Entities
              </h2>
              <div className="flex flex-wrap gap-2">
                {entity.related_entities.map((rel) => (
                  <Link
                    key={rel.id}
                    href={`/entities/${rel.id}`}
                    className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:border-emerald-500/40 text-xs font-mono text-slate-300"
                  >
                    {rel.name} <span className="text-slate-500 uppercase text-[10px]">({rel.entity_type})</span>
                  </Link>
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </article>
  );
}
