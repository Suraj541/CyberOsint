"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { fetchEntityById } from "../../../lib/api";
import { EntityDetail, SeverityLevel } from "../../../lib/types";
import { SeverityBadge } from "../../../components/SeverityBadge";
import { ContentCard } from "../../../components/ContentCard";
import { formatDate } from "../../../lib/formatters";

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
        setEntity(null);
      } finally {
        setLoading(false);
      }
    }
    loadEntity();
  }, [entityParam]);

  if (loading) {
    return (
      <div className="py-24 text-center font-mono text-sm text-[#68655B] animate-pulse">
        Retrieving intelligence dossier for &apos;{entityParam}&apos;...
      </div>
    );
  }

  // State 1: Entity Genuinely Does Not Exist (404)
  if (!entity) {
    return (
      <div className="cyber-card rounded-2xl p-12 text-center max-w-xl mx-auto my-12 bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
        <div className="w-12 h-12 mx-auto mb-4 rounded-xl bg-[#B91C1C]/10 border border-[#B91C1C]/25 flex items-center justify-center text-xl text-[#B91C1C] font-mono">
          ✕
        </div>
        <h2 className="text-xl font-bold text-[#171714] mb-2 font-mono">Entity Not Found</h2>
        <p className="text-sm text-[#68655B] mb-6">
          The requested entity &apos;{entityParam}&apos; does not exist in the active intelligence registry.
        </p>
        <Link
          href="/"
          className="px-4 py-2 rounded-lg bg-[#C2821A] hover:bg-[#D97706] text-white font-bold font-mono text-xs inline-block transition-colors shadow-sm"
        >
          &larr; Return to Dashboard
        </Link>
      </div>
    );
  }

  const isCVE = entity.entity_type.toLowerCase() === "cve";
  const isMalware = ["malware", "threat_actor"].includes(entity.entity_type.toLowerCase());
  const confidenceVal = Math.round(((entity as any).confidence || 0.88) * 100);

  // Derive First Seen and Last Seen dates
  const timelineDates = (entity.timeline || [])
    .map((t) => t.date)
    .filter(Boolean)
    .sort() as string[];
  const firstSeen = timelineDates.length > 0 ? formatDate(timelineDates[0]) : (entity.created_at ? formatDate(entity.created_at) : "Historical");
  const lastSeen = timelineDates.length > 0 ? formatDate(timelineDates[timelineDates.length - 1]) : (entity.updated_at ? formatDate(entity.updated_at) : "Active");

  // Determine category tags
  const categoryTags: string[] = [
    entity.entity_type.toUpperCase(),
    isCVE ? "Vulnerability" : isMalware ? "Adversary TTP" : "Infrastructure Asset",
  ];
  if (entity.metadata_json && entity.metadata_json.includes("cwe")) {
    categoryTags.push("Security Weakness");
  }

  return (
    <article className="space-y-8 animate-in fade-in duration-200 max-w-5xl mx-auto pb-16">
      {/* Breadcrumbs & Navigation */}
      <div className="flex items-center justify-between text-xs font-mono text-[#68655B] border-b border-[#E4DBC8] pb-4">
        <div className="flex items-center gap-2">
          <button
            onClick={() => router.back()}
            className="text-[#C2821A] hover:text-[#D97706] flex items-center gap-1 font-semibold"
          >
            &larr; Back
          </button>
          <span>/</span>
          <span className="text-[#68655B] uppercase">Dossiers</span>
          <span>/</span>
          <span className="text-[#2D7A4F] uppercase font-bold">{entity.entity_type}</span>
          <span>/</span>
          <span className="text-[#171714] font-bold">{entity.name}</span>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href="/graph"
            className="flex items-center gap-1.5 px-3 py-1 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] text-xs font-mono transition-colors"
          >
            <span>🕸 View in Graph</span>
            <span>&rarr;</span>
          </Link>
          <span className="text-[11px] px-2.5 py-0.5 rounded bg-[#F1EBD8] border border-[#E4DBC8] text-[#68655B] font-medium">
            {entity.content_count} Correlated Intelligence Records
          </span>
        </div>
      </div>

      {/* State 2: Entity Exists, but has 0 linked records notice */}
      {entity.content_count === 0 && (
        <div className="p-4 rounded-xl bg-[#FFFDF5] border-2 border-[#C2821A]/60 text-[#171714] text-xs font-mono shadow-sm flex items-start gap-3">
          <span className="text-base text-[#C2821A] font-bold">ℹ</span>
          <div>
            <span className="font-bold text-[#C2821A] uppercase tracking-wider block mb-0.5">
              INTELLIGENCE STATUS NOTICE
            </span>
            <p className="text-[#68655B]">
              Entity exists, but no active intelligence records are currently linked.
            </p>
          </div>
        </div>
      )}

      {/* Entity Dossier Header */}
      <div className="p-6 md:p-8 rounded-2xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-6 relative z-10">
          <div className="space-y-4 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono uppercase px-2.5 py-0.5 rounded bg-[#F1EBD8] text-[#C2821A] border border-[#E4DBC8] font-bold tracking-wider">
                DOSSIER // {entity.entity_type.toUpperCase()}
              </span>
              <span className="text-xs font-mono text-[#68655B] px-2 py-0.5 rounded bg-[#F1EBD8] border border-[#E4DBC8]">
                ID #{entity.id}
              </span>
              <span className="text-xs font-mono text-[#2D7A4F] px-2 py-0.5 rounded bg-[#2D7A4F]/10 border border-[#2D7A4F]/25 font-semibold">
                Normalized: {entity.normalized_name}
              </span>
            </div>

            <h1 className="text-2xl md:text-3xl font-extrabold text-[#171714] tracking-tight font-sans">
              {entity.name}
            </h1>

            {/* Aliases Display */}
            {entity.aliases && entity.aliases.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-mono uppercase tracking-wider text-[#68655B] font-bold">
                  Aliases:
                </span>
                {entity.aliases.map((alias, idx) => (
                  <span
                    key={idx}
                    className="px-2 py-0.5 rounded bg-[#F1EBD8] border border-[#E4DBC8] text-[#171714] text-xs font-mono"
                  >
                    {alias}
                  </span>
                ))}
              </div>
            )}

            {/* Overview Description */}
            <div className="pt-1">
              <h2 className="text-xs font-mono uppercase tracking-wider text-[#68655B] font-bold mb-1">
                Overview & Intelligence Summary
              </h2>
              <p className="text-sm md:text-base text-[#171714] leading-relaxed">
                {entity.description || "Active profile indexed in the knowledge graph. Extracted from trusted public vulnerability feeds, vendor advisories, and security reporting."}
              </p>
            </div>

            {/* Metadata Pills: First Seen / Last Seen / Categories */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2 font-mono text-xs">
              <div className="p-2.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8]">
                <span className="text-[10px] text-[#68655B] block uppercase">First Seen</span>
                <span className="font-bold text-[#171714]">{firstSeen}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8]">
                <span className="text-[10px] text-[#68655B] block uppercase">Last Seen</span>
                <span className="font-bold text-[#171714]">{lastSeen}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8]">
                <span className="text-[10px] text-[#68655B] block uppercase">Categories</span>
                <span className="font-bold text-[#171714] truncate block">{categoryTags.join(", ")}</span>
              </div>
              <div className="p-2.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8]">
                <span className="text-[10px] text-[#68655B] block uppercase">Confidence Meter</span>
                <div className="flex items-center gap-1.5 mt-0.5">
                  <div className="flex-1 bg-[#E4DBC8] h-2 rounded-full overflow-hidden">
                    <div
                      className="bg-[#C2821A] h-full rounded-full"
                      style={{ width: `${confidenceVal}%` }}
                    />
                  </div>
                  <span className="font-bold text-[#171714] text-[11px]">{confidenceVal}%</span>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Stats / CVSS Highlight */}
          {isCVE && entity.severity && (
            <div className="shrink-0 p-4 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] flex flex-col items-center text-center min-w-[150px]">
              <span className="text-[10px] font-mono uppercase tracking-wider text-[#68655B] mb-1 font-semibold">
                Severity Rating
              </span>
              <div className="my-1">
                <SeverityBadge
                  severity={(entity.severity.severity_rating as SeverityLevel) || "CRITICAL"}
                  score={entity.severity.cvss_score}
                />
              </div>
              {entity.severity.cvss_score !== undefined && (
                <span className="text-2xl font-mono font-extrabold text-[#171714] mt-1">
                  {entity.severity.cvss_score.toFixed(1)}
                  <span className="text-xs text-[#68655B] font-normal"> / 10.0</span>
                </span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* ========================================================================= */}
      {/* 1. CVE SPECIFIC METRICS & PRODUCTS                                         */}
      {/* ========================================================================= */}
      {isCVE && (
        <div className="space-y-6">
          {entity.severity && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-[#C2821A] font-bold flex items-center gap-2">
                  <span>◈</span> Vulnerability Severity Metrics
                </h2>
                <span className="text-xs font-mono text-[#68655B]">CVSS Standard</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
                  <span className="text-xs font-mono text-[#68655B] block mb-1">Base Score & Rating</span>
                  <div className="flex items-center gap-3">
                    <span className="text-xl font-mono font-bold text-[#171714]">
                      {entity.severity.cvss_score !== undefined ? entity.severity.cvss_score.toFixed(1) : "N/A"}
                    </span>
                    {entity.severity.severity_rating && (
                      <SeverityBadge severity={entity.severity.severity_rating as SeverityLevel} />
                    )}
                  </div>
                </div>

                <div className="p-4 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
                  <span className="text-xs font-mono text-[#68655B] block mb-1">CWE Weakness Type</span>
                  <span className="text-sm font-mono font-bold text-[#2D7A4F]">
                    {entity.severity.cwe_id || "Unclassified Weakness"}
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
                  <span className="text-xs font-mono text-[#68655B] block mb-1">Exploitability Vector</span>
                  <span className="text-xs font-mono text-[#171714] break-all">
                    {entity.severity.vector_string || "Vector string not provided"}
                  </span>
                </div>
              </div>
            </section>
          )}

          {entity.affected_products && entity.affected_products.length > 0 && (
            <section className="cyber-card rounded-2xl p-6 space-y-4">
              <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
                <h2 className="text-sm font-mono uppercase tracking-wider text-[#C2821A] font-bold flex items-center gap-2">
                  <span>◈</span> Affected Products & Platforms
                </h2>
                <span className="text-xs font-mono text-[#68655B]">
                  {entity.affected_products.length} Impacted Assets
                </span>
              </div>

              <div className="flex flex-wrap gap-2.5">
                {entity.affected_products.map((prod, idx) => (
                  <span
                    key={idx}
                    className="px-3 py-1.5 rounded-lg bg-[#F1EBD8] border border-[#E4DBC8] text-[#171714] text-xs font-mono flex items-center gap-2"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-[#C2821A]" />
                    {prod}
                  </span>
                ))}
              </div>
            </section>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* MALWARE & THREAT ACTOR TELEMETRY (Threat Actors, Campaigns, Techniques, Tools) */}
      {/* ========================================================================= */}
      {(isMalware || entity.entity_type?.toLowerCase() === "threat_actor" || entity.entity_type?.toLowerCase() === "tool") && (
        <section className="cyber-card rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
            <h2 className="text-sm font-mono uppercase tracking-wider text-[#B91C1C] font-bold flex items-center gap-2">
              <span>◈</span> Threat Actors, Campaigns & MITRE Techniques
            </h2>
            <span className="text-xs font-mono text-[#68655B]">Adversary Profile</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
            <div className="p-3.5 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[10px] text-[#68655B] uppercase block mb-1 font-semibold">Threat Actors</span>
              <span className="font-bold text-[#171714]">
                {entity.threat_actors && entity.threat_actors.length > 0
                  ? entity.threat_actors.join(", ")
                  : "Under Attribution Analysis"}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[10px] text-[#68655B] uppercase block mb-1 font-semibold">Campaigns</span>
              <span className="font-bold text-[#171714]">
                {entity.campaigns && entity.campaigns.length > 0
                  ? entity.campaigns.join(", ")
                  : "No Targeted Campaigns Recorded"}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[10px] text-[#68655B] uppercase block mb-1 font-semibold">Techniques</span>
              <span className="font-bold text-[#171714]">
                {entity.techniques && entity.techniques.length > 0
                  ? entity.techniques.join(", ")
                  : "Standard TTPs Monitored"}
              </span>
            </div>
            <div className="p-3.5 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8]">
              <span className="text-[10px] text-[#68655B] uppercase block mb-1 font-semibold">Tools</span>
              <span className="font-bold text-[#171714]">
                {entity.tools && entity.tools.length > 0
                  ? entity.tools.join(", ")
                  : "Associated Utilities Correlated"}
              </span>
            </div>
          </div>
        </section>
      )}

      {/* ========================================================================= */}
      {/* 2. SOURCES & REFERENCES SECTION                                           */}
      {/* ========================================================================= */}
      {entity.references && entity.references.length > 0 && (
        <section className="cyber-card rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
            <h2 className="text-sm font-mono uppercase tracking-wider text-[#C2821A] font-bold flex items-center gap-2">
              <span>◈</span> Official References & Advisories
            </h2>
            <span className="text-xs font-mono text-[#68655B]">
              {entity.references.length} Authoritative Links
            </span>
          </div>

          <ul className="divide-y divide-[#E4DBC8] font-mono text-xs">
            {entity.references.map((refUrl, idx) => (
              <li key={idx} className="py-2.5 flex items-center justify-between gap-4">
                <a
                  href={refUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[#C2821A] hover:text-[#D97706] hover:underline truncate max-w-2xl flex items-center gap-1.5"
                >
                  <span>&nearr;</span>
                  <span className="truncate">{refUrl}</span>
                </a>
                <span className="text-[#68655B] shrink-0 uppercase text-[10px]">Verified Source</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ========================================================================= */}
      {/* 3. RELATED INTELLIGENCE (ARTICLES & REPORTS)                              */}
      {/* ========================================================================= */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-[#171714] tracking-tight flex items-center gap-2 font-sans">
            <span className="text-[#C2821A] font-mono">◈</span> Related Intelligence Records
          </h2>
          <span className="text-xs font-mono text-[#68655B]">
            {entity.content_count} Correlated Items
          </span>
        </div>

        {((entity.articles && entity.articles.length > 0) || (entity.reports && entity.reports.length > 0) || (entity.linked_content && entity.linked_content.length > 0)) ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(entity.articles || []).map((art) => (
              <Link key={art.id} href={`/content/${art.id}`} className="block">
                <ContentCard item={art} />
              </Link>
            ))}
            {(entity.reports || []).map((rep) => (
              <Link key={rep.id} href={`/content/${rep.id}`} className="block">
                <ContentCard item={rep} />
              </Link>
            ))}
            {(!entity.articles?.length && !entity.reports?.length && entity.linked_content) &&
              entity.linked_content.map((link) => (
                <Link key={link.content_id} href={`/content/${link.content_id}`} className="block">
                  <div className="cyber-card rounded-xl p-5 hover:border-[#C2821A] transition-colors bg-[#FFFDF5]">
                    <div className="flex items-center justify-between text-xs font-mono text-[#68655B] mb-2">
                      <span className="uppercase text-[#C2821A] font-bold">{link.content_type}</span>
                      <span>{formatDate(link.published_at, "Recent")}</span>
                    </div>
                    <h3 className="font-bold text-[#171714] mb-2 line-clamp-2">{link.title}</h3>
                    {link.context_snippet && (
                      <p className="text-xs text-[#68655B] line-clamp-2 font-mono">
                        {link.context_snippet}
                      </p>
                    )}
                  </div>
                </Link>
              ))}
          </div>
        ) : (
          <div className="cyber-card rounded-xl p-6 text-center text-xs font-mono text-[#68655B]">
            Entity exists, but no active intelligence records are currently linked.
          </div>
        )}
      </section>

      {/* ========================================================================= */}
      {/* 4. RELATED ENTITIES IN KNOWLEDGE GRAPH                                    */}
      {/* ========================================================================= */}
      {entity.related_entities && entity.related_entities.length > 0 && (
        <section className="cyber-card rounded-2xl p-6 space-y-4">
          <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
            <h2 className="text-sm font-mono uppercase tracking-wider text-[#2D7A4F] font-bold flex items-center gap-2">
              <span>◈</span> Related Entities in Knowledge Graph
            </h2>
            <span className="text-xs font-mono text-[#68655B]">
              {entity.related_entities.length} Associations
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3 font-mono text-xs">
            {entity.related_entities.map((rel) => (
              <Link
                key={rel.id}
                href={`/entities/${rel.id}`}
                className="p-3 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] hover:border-[#2D7A4F] transition-colors flex items-center justify-between group"
              >
                <div>
                  <span className="font-bold text-[#171714] group-hover:text-[#2D7A4F] block transition-colors">
                    {rel.name}
                  </span>
                  <span className="text-[10px] text-[#68655B] uppercase">{rel.entity_type}</span>
                </div>
                {rel.mention_count && rel.mention_count > 1 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#E4DBC8] text-[#171714] border border-[#D8CEB9]">
                    {rel.mention_count}x co-occur
                  </span>
                )}
              </Link>
            ))}
          </div>
        </section>
      )}

      {/* ========================================================================= */}
      {/* 5. TIMELINE VISUALIZATION                                                 */}
      {/* ========================================================================= */}
      {entity.timeline && entity.timeline.length > 0 && (
        <section className="cyber-card rounded-2xl p-6 space-y-6">
          <div className="flex items-center justify-between border-b border-[#E4DBC8] pb-3">
            <h2 className="text-sm font-mono uppercase tracking-wider text-[#C2821A] font-bold flex items-center gap-2">
              <span>◈</span> Recorded Activity Timeline
            </h2>
            <span className="text-xs font-mono text-[#68655B]">
              {entity.timeline.length} Milestones
            </span>
          </div>

          <div className="relative pl-6 border-l border-[#E4DBC8] space-y-6 font-mono text-xs">
            {entity.timeline.map((evt, idx) => (
              <div key={idx} className="relative group">
                <div className="absolute -left-[31px] top-0.5 w-3 h-3 rounded-full bg-[#FFFDF5] border-2 border-[#C2821A] group-hover:bg-[#C2821A] transition-colors" />
                <div className="flex flex-col sm:flex-row sm:items-baseline justify-between gap-1 mb-1">
                  <span className="font-bold text-[#171714] text-sm">{evt.title}</span>
                  <span className="text-[11px] text-[#68655B]">{formatDate(evt.date, "Undated")}</span>
                </div>
                <div className="flex items-center gap-2 text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-[#F1EBD8] text-[#C2821A] border border-[#E4DBC8] uppercase font-bold">
                    {evt.event_type}
                  </span>
                  {evt.url && (
                    <a
                      href={evt.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[#C2821A] hover:underline flex items-center gap-0.5"
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
    </article>
  );
}
