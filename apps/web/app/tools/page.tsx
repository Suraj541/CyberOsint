"use client";

import React, { useState, useMemo, useEffect } from "react";

export interface OSINTTool {
  id: string;
  name: string;
  category: "frameworks" | "domains" | "network" | "people" | "documents";
  categoryLabel: string;
  shortDescription: string;
  officialUrl: string;
  githubUrl?: string;
  icon: string;
  capabilities: string[];
  useCases: string[];
}

const OSINT_TOOLS_CATALOG: OSINTTool[] = [
  // 1. General OSINT Directories & Frameworks
  {
    id: "osint-framework",
    name: "OSINT Framework",
    category: "frameworks",
    categoryLabel: "Directories & Frameworks",
    shortDescription:
      "A web-based interactive directory that gathers and organizes open source intelligence gathering tools, services, and public databases into an expandable mindmap.",
    officialUrl: "https://osintframework.com/",
    githubUrl: "https://github.com/lockfale/OSINT-Framework",
    icon: "🗂️",
    capabilities: [
      "Taxonomy mindmap",
      "Categorized resource discovery",
      "Public records indexing",
      "Free & paid service curation",
    ],
    useCases: [
      "Initial investigation scope definition",
      "Locating specialized regional public records",
      "Training research teams on intelligence methodologies",
    ],
  },
  {
    id: "intelligence-x",
    name: "Intelligence X",
    category: "frameworks",
    categoryLabel: "Directories & Frameworks",
    shortDescription:
      "A European search engine and data archive specializing in darknet markets, historical website snapshots, leak databases, and data breach records.",
    officialUrl: "https://intelx.io/",
    icon: "🔍",
    capabilities: [
      "Multi-selector search (IP, CIDR, Email, Domain, BTC/ETH)",
      "Darknet & Tor crawling archive",
      "Historical pastebin archive",
      "Data breach credential validation",
    ],
    useCases: [
      "Corporate brand exposure monitoring",
      "Investigating dark web ransomware leak announcements",
      "Tracking historical pastebin drops and compromise indicators",
    ],
  },

  // 2. Domain & Company Infrastructure
  {
    id: "theharvester",
    name: "theHarvester",
    category: "domains",
    categoryLabel: "Domain & Infrastructure",
    shortDescription:
      "A fast and popular Python OSINT reconnaissance tool that gathers emails, subdomains, hosts, employee names, open ports, and banners from dozens of search engines and public registries.",
    officialUrl: "https://github.com/laramies/theHarvester",
    githubUrl: "https://github.com/laramies/theHarvester",
    icon: "🌾",
    capabilities: [
      "Multi-source passive reconnaissance",
      "Subdomain enumeration (DNS & Certs)",
      "Employee names & email harvesting",
      "Virtual host discovery & IP mapping",
    ],
    useCases: [
      "External attack surface reconnaissance during penetration testing",
      "Identifying exposed executive and staff email addresses",
      "Uncovering unindexed cloud subdomains and developer environments",
    ],
  },
  {
    id: "hunter-io",
    name: "Hunter",
    category: "domains",
    categoryLabel: "Domain & Infrastructure",
    shortDescription:
      "An enterprise search platform that maps out corporate email address formats, department directories, and verifies active mail delivery servers for specified domain names.",
    officialUrl: "https://hunter.io/",
    icon: "🎯",
    capabilities: [
      "Domain search & email pattern detection",
      "SMTP delivery & bounce verification",
      "Author & executive finder",
      "Public source confidence scoring",
    ],
    useCases: [
      "Mapping organizational hierarchies and department contacts",
      "Verifying validity of intelligence disclosure contacts",
      "Analyzing standard corporate email generation patterns",
    ],
  },
  {
    id: "dnsdumpster",
    name: "DNSDumpster",
    category: "domains",
    categoryLabel: "Domain & Infrastructure",
    shortDescription:
      "A domain research and reconnaissance tool that queries DNS records, discovers subdomains, discovers MX/TXT/SOA records, and visualizes network topology maps.",
    officialUrl: "https://dnsdumpster.com/",
    icon: "🗺️",
    capabilities: [
      "Subdomain enumeration & brute force",
      "DNS record analysis (A, MX, NS, TXT)",
      "Autonomous System Number (ASN) mapping",
      "Visual network relationship graph export",
    ],
    useCases: [
      "Detecting shadow IT cloud endpoints and forgotten web servers",
      "Validating SPF and DMARC anti-spoofing record hygiene",
      "Mapping corporate mail transfer agent infrastructure",
    ],
  },

  // 3. Device & Network Footprinting
  {
    id: "shodan",
    name: "Shodan",
    category: "network",
    categoryLabel: "Device & Network Footprinting",
    shortDescription:
      "The world's leading search engine for Internet-connected devices, industrial control systems (ICS/SCADA), webcams, database servers, and network services.",
    officialUrl: "https://www.shodan.io/",
    icon: "🌐",
    capabilities: [
      "Banner grabbing across IPv4 & IPv6",
      "Industrial Control System (SCADA) monitoring",
      "Vulnerability (CVE) correlation per service banner",
      "Geographical & ASN network filtering",
    ],
    useCases: [
      "Detecting unintentionally exposed administrative panels and databases",
      "Monitoring critical infrastructure exposure across municipal grids",
      "Verifying patch levels across external enterprise subnets",
    ],
  },
  {
    id: "censys",
    name: "Censys",
    category: "network",
    categoryLabel: "Device & Network Footprinting",
    shortDescription:
      "A comprehensive Internet intelligence platform that continuously scans all IPv4 addresses and ingests worldwide TLS/SSL certificates to reveal external attack surfaces.",
    officialUrl: "https://censys.com/",
    icon: "📡",
    capabilities: [
      "Global TLS/SSL certificate transparency log ingestion",
      "Full IPv4 host fingerprinting",
      "Automated external attack surface management (ASM)",
      "High-speed structured Boolean search queries",
    ],
    useCases: [
      "Tracking phishing campaigns via newly issued SSL certificates",
      "Identifying unknown internet-facing cloud compute instances",
      "Correlating corporate certificate authorities across infrastructure",
    ],
  },

  // 4. Person & Social Media Footprinting
  {
    id: "sherlock",
    name: "Sherlock",
    category: "people",
    categoryLabel: "Person & Social Footprinting",
    shortDescription:
      "An open source command-line tool that rapidly hunts down social media accounts and profile registrations by target username across more than 400 social platforms and forums.",
    officialUrl: "https://github.com/sherlock-project/sherlock",
    githubUrl: "https://github.com/sherlock-project/sherlock",
    icon: "🕵️",
    capabilities: [
      "400+ platform concurrent scanning",
      "Tor SOCKS5 proxy support",
      "Direct profile link extraction",
      "Batch username investigation exports",
    ],
    useCases: [
      "Correlating threat actor handles across developer and underground forums",
      "Verifying online footprint during executive protection assessments",
      "Identifying operational security failures through reused aliases",
    ],
  },
  {
    id: "social-searcher",
    name: "Social Searcher",
    category: "people",
    categoryLabel: "Person & Social Footprinting",
    shortDescription:
      "A real-time social media search and analytics engine that aggregates mentions across public web platforms including YouTube, Reddit, X (Twitter), and web forums.",
    officialUrl: "https://www.social-searcher.com/",
    icon: "💬",
    capabilities: [
      "Real-time social keyword listening",
      "Sentiment analysis & volume velocity",
      "Popular hashtags & influencer metrics",
      "Multi-network query aggregation without individual API keys",
    ],
    useCases: [
      "Monitoring brand defamation and disinformation campaigns in real time",
      "Tracking emerging cyber incident announcements across social channels",
      "Aggregating public reactions to security advisories and breaches",
    ],
  },

  // 5. Document & File Metadata
  {
    id: "foca",
    name: "FOCA (Fingerprinting Organizations with Collected Archives)",
    category: "documents",
    categoryLabel: "Document & File Metadata",
    shortDescription:
      "A specialized OSINT tool that scans target websites, downloads public documents (PDF, DOCX, XLSX, PPTX, SVG), and extracts embedded metadata, usernames, software versions, and internal paths.",
    officialUrl: "https://github.com/ElevenPaths/FOCA",
    githubUrl: "https://github.com/ElevenPaths/FOCA",
    icon: "📄",
    capabilities: [
      "Automated document crawler (Google, Bing, DuckDuckGo)",
      "EXIF and XML metadata extraction",
      "Internal folder path & printer share discovery",
      "Operating system & software suite identification",
    ],
    useCases: [
      "Extracting internal Active Directory usernames from published PDF reports",
      "Discovering internal network paths and printer server hostnames",
      "Auditing corporate document publishing workflows for information leakage",
    ],
  },
];

const CATEGORIES = [
  { key: "all", label: "ALL TOOLS" },
  { key: "frameworks", label: "DIRECTORIES & FRAMEWORKS" },
  { key: "domains", label: "DOMAIN & INFRASTRUCTURE" },
  { key: "network", label: "DEVICE & NETWORK" },
  { key: "people", label: "PERSON & SOCIAL" },
  { key: "documents", label: "DOCUMENT & METADATA" },
];

export default function OSINTToolsPage() {
  const [activeCategory, setActiveCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [favorites, setFavorites] = useState<string[]>([]);

  // Load bookmarks from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem("osint_toolkit_favs");
      if (saved) setFavorites(JSON.parse(saved));
    } catch {
      // Ignore storage errors
    }
  }, []);

  const toggleFavorite = (id: string) => {
    setFavorites((prev) => {
      const next = prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id];
      try {
        localStorage.setItem("osint_toolkit_favs", JSON.stringify(next));
      } catch {
        // Ignore storage errors
      }
      return next;
    });
  };

  const filteredTools = useMemo(() => {
    return OSINT_TOOLS_CATALOG.filter((tool) => {
      const matchCategory = activeCategory === "all" || tool.category === activeCategory;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        tool.name.toLowerCase().includes(q) ||
        tool.shortDescription.toLowerCase().includes(q) ||
        tool.capabilities.some((c) => c.toLowerCase().includes(q)) ||
        tool.useCases.some((u) => u.toLowerCase().includes(q));
      return matchCategory && matchSearch;
    });
  }, [activeCategory, searchQuery]);

  return (
    <div className="space-y-8 animate-in fade-in duration-200 pb-16">
      {/* Header Banner */}
      <div className="border-b border-[#E4DBC8] pb-6 flex flex-col md:flex-row md:items-end justify-between gap-4">
        <div>
          <span className="text-xs font-mono text-[#C2821A] font-bold uppercase tracking-wider block mb-1">
            EXTERNAL OSINT CATALOG // REFERENCE ARSENAL
          </span>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-[#171714] tracking-tight font-sans">
            OSINT Toolkit & Reconnaissance Catalog
          </h1>
          <p className="text-xs sm:text-sm text-[#68655B] mt-1 max-w-3xl">
            A structured directory of authoritative open source intelligence tools, external search engines, and forensic utilities.
            Verified official documentation, source repositories, and practical investigative use cases.
          </p>
        </div>

        <div className="flex items-center gap-3 shrink-0 font-mono text-xs">
          <div className="px-3.5 py-2 rounded-xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
            <span className="text-[#68655B] block text-[10px] uppercase font-semibold">Cataloged Tools</span>
            <span className="text-[#171714] font-bold text-sm">{OSINT_TOOLS_CATALOG.length}</span>
          </div>
          <div className="px-3.5 py-2 rounded-xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
            <span className="text-[#C2821A] block text-[10px] uppercase font-semibold">Bookmarked</span>
            <span className="text-[#171714] font-bold text-sm">{favorites.length}</span>
          </div>
        </div>
      </div>

      {/* Notice Banner */}
      <div className="p-3.5 rounded-xl bg-[#FFFDF5] border border-[#E4DBC8] text-xs font-mono text-[#68655B] flex items-center gap-3">
        <span className="text-[#C2821A] text-base">ℹ</span>
        <span>
          <strong className="text-[#171714]">External Catalog Notice:</strong> These entries reference independent, external intelligence services and open source repositories.
          This platform does not assert backend control or live proxy execution over external services without configured API access keys.
        </span>
      </div>

      {/* Filter and Search Bar */}
      <div className="space-y-3">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 rounded-xl bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm">
          <div className="relative w-full sm:w-80">
            <span className="absolute left-3 top-2.5 text-[#68655B] text-xs font-mono">⌕</span>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search tools, capabilities, or keywords..."
              className="w-full bg-[#F1EBD8] border border-[#E4DBC8] rounded-lg pl-8 pr-3 py-1.5 text-xs font-mono text-[#171714] placeholder-[#8C887B] focus:outline-none focus:border-[#C2821A]"
            />
          </div>

          <div className="flex items-center gap-1.5 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0 font-mono text-xs">
            {CATEGORIES.map((cat) => (
              <button
                key={cat.key}
                onClick={() => setActiveCategory(cat.key)}
                className={`px-3 py-1.5 rounded-lg text-xs whitespace-nowrap transition-colors ${
                  activeCategory === cat.key
                    ? "bg-[#C2821A] text-white font-bold shadow-sm"
                    : "bg-[#F1EBD8] text-[#68655B] hover:text-[#171714] border border-[#E4DBC8]"
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Tools Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {filteredTools.map((tool) => {
          const isFav = favorites.includes(tool.id);

          return (
            <div
              key={tool.id}
              className="cyber-card rounded-2xl p-6 bg-[#FFFDF5] border border-[#E4DBC8] shadow-sm hover:border-[#C2821A] transition-all flex flex-col justify-between"
            >
              <div className="space-y-4">
                {/* Top header row */}
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-11 h-11 rounded-xl bg-[#F1EBD8] border border-[#E4DBC8] flex items-center justify-center text-2xl shadow-sm">
                      {tool.icon}
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-[#171714] font-sans">
                        {tool.name}
                      </h3>
                      <span className="text-[11px] font-mono text-[#C2821A] uppercase tracking-wider font-semibold">
                        {tool.categoryLabel}
                      </span>
                    </div>
                  </div>

                  <button
                    onClick={() => toggleFavorite(tool.id)}
                    className="p-1.5 rounded-lg text-sm transition-colors hover:bg-[#F1EBD8]"
                    title={isFav ? "Remove bookmark" : "Bookmark tool"}
                  >
                    {isFav ? "★" : "☆"}
                  </button>
                </div>

                {/* Short Description */}
                <p className="text-xs sm:text-sm text-[#68655B] leading-relaxed">
                  {tool.shortDescription}
                </p>

                {/* Capabilities */}
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono text-[#171714] uppercase tracking-wider font-bold block">
                    Core Capabilities:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {tool.capabilities.map((cap, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-0.5 rounded bg-[#F1EBD8] border border-[#E4DBC8] text-[#171714] text-[11px] font-mono"
                      >
                        ✓ {cap}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Practical Use Cases */}
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] font-mono text-[#171714] uppercase tracking-wider font-bold block">
                    Investigative Use Cases:
                  </span>
                  <ul className="space-y-1 text-xs font-mono text-[#68655B]">
                    {tool.useCases.map((uc, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <span className="text-[#C2821A] shrink-0 font-bold">&bull;</span>
                        <span>{uc}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              {/* Action Buttons Footer */}
              <div className="pt-5 mt-5 border-t border-[#E4DBC8] flex items-center justify-between gap-3 font-mono text-xs">
                <a
                  href={tool.officialUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="px-3.5 py-1.5 rounded-lg bg-[#C2821A] hover:bg-[#D97706] text-white font-bold transition-colors flex items-center gap-1.5 shadow-sm"
                >
                  <span>Open Official Site</span>
                  <span>&nearr;</span>
                </a>

                {tool.githubUrl && (
                  <a
                    href={tool.githubUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="px-3 py-1.5 rounded-lg bg-[#F1EBD8] hover:bg-[#EAE3CE] border border-[#E4DBC8] text-[#171714] font-semibold transition-colors flex items-center gap-1"
                  >
                    <span>GitHub / Docs</span>
                    <span>&nearr;</span>
                  </a>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
