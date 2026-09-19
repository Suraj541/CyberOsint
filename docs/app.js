/**
 * CyberOsint — Interactive Showcase Logic
 * Standalone Client-Side Execution (0 external dependencies, 0 server requirements)
 */

document.addEventListener("DOMContentLoaded", () => {
  initThemeToggle();
  initNavigation();
  initArchitectureInspector();
  initSearchSimulator();
  initKnowledgeGraph();
  initQuickstartTabs();
  initCopyButtons();
});

/* ==========================================================================
   0. Theme Toggle (Light & Night Mode)
   ========================================================================== */
function initThemeToggle() {
  const toggleBtn = document.getElementById("theme-toggle-btn");
  if (!toggleBtn) return;

  const currentTheme = () => document.documentElement.getAttribute("data-theme") || "dark";

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    if (theme === "dark") {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    localStorage.setItem("theme", theme);
    toggleBtn.setAttribute("title", theme === "dark" ? "Switch to Light Mode" : "Switch to Night Mode");
    toggleBtn.setAttribute("aria-label", theme === "dark" ? "Switch to Light Mode" : "Switch to Night Mode");
  }

  const stored = localStorage.getItem("theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initial = stored ? stored : (prefersDark ? "dark" : "light");
  applyTheme(initial);

  toggleBtn.addEventListener("click", () => {
    const next = currentTheme() === "dark" ? "light" : "dark";
    applyTheme(next);
  });
}

/* ==========================================================================
   1. Navigation & Scroll Spy
   ========================================================================== */
function initNavigation() {
  const header = document.querySelector(".site-header");
  const mobileToggle = document.querySelector(".mobile-toggle");
  const navLinks = document.querySelector(".nav-links");
  const links = document.querySelectorAll(".nav-link");

  // Scroll Header Tint
  window.addEventListener("scroll", () => {
    if (window.scrollY > 40) {
      header.classList.add("scrolled");
    } else {
      header.classList.remove("scrolled");
    }
  });

  // Mobile Menu Toggle
  if (mobileToggle && navLinks) {
    mobileToggle.addEventListener("click", () => {
      navLinks.classList.toggle("open");
    });

    links.forEach(link => {
      link.addEventListener("click", () => {
        navLinks.classList.remove("open");
      });
    });
  }

  // Scroll Spy Active State
  const sections = document.querySelectorAll("section[id]");
  window.addEventListener("scroll", () => {
    const scrollY = window.pageYOffset;
    sections.forEach(current => {
      const sectionHeight = current.offsetHeight;
      const sectionTop = current.offsetTop - 120;
      const sectionId = current.getAttribute("id");
      const targetLink = document.querySelector(`.nav-links a[href*="${sectionId}"]`);
      if (targetLink) {
        if (scrollY > sectionTop && scrollY <= sectionTop + sectionHeight) {
          links.forEach(l => l.classList.remove("active"));
          targetLink.classList.add("active");
        }
      }
    });
  });
}

/* ==========================================================================
   2. Architecture Pipeline Inspector
   ========================================================================== */
const ARCH_STAGES = {
  sources: {
    tag: "Stage 01 • External Ingress",
    title: "Global Threat Feeds & Ingress Connectors",
    desc: "CyberOsint continuously polls authoritative external sources across government CERTs, vulnerability registries, exploit repositories, security blogs, and malware telemetry.",
    specs: [
      { label: "Connectors", val: "CISA KEV, MSRC, GHSA, NVD, Project Zero, Abuse.ch, arXiv" },
      { label: "Protocols", val: "HTTPS REST, RSS/Atom, JSON Advisories, CVRF/CSAF" },
      { label: "Scheduling", val: "APScheduler Background Worker (Configurable Intervals)" },
      { label: "Security", val: "SSRF Protection, RFC 1918 Private Subnet Filter" }
    ]
  },
  connectors: {
    tag: "Stage 02 • Network Layer",
    title: "Autonomous Connector & Request Management",
    desc: "Handles outbound requests with strict security controls, exponential backoff, rate limiting, and custom User-Agent headers compliant with robots.txt standards.",
    specs: [
      { label: "Concurrency", val: "Asyncio / HTTPX Connection Pools (Max 5 concurrent)" },
      { label: "Rate Limiting", val: "Token Bucket Algorithm with Redis / Memory Backend" },
      { label: "Timeout", val: "30s Connect / Read Timeout with Auto-Retry" },
      { label: "Defense", val: "Blocks Loopback (127.0.0.1) & Cloud Metadata (169.254.169.254)" }
    ]
  },
  normalization: {
    tag: "Stage 03 • Processing",
    title: "Data Normalization & SHA-256 Deduplication",
    desc: "Ingested raw payloads are converted into standard CyberOSINT schema contracts. Duplicate intelligence items are deterministically filtered via SHA-256 content hashes.",
    specs: [
      { label: "Standard Schema", val: "CyberOSINT Core Content Contract (Pydantic v2)" },
      { label: "Deduplication", val: "SHA-256 Hash of Normalized Title + Body Text" },
      { label: "Timestamps", val: "ISO 8601 UTC Standardization with Fallback Parsing" },
      { label: "Raw Archiving", val: "Preserved Raw JSON Payloads for Audit & Re-indexing" }
    ]
  },
  classification: {
    tag: "Stage 04 • Enrichment",
    title: "Taxonomy Classification & Named Entity Recognition",
    desc: "Extracts structured metadata, maps cybersecurity taxonomies (CVE, KEV, Threat Actor, Malware Family, CWE), and calculates initial severity and confidence scores.",
    specs: [
      { label: "NER Extraction", val: "Regex & Heuristic Named Entity Resolution Engine" },
      { label: "Taxonomy", val: "Vulnerability, Threat Intel, Advisory, Research, News" },
      { label: "CVE Detection", val: "Automated Regex CVE-YYYY-NNNNN Pattern Extraction" },
      { label: "CVSS Scoring", val: "CVSS v3.1 Base Score, Severity Vector & Exploit Status" }
    ]
  },
  database: {
    tag: "Stage 05 • Persistence",
    title: "PostgreSQL 16 Relational Engine",
    desc: "All normalized content, entities, relationships, sources, and ingestion audit states are persisted reliably in PostgreSQL with ACID guarantees and Alembic schema migrations.",
    specs: [
      { label: "Database", val: "PostgreSQL 16 (Relational Engine)" },
      { label: "ORM / Layer", val: "SQLAlchemy 2.0 Async Session Management" },
      { label: "Migrations", val: "Alembic Versioned Database Schemas" },
      { label: "Tables", val: "contents, entities, relationships, sources, cve_details" }
    ]
  },
  search: {
    tag: "Stage 06 • Retrieval Engine",
    title: "Hybrid Search & Reciprocal Rank Fusion (RRF)",
    desc: "Simultaneously queries OpenSearch BM25 text indexes and 384-dimensional dense vector embeddings, fusing the rank distributions using RRF (k=60) for optimal relevance.",
    specs: [
      { label: "Text Search", val: "OpenSearch BM25 Inverted Index / Postgres Full-Text" },
      { label: "Vector Search", val: "384-D Embeddings (sentence-transformers / MiniLM)" },
      { label: "Fusion Formula", val: "RRF(d) = Σ [ 1 / (60 + rank_i(d)) ]" },
      { label: "Resilience", val: "Automatic In-Memory Cosine Similarity Fallback Mode" }
    ]
  },
  api: {
    tag: "Stage 07 • Interface",
    title: "FastAPI Backend & Next.js 14 UI",
    desc: "High-performance asynchronous API endpoints serve the Next.js frontend with sub-millisecond response times, OpenAPI Swagger docs, and Server-Sent Events (SSE) telemetry.",
    specs: [
      { label: "Backend", val: "FastAPI on Python 3.11+ (Uvicorn ASGI)" },
      { label: "Frontend", val: "Next.js 14 + React + TypeScript + Tailwind CSS" },
      { label: "Live Telemetry", val: "Server-Sent Events (SSE) Status Streaming" },
      { label: "API Docs", val: "Interactive Swagger UI available at /docs" }
    ]
  }
};

function initArchitectureInspector() {
  const buttons = document.querySelectorAll(".arch-node-btn");
  const stageTag = document.getElementById("arch-stage-tag");
  const title = document.getElementById("arch-stage-title");
  const desc = document.getElementById("arch-stage-desc");
  const specsContainer = document.getElementById("arch-stage-specs");

  if (!buttons.length || !stageTag || !title || !desc || !specsContainer) return;

  function setStage(stageKey) {
    const data = ARCH_STAGES[stageKey];
    if (!data) return;

    buttons.forEach(btn => {
      btn.classList.toggle("active", btn.dataset.stage === stageKey);
    });

    stageTag.textContent = data.tag;
    title.textContent = data.title;
    desc.textContent = data.desc;

    specsContainer.innerHTML = data.specs
      .map(
        s => `
        <div class="spec-row">
          <span class="spec-label">${s.label}</span>
          <span class="spec-val">${s.val}</span>
        </div>`
      )
      .join("");
  }

  buttons.forEach(btn => {
    btn.addEventListener("click", () => {
      setStage(btn.dataset.stage);
    });
  });

  // Default stage
  setStage("search");
}

/* ==========================================================================
   3. Interactive Hybrid Search Simulator
   ========================================================================== */
const MOCK_INTEL_DB = [
  {
    id: "intel-01",
    title: "Critical VMware vCenter Remote Code Execution (CVE-2024-38812)",
    type: "Vulnerability / KEV",
    badgeClass: "intel-tag-cve",
    snippet: "A heap-based buffer overflow in the DCE/RPC protocol implementation allows an unauthenticated network attacker to trigger remote code execution by sending a specially crafted network packet.",
    keywords: ["vmware", "vcenter", "cve-2024-38812", "rce", "cve", "zero-day", "buffer overflow"],
    source: "CISA KEV / Broadcom Advisory",
    textRankBase: 1,
    vectorScoreBase: 0.94
  },
  {
    id: "intel-02",
    title: "LockBit 3.0 Ransomware Campaign Targeting ESXi Infrastructure",
    type: "Threat Intel",
    badgeClass: "intel-tag-kev",
    snippet: "LockBit affiliates observed deploying updated Linux/ESXi encryptor payloads utilizing compromised administrative credentials and living-off-the-land binaries for discovery.",
    keywords: ["ransomware", "lockbit", "lockbit 3.0", "esxi", "encryption", "threat actor"],
    source: "FBI / CISA Alert AA24-051A",
    textRankBase: 2,
    vectorScoreBase: 0.91
  },
  {
    id: "intel-03",
    title: "Palo Alto Networks PAN-OS Zero-Day Command Injection (CVE-2024-3400)",
    type: "Vulnerability / KEV",
    badgeClass: "intel-tag-cve",
    snippet: "Command injection flaw in GlobalProtect feature of PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
    keywords: ["palo alto", "pan-os", "cve-2024-3400", "cve", "zero-day", "firewall", "injection"],
    source: "CISA Known Exploited Vulnerabilities",
    textRankBase: 3,
    vectorScoreBase: 0.88
  },
  {
    id: "intel-04",
    title: "Google Project Zero: In-the-Wild Exploitation of Arm Mali GPU Drivers",
    type: "Research",
    badgeClass: "intel-tag-cert",
    snippet: "Detailed exploit anatomy of use-after-free conditions in the Valhall and Bifrost GPU kernel drivers, demonstrating full sandbox escape without root permission.",
    keywords: ["zero-day", "project zero", "arm", "mali", "gpu", "research", "exploit", "use-after-free"],
    source: "Google Project Zero Research",
    textRankBase: 4,
    vectorScoreBase: 0.85
  },
  {
    id: "intel-05",
    title: "Phishing Campaigns Exploiting Microsoft OAuth Application Consent",
    type: "Advisory",
    badgeClass: "intel-tag-rrf",
    snippet: "Adversaries weaponizing malicious OAuth application registrations to illicitly access cloud enterprise mailboxes without triggering MFA challenges.",
    keywords: ["phishing", "oauth", "microsoft", "credential stuffing", "credentials", "cloud"],
    source: "MSRC Security Advisory",
    textRankBase: 5,
    vectorScoreBase: 0.82
  },
  {
    id: "intel-06",
    title: "MalwareBazaar: Proliferation of AgentTesla Infostealer Signatures",
    type: "Malware Feed",
    badgeClass: "intel-tag-kev",
    snippet: "Automated analysis of 142 unique samples distributing .NET based infostealers harvesting browser credentials, FTP profiles, and cryptocurrency wallets.",
    keywords: ["malware", "agenttesla", "infostealer", "abuse.ch", "ransomware", "phishing"],
    source: "Abuse.ch MalwareBazaar",
    textRankBase: 6,
    vectorScoreBase: 0.79
  }
];

function initSearchSimulator() {
  const searchInput = document.getElementById("demo-search-input");
  const chips = document.querySelectorAll(".search-chip");
  const resultsContainer = document.getElementById("demo-results-container");
  const resultCountEl = document.getElementById("demo-result-count");
  const queryDurationEl = document.getElementById("demo-query-duration");

  if (!searchInput || !resultsContainer) return;

  function performSearch(query) {
    const cleanQuery = query.toLowerCase().trim();
    const startTime = performance.now();

    let matched = MOCK_INTEL_DB.map(item => {
      // Check keyword match
      const titleMatch = item.title.toLowerCase().includes(cleanQuery);
      const snippetMatch = item.snippet.toLowerCase().includes(cleanQuery);
      const keywordMatch = item.keywords.some(k => k.includes(cleanQuery) || cleanQuery.includes(k));

      let matchScore = 0;
      if (titleMatch) matchScore += 3;
      if (keywordMatch) matchScore += 2;
      if (snippetMatch) matchScore += 1;

      // Simulate BM25 rank (1 to 6)
      const textRank = matchScore > 0 ? Math.max(1, 7 - matchScore) : item.textRankBase;
      // Simulate Dense Vector cosine similarity rank
      const vectorRank = item.vectorScoreBase > 0.85 ? 1 : Math.min(6, item.textRankBase + 1);

      // RRF formula with k = 60
      const k = 60;
      const rrfScore = (1 / (k + textRank)) + (1 / (k + vectorRank));

      return {
        ...item,
        matchScore,
        textRank,
        vectorRank,
        rrfScore: parseFloat(rrfScore.toFixed(5))
      };
    });

    // If query provided, sort by RRF score descending
    matched.sort((a, b) => b.rrfScore - a.rrfScore);

    const duration = Math.round(performance.now() - startTime + Math.random() * 8 + 4);
    if (queryDurationEl) queryDurationEl.textContent = `${duration}ms`;
    if (resultCountEl) resultCountEl.textContent = matched.length;

    renderResults(matched, cleanQuery);
  }

  function renderResults(items, query) {
    resultsContainer.innerHTML = items
      .map(item => {
        return `
        <article class="demo-result-card">
          <div class="result-card-header">
            <span class="result-type-badge ${item.badgeClass}">${item.type}</span>
            <span style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${item.source}</span>
          </div>
          <h4 class="result-title">${item.title}</h4>
          <p class="result-snippet">${item.snippet}</p>
          <div class="result-scores-row">
            <div class="score-tag">BM25 Rank: <span>#${item.textRank}</span></div>
            <div class="score-tag">Vector Rank: <span>#${item.vectorRank}</span></div>
            <div class="score-tag">RRF Score (k=60): <span style="color: var(--accent-emerald);">${item.rrfScore}</span></div>
          </div>
        </article>
        `;
      })
      .join("");
  }

  // Event Listeners
  searchInput.addEventListener("input", e => {
    performSearch(e.target.value);
  });

  chips.forEach(chip => {
    chip.addEventListener("click", () => {
      const q = chip.dataset.query;
      searchInput.value = q;
      performSearch(q);
    });
  });

  // Initial search
  performSearch("ransomware");
}

/* ==========================================================================
   4. Interactive Knowledge Graph
   ========================================================================== */
const GRAPH_NODES_DATA = {
  cve: {
    name: "CVE-2024-38812",
    type: "Vulnerability",
    desc: "Critical DCE/RPC heap-based buffer overflow vulnerability in VMware vCenter Server with CVSS v3.1 Base Score 9.8 (Critical).",
    meta: [
      { label: "CVSS v3.1", val: "9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)" },
      { label: "CWE Weakness", val: "CWE-119 (Memory Buffer Boundary Overflow)" },
      { label: "Status", val: "CISA KEV Added / Exploited In-The-Wild" },
      { label: "Discovered By", val: "Matrix Lab of QiAnXin Group" }
    ]
  },
  product: {
    name: "VMware vCenter Server",
    type: "Target Product",
    desc: "Centralized virtualization management platform deployed across Fortune 500 enterprise private clouds and data centers.",
    meta: [
      { label: "Vendor", val: "Broadcom Inc. / VMware" },
      { label: "Affected Versions", val: "7.0, 8.0, Cloud Foundation 4.x/5.x" },
      { label: "Service Impact", val: "Central Hypervisor Control Plane" },
      { label: "Patch Status", val: "Security Advisory VMSA-2024-0019" }
    ]
  },
  vendor: {
    name: "Broadcom Inc.",
    type: "Vendor",
    desc: "Global infrastructure software and semiconductor manufacturer, parent corporation maintaining VMware products.",
    meta: [
      { label: "Entity Category", val: "Technology Vendor" },
      { label: "Total Tracked CVEs", val: "84 active advisories in platform" },
      { label: "Disclosure Portal", val: "Broadcom Security Advisory Center" },
      { label: "Confidence", val: "1.00 (Deterministic Resolution)" }
    ]
  },
  threat: {
    name: "Ransomware Operators",
    type: "Threat Actor Category",
    desc: "Financially motivated threat syndicates (e.g., LockBit, Akira, RansomHub) weaponizing virtualization hypervisor vulnerabilities.",
    meta: [
      { label: "Tactics (ATT&CK)", val: "Initial Access (T1190), Impact (T1486)" },
      { label: "Target Scope", val: "Enterprise Datacenter Virtual Machines" },
      { label: "Correlated Reports", val: "12 active dispatches in CyberOsint" },
      { label: "Severity Priority", val: "CRITICAL ALERT (Tier 1)" }
    ]
  },
  weakness: {
    name: "CWE-119: Memory Corruption",
    type: "Weakness Classification",
    desc: "Improper restriction of operations within the bounds of a memory buffer, leading to arbitrary code execution or service crash.",
    meta: [
      { label: "Class", val: "Memory Safety Flaw" },
      { label: "Exploitation Vector", val: "DCE/RPC Network Packets" },
      { label: "Prevalence", val: "High across legacy C/C++ network services" },
      { label: "Remediation", val: "Patch deployment & bound checking guards" }
    ]
  }
};

function initKnowledgeGraph() {
  const nodes = document.querySelectorAll(".graph-node");
  const typeBadge = document.getElementById("graph-entity-type");
  const nameEl = document.getElementById("graph-entity-name");
  const descEl = document.getElementById("graph-entity-desc");
  const metaContainer = document.getElementById("graph-entity-meta");

  if (!nodes.length || !typeBadge || !nameEl || !descEl || !metaContainer) return;

  function selectNode(key) {
    const data = GRAPH_NODES_DATA[key];
    if (!data) return;

    nodes.forEach(n => {
      n.classList.toggle("active", n.dataset.node === key);
    });

    typeBadge.textContent = data.type;
    nameEl.textContent = data.name;
    descEl.textContent = data.desc;

    metaContainer.innerHTML = data.meta
      .map(
        m => `
        <div class="spec-row">
          <span class="spec-label">${m.label}</span>
          <span class="spec-val">${m.val}</span>
        </div>`
      )
      .join("");
  }

  nodes.forEach(node => {
    node.addEventListener("click", () => {
      selectNode(node.dataset.node);
    });
  });

  // Default selection
  selectNode("cve");
}

/* ==========================================================================
   5. Quickstart Tabs
   ========================================================================== */
function initQuickstartTabs() {
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabContents = document.querySelectorAll(".tab-content");

  if (!tabBtns.length) return;

  tabBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetId = btn.dataset.tab;

      tabBtns.forEach(b => b.classList.remove("active"));
      tabContents.forEach(c => c.classList.remove("active"));

      btn.classList.add("active");
      const targetContent = document.getElementById(`tab-${targetId}`);
      if (targetContent) targetContent.classList.add("active");
    });
  });
}

/* ==========================================================================
   6. Copy to Clipboard
   ========================================================================== */
function initCopyButtons() {
  const copyBtns = document.querySelectorAll(".copy-btn");
  const toast = document.getElementById("toast-notice");

  function showToast(msg) {
    if (!toast) return;
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => {
      toast.classList.remove("show");
    }, 2400);
  }

  copyBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const targetCodeId = btn.dataset.target;
      const codeElement = document.getElementById(targetCodeId);
      if (!codeElement) return;

      const textToCopy = codeElement.innerText.trim();
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = btn.innerHTML;
        btn.innerHTML = `
          <svg class="btn-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
          </svg> Copied!
        `;
        showToast("✓ Command copied to clipboard");
        setTimeout(() => {
          btn.innerHTML = originalText;
        }, 2000);
      });
    });
  });
}
