# CyberOsint — Cybersecurity OSINT Intelligence Platform

> A production-grade, sovereign Open Source Intelligence (OSINT) platform engineered to continuously ingest, normalize, classify, cross-link, and correlate cybersecurity intelligence from authoritative global threat feeds, vulnerability databases, and security advisories into an interactive knowledge graph and hybrid search engine.

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js%2014-black.svg?logo=next.js&logoColor=white)](https://nextjs.org)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg?logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Live%20Showcase-GitHub%20Pages-e5a93b.svg)](https://suraj541.github.io/CyberOsint/)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Verified-emerald.svg)](#features)

---

## 1. System Overview

**CyberOsint** is an autonomous cybersecurity OSINT workstation and aggregation engine. It monitors external sovereign CERT directives, vendor vulnerability registries, peer-reviewed exploit research, threat actor campaigns, and decentralized infosec channels.

All ingested data undergoes deterministic deduplication, semantic classification, named entity recognition (NER), and relationship mapping, feeding an interactive warm-paper intelligence dashboard, an entity knowledge graph, and a Reciprocal Rank Fusion (RRF) hybrid search engine.

### Strict Ethical OSINT Compliance
This platform operates exclusively within public OSINT boundaries:
* **No Unauthorized Access**: Does not bypass authentication gates, paywalls, or bot mitigation.
* **No Private Scraping**: Does not intercept private forums, closed channels, or credentials.
* **Respectful Ingestion**: Honors `robots.txt`, enforces request rate limiting, exponential backoff, and full SSRF protection (prohibiting RFC 1918 / loopback / cloud metadata egress).
* Conforms to the ethical security disclosure guidelines documented in [SECURITY.md](SECURITY.md).

---

## 2. Core Features

* **Continuous OSINT Aggregation**: Multi-threaded, scheduled ingestion pipeline supporting RSS/Atom, REST APIs, JSON advisories, and structured feeds.
* **10+ Standard Intelligence Connectors**:
  * *Government CERTs*: CISA Alerts, Operational Directives, and Advisories
  * *Vulnerability Registries*: CISA KEV (Known Exploited Vulnerabilities) & NVD feeds
  * *Vendor Security*: Microsoft Security Response Center (MSRC CVRF/CSAF)
  * *Security Blogs & Research*: Google Project Zero, arXiv Computer Science (cs.CR)
  * *Ecosystem Advisories*: GitHub Security Advisory Database (GHSA)
  * *Decentralized Infosec*: Mastodon `infosec.exchange` threat telemetry
  * *Specialized Malware Threat Feeds*: Abuse.ch MalwareBazaar IOCs and family signatures
* **Reciprocal Rank Fusion (RRF) Hybrid Search**:
  * Simultaneously evaluates BM25 full-text queries and dense vector embeddings ($k=60$).
  * Real-time engine health telemetry badge (`TEXT ● VECTOR ● RRF ●`).
  * Expandable diagnostics with keyword vs. vector score breakdowns.
* **Knowledge Graph & Entity Resolution**:
  * Extracts, normalizes, and links Vendors, Technologies, Vulnerabilities (CVEs), Malware Families, and Threat Actors.
  * Graph topology engine computing multi-hop neighbor subgraphs, degrees, and shortest path traversals.
  * Deep intelligence dossiers displaying confidence gauges, aliases, activity timelines, and correlated threat reports.
* **Curated OSINT Toolkit Directory**:
  * 10 curated tools across 5 categories: Frameworks (OSINT Framework, Intelligence X), Domain Infrastructure (theHarvester, Hunter, DNSDumpster), Network (Shodan, Censys), People/Social (Sherlock, Social Searcher), and Document Metadata (FOCA).
* **Vulnerability Surveillance (CVE & KEV Tracker)**:
  * CVSS v3.1 impact ratings, vector strings, CWE classifications, and active in-the-wild exploitation filters.
* **Threat News & Advisory Wire**:
  * Editorial intelligence briefing with lead story feature, chronological dispatches, and source activity distribution.
* **Live SSE Telemetry & Notifications**:
  * Server-Sent Events (SSE) dispatching real-time ingestion status and threat alert triggers.
* **Security & Sandboxing Hardening**:
  * SSRF validation engine restricting loopback (`127.0.0.1`), link-local (`169.254.169.254`), and private subnets.
  * Token-bucket rate limiting and cryptographically protected secret vault backends (Env, Encrypted File, Vault).

---

## 3. System Architecture

```text
               ┌──────────────────────────────────────────────────────────┐
               │              External Public Intelligence Sources        │
               │   (CISA KEV, MSRC, GHSA, Project Zero, arXiv, Abuse.ch)   │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │               Autonomous Connectors Layer                │
               │  (SSRF-Protected, Rate-Limited, Exponential Backoff)     │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │               Collection & Ingestion Pipeline            │
               │        (Raw Staging, SHA256 Deduplication, Metrics)      │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │           Enrichment & Extraction Processors             │
               │   • Cybersecurity Taxonomy Classifier                    │
               │   • Security Entity Extraction & Normalization           │
               │   • Co-occurrence Relationship Builder                   │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │                PostgreSQL 16 Storage Engine              │
               │   (Content, Entities, Relationships, CVEs, Sources)      │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │                Hybrid Search Engine (RRF)                │
               │   • OpenSearch BM25 Full-Text Search                     │
               │   • 384-D Dense Vector Embeddings (all-MiniLM-L6-v2)     │
               │   • Reciprocal Rank Fusion Algorithm (k=60)              │
               └─────────────────────────────┬────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────────┐
               │                 FastAPI REST API Layer                       │
               │  • /api/v1/content     • /api/v1/entities   • /api/v1/search │
               │  • /api/v1/graph       • /api/v1/cve        • /api/v1/sources│
               └─────────────────────────────┬────────────────────────────────┘
                                             │
                                             ▼
               ┌──────────────────────────────────────────────────────────┐
               │             Next.js 14 Web Workstation (UI)              │
               │  • Archival Paper Dossier Design System                  │
               │  • Interactive Knowledge Graph Explorer                  │
               │  • OSINT Toolkit, Situation News Wire & Surveillance     │
               └──────────────────────────────────────────────────────────┘
```

---

## 4. Technology Stack

### Backend
* **Language & Framework**: Python 3.11+, FastAPI, Uvicorn
* **Database & ORM**: PostgreSQL 16, SQLAlchemy 2.0, Alembic
* **Search & Vectors**: Reciprocal Rank Fusion (RRF), OpenSearch client, SentenceTransformers
* **Networking & Security**: HTTPX with custom SSRF-safe DNS resolver, Tenacity backoff

### Frontend
* **Framework**: Next.js 14 (App Router, Server & Client Components)
* **Library**: React 18, TypeScript 5
* **Styling**: Tailwind CSS (Custom Archival Warm-Paper Design System)
* **Icons & UI**: Lucide React, Glassmorphic Panels, SVG Graph Canvas

### Infrastructure
* **Database**: PostgreSQL 16
* **Cache & Broker**: Redis 7
* **Containerization**: Docker Compose (`docker-compose.yml`, `docker-compose.prod.yml`)

---

## 5. Repository Structure

```text
cyber-osint/
├── apps/
│   ├── api/                     # FastAPI Backend Application
│   │   ├── alembic/             # Database schema migrations
│   │   ├── app/
│   │   │   ├── api/v1/          # REST route handlers (search, entities, graph, etc.)
│   │   │   ├── models/          # SQLAlchemy database models
│   │   │   ├── schemas/         # Pydantic validation schemas
│   │   │   ├── workers/         # Background scheduler & sync workers
│   │   │   ├── database.py      # Database session management
│   │   │   └── main.py          # FastAPI application factory
│   │   └── requirements.txt     # Backend Python dependencies
│   └── web/                     # Next.js 14 Frontend Application
│       ├── app/                 # App Router pages (/, search, graph, entities, etc.)
│       ├── components/          # Reusable UI components (Navbar, Sidebar, Modals)
│       ├── lib/                 # API client, types, and formatters
│       ├── tailwind.config.js   # Archival paper color tokens
│       └── package.json         # Frontend dependencies & scripts
├── connectors/                  # Source connectors (CERT, CVE, RSS, GitHub, etc.)
│   ├── base.py                  # BaseConnector abstract class
│   ├── registry.py              # Dynamic connector registry
│   └── security.py              # SSRF protection & safe HTTP client
├── services/                    # Core business logic services
│   ├── ingestion/               # Pipeline execution & metrics
│   ├── search/                  # Search indexing & retrieval
│   ├── semantic/                # RRF hybrid fusion & embedding service
│   ├── graph/                   # Graph topology & subgraph queries
│   └── secrets/                 # Vault & key manager
├── tests/                       # Unit and integration test suites
├── connectors.yaml              # Active feed definitions and intervals
├── docker-compose.yml           # Local multi-container development environment
├── run_all.bat                  # 1-click Windows startup script
├── run_backend.bat              # Backend launcher script
├── run_frontend.bat             # Frontend launcher script
├── .env.example                 # Safe environment template
├── .gitignore                   # Comprehensive exclude rules
└── README.md                    # Platform documentation
```

---

## 6. Installation & Quickstart

### Prerequisites
* **Python**: 3.11 or higher
* **Node.js**: 18.17+ / 20+ and `npm`
* **PostgreSQL**: Version 15 or 16
* **Git**

### 1. Clone the Repository
```bash
git clone https://github.com/Suraj541/CyberOsint.git
cd CyberOsint
```

### 2. Environment Configuration
Copy the template to create your local `.env`:
```bash
cp .env.example .env
```
Configure your PostgreSQL credentials in `.env`:
```env
DATABASE_URL="postgresql://postgres:your_password@localhost:5432/cyber_osint"
POSTGRES_USER="postgres"
POSTGRES_PASSWORD="your_password"
POSTGRES_DB="cyber_osint"
```

### 3. Backend Setup
```bash
# Create and activate virtual environment
python -m venv .venv

# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r apps/api/requirements.txt
```

### 4. Database Initialization
```bash
# Apply migrations to PostgreSQL
cd apps/api
alembic upgrade head
cd ../..
```

### 5. Frontend Setup
```bash
cd apps/web
npm install
cd ../..
```

---

## 7. Running the Platform

### Option A: 1-Click Launch (Windows)
Double-click `run_all.bat` (or execute `.\run_all.bat` in terminal). This automatically starts:
* **FastAPI Backend**: `http://127.0.0.1:8000` (Swagger docs: `http://127.0.0.1:8000/docs`)
* **Next.js Web UI**: `http://localhost:3000`

### Option B: Dedicated Terminals

#### Terminal 1 — Backend API
```bash
# Set PYTHONPATH and start Uvicorn
run_backend.bat
# Or manually:
set PYTHONPATH=.;apps/api
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Terminal 2 — Frontend UI
```bash
run_frontend.bat
# Or manually:
cd apps/web
npm run dev
# For production server: npm run build && npm run start
```

---

## 8. Verification & Testing

Execute the automated verification test suite:

```bash
# Set PYTHONPATH
set PYTHONPATH=.;apps/api

# Run comprehensive test suites
python -m unittest tests/test_stage19_frontend.py tests/test_stage22_entity_pages.py tests/test_stage26_knowledge_graph.py apps/api/tests/test_rrf_comprehensive.py
```

### Frontend Typecheck & Production Build
```bash
cd apps/web
npx tsc --noEmit
npm run build
```

---

## 9. License

This project is open source and licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for terms.
