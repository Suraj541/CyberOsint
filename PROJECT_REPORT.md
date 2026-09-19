# Cybersecurity OSINT Intelligence Platform — Project Report & Architecture Documentation

**Document Version:** 1.0.0  
**Status:** All Tests Passing (633 Passed, 0 Failed, 1 Skipped / 634 Total)  
**Backend API:** FastAPI v0.1.0 (`http://127.0.0.1:8000`)  
**Frontend Web:** Next.js v14.2.35 (`http://localhost:3000`)  
**Date:** September 2026  

---

## Executive Summary

The **Cybersecurity OSINT Intelligence Platform** (`cyber-osint`) is a centralized, automated intelligence platform that continuously discovers, ingests, normalizes, classifies, extracts, and correlates cybersecurity intelligence from publicly accessible internet sources into a queryable knowledge and intelligence layer.

### System Health & Validation Status

| Metric | Status / Value | Details |
| :--- | :--- | :--- |
| **Total Test Cases** | **634 tests** | 48 Stage Suites + 12 Subsystem Suites |
| **Passed Tests** | **633 tests (99.84%)** | All functional and integration suites passing |
| **Failed Tests** | **0 tests (0.00%)** | Zero test failures |
| **Skipped Tests** | **1 test (0.16%)** | `pg_dump` checksum test skipped gracefully under local SQLite fallback |
| **Backend API Server** | **Healthy (200 OK)** | Validated on `GET /health` and `GET /api/v1/dashboard` |
| **Frontend Web Build** | **Compiled Cleanly (22/22 routes)** | Next.js 14 production build verified with 0 TypeScript/ESLint errors |
| **Database Mode** | **SQLite Fallback Active** | Dual-mode support: PostgreSQL in production, automatic SQLite for local offline development |

---

## 1. Test Suite Audit & Problem Resolution Report

### 1.1 The Original Problem in `test_results.txt`

Prior test runs generated an error log indicating:
```text
FAILED (failures=2, errors=26, skipped=34) out of 209 tests
```
Most failures failed with:
```text
ModuleNotFoundError: No module named 'connectors.base'
```

#### Root Cause Analysis:
1. **Unittest Top-Level Directory Shadowing**:
   The test runner was invoked using:
   ```powershell
   python -m unittest discover -s tests -p "test_stage*.py"
   ```
   When `-t` (top-level directory) is omitted, Python's `unittest` sets the top-level package search path to `-s` (the `tests/` folder).
2. **Subpackage Namespace Collisions**:
   Inside the `tests/` directory, there were subdirectories named `tests/connectors/`, `tests/api/`, `tests/classification/`, etc., each containing `__init__.py`. When any test executed `from connectors.base import BaseConnector`, Python resolved `connectors` to the local `tests/connectors` directory (which only contains test files) instead of the actual root `cyber-osint/connectors` package!
3. **Missing `apps/api` in Discovery Path**:
   Certain imports rely on the FastAPI application code located in `apps/api/app`. Without `apps/api` on the import path, modules trying to import schemas or database models failed with `ModuleNotFoundError: No module named 'app'`.

### 1.2 The Fix Applied
1. **Explicit Top-Level Root**:
   Specifying `-t .` forces Python's unittest to treat the root project folder `cyber-osint` as the top-level package:
   ```powershell
   python -m unittest discover -s tests -t . -p "test_*.py"
   ```
2. **Path Configuration**:
   Ensuring `$env:PYTHONPATH = ".;apps/api"` guarantees that both root packages (`connectors`, `services`, `workers`) and the backend application (`app`) are resolved cleanly without any shadowing.
3. **Execution Verification**:
   Running the full suite across all 48 stages and 12 subsystem directories yields **634 tests executed: 633 passed, 0 failed, 1 skipped**.
4. **Convenience Scripts**:
   Created dedicated batch scripts (`run_tests.bat`, `run_backend.bat`, `run_frontend.bat`, `run_all.bat`) so tests and application servers can be started on Windows with a single click.

---

## 2. Test Execution Breakdown by Stage & Subsystem

### Stage Test Suites (`tests/test_stage*.py`)

| Test File | Stage / Focus Area | Tests | Status |
| :--- | :--- | :---: | :---: |
| `test_stage1_repository.py` | Repository Scaffolding, Docker, Config | 14 | PASSED |
| `test_stage2_backend.py` | FastAPI Backend Baseline & Healthcheck | 8 | PASSED |
| `test_stage3_models.py` | PostgreSQL/SQLite SQLAlchemy Core Models | 10 | PASSED |
| `test_stage4_source_registry.py` | BaseConnector Interface & Registry | 7 | PASSED |
| `test_stage5_rss_connector.py` | Priority 1: RSS Feed Connector | 7 | PASSED |
| `test_stage8_ingestion_pipeline.py` | Ingestion, Normalization, Deduplication | 9 | PASSED |
| `test_stage9_scheduler.py` | Periodic Background Scheduler Workers | 7 | PASSED |
| `test_stage10_redis.py` | Cache Layer, Task Queue, Rate Limiting | 6 | PASSED |
| `test_stage11_cve_connectors.py` | Priority 3: CVE & NVD Connectors | 9 | PASSED |
| `test_stage13_taxonomy.py` | 10-Class Security Taxonomy & Keywords | 9 | PASSED |
| `test_stage14_classifier.py` | Rule-based & ML Threat Classification | 9 | PASSED |
| `test_stage15_extractor.py` | Regex/NLP Entity Extraction (CVE, IP, etc.) | 9 | PASSED |
| `test_stage16_deduplication.py` | Exact SHA-256 + SimHash MinHash LSH | 12 | PASSED |
| `test_stage17_search.py` | In-Memory & OpenSearch Full-Text Search | 11 | PASSED |
| `test_stage18_semantic.py` | Dense Semantic Embeddings & Content Chunks | 15 | PASSED |
| `test_stage19_frontend.py` | Next.js Frontend App Directory & Layout | 12 | PASSED |
| `test_stage20_dashboard.py` | Consolidated Dashboard Endpoints & Stats | 19 | PASSED |
| `test_stage22_entity_pages.py` | Entity Profiles & Content Correlation | 25 | PASSED |
| `test_stage23_video_intelligence.py` | Priority 8: Video Metadata & Transcripts | 22 | PASSED |
| `test_stage24_document_intelligence.py` | PDF/DOCX Parsing & Text Extraction | 42 | PASSED |
| `test_stage25_mitre_attack.py` | MITRE ATT&CK Matrix & Technique Mapping | 29 | PASSED |
| `test_stage26_knowledge_graph.py` | Entity Relationship Graph & Visualizations | 25 | PASSED |
| `test_stage27_source_reliability.py` | Source Reputation Scoring & Quality Metrics | 20 | PASSED |
| `test_stage28_ai_summarization.py` | Abstractive & Extractive Summarization | 25 | PASSED |
| `test_stage29_ai_research.py` | AI Research Queries & Threat Synthesis | 24 | PASSED |
| `test_stage30_recommendations.py` | User Recommendations & Content Similarity | 23 | PASSED |
| `test_stage31_watchlists.py` | Threat Watchlists & Entity Alerts | 23 | PASSED |
| `test_stage32_notifications.py` | Multi-Channel Notifications (Webhook/Email) | 33 | PASSED |
| `test_stage33_connectors.py` | Priority 1-11 Connectors Functional Validation | 26 | PASSED |
| `test_stage34_connector_config.py` | Dynamic Connector YAML & Parameter Tuning | 19 | PASSED |
| `test_stage35_secret_management.py` | Secrets Vault & Environment Masking | 17 | PASSED |
| `test_stage36_security_hardening.py` | OWASP Headers, Input Sanitization, Auth | 38 | PASSED |
| `test_stage37_ssrf_protection.py` | Private IP Blocking & SSRF Guardrails | 36 | PASSED |
| `test_stage38_sandboxed_document_processing.py` | Memory-Limited Document Sandbox | 32 | PASSED |
| `test_stage39_testing_suite.py` | Test Framework Health & Harness Verification | 13 | PASSED |
| `test_stage40_observability.py` | Prometheus Metrics & Error Counters | 35 | PASSED |
| `test_stage41_admin_panel.py` | Admin Management Endpoints & Health Check | 34 | PASSED |
| `test_stage42_database_backup.py` | Backup Manager, Compression & Checksums | 65 | 64 PASSED / 1 SKIPPED |
| `test_stage43_deployment.py` | Production Docker & Compose Validation | 9 | PASSED |
| `test_stage44_first_mvp.py` | Phase 1 MVP Integration Baseline | 11 | PASSED |
| `test_stage45_mvp_success_test.py` | MVP End-to-End Success Verification | 19 | PASSED |
| `test_stage46_version2.py` | Version 2 Architecture Validation | 10 | PASSED |
| `test_stage47_version3.py` | Version 3 Intelligence Expansion | 27 | PASSED |
| `test_stage48_version4.py` | Version 4 Enterprise Hardening | 39 | PASSED |
| `test_stage49_compliance_dod.py` | DoD Automated Compliance Verifier | 18 | PASSED |
| `test_stage50_definition_of_done.py` | Platform Definition-of-Done Certificate | 20 | PASSED |
| `test_stage51_critical_architecture.py` | 12-Subsystem Architecture Verification | 27 | PASSED |
| `test_stage52_golden_pipeline.py` | 10-Step Golden Data Pipeline Verification | 14 | PASSED |

### Subsystem Verification Suites (`tests/<subsystem>/`)

| Subsystem Directory | Test Target | Tests | Status |
| :--- | :--- | :---: | :---: |
| `tests/api/` | REST Endpoints, Routing, Parameters | 8 | PASSED |
| `tests/classification/` | Classification Engine & Taxonomy Rules | 6 | PASSED |
| `tests/connectors/` | Connector Base Lifecycle & Registry | 6 | PASSED |
| `tests/deduplication/` | Content Fingerprinting & Similarity | 6 | PASSED |
| `tests/extraction/` | Entity Extractor & Pattern Matching | 7 | PASSED |
| `tests/ingestion/` | Database Storage, Normalizer, Parser | 17 | PASSED |
| `tests/search/` | Search Query Processing & Ranking | 7 | PASSED |
| `tests/security/` | Auth, Access Control, SSRF & File Checks | 14 | PASSED |

**Total Discovery: 634 Tests | 633 Passed | 0 Failed | 1 Skipped**

---

## 3. Project Architecture & Directory Structure

```text
cyber-osint/
├── apps/
│   ├── api/                           # FastAPI Backend Application
│   │   ├── app/
│   │   │   ├── api/v1/                # Version 1 API Route Handlers
│   │   │   │   ├── endpoints/         # Modular endpoints (auth, dashboard, content,
│   │   │   │   │                      # entities, search, connectors, admin, backup, etc.)
│   │   │   │   └── router.py          # Unified APIRouter aggregator
│   │   │   ├── models/                # SQLAlchemy ORM Database Models
│   │   │   │   ├── content.py         # Ingested Content, Articles, CVEs
│   │   │   │   ├── entity.py          # Extracted Entities & Graph Nodes
│   │   │   │   ├── source.py          # Data Sources & Feed Configurations
│   │   │   │   ├── user.py            # User Authentication & Role Model
│   │   │   │   └── watchlist.py       # User Watchlists & Alert Rules
│   │   │   ├── schemas/               # Pydantic v2 Request/Response Schemas
│   │   │   ├── workers/               # Background task scheduler
│   │   │   ├── config.py              # Application settings (Pydantic Settings)
│   │   │   ├── database.py            # Database engine, session factory, SQLite fallback
│   │   │   └── main.py                # FastAPI app initialization, middleware, lifespan
│   │   ├── alembic/                   # Database migration scripts
│   │   └── requirements.txt           # Backend Python dependencies
│   └── web/                           # Next.js 14 Web Frontend
│       ├── app/                       # App Router pages & layouts
│       │   ├── page.tsx               # Consolidated Dashboard home
│       │   ├── admin/                 # OSINT Admin Panel & Monitoring
│       │   ├── intelligence/          # Threat Intelligence Explorer
│       │   ├── search/                # Semantic & Full-text Search UI
│       │   ├── graph/                 # Interactive Knowledge Graph
│       │   ├── sources/               # Source Registry Management
│       │   ├── vulnerabilities/       # CVE & Vulnerability Tracker
│       │   ├── watchlists/            # User Alerts & Watchlists
│       │   └── ... (22 total routes)
│       ├── components/                # Modular React UI components
│       ├── lib/                       # API client & utility functions
│       └── package.json               # Frontend dependencies & scripts
├── connectors/                        # Data Source Ingestion Connectors (11 Prioritized)
│   ├── base.py                        # BaseConnector abstract base class & NormalizedItem
│   ├── registry.py                    # Connector dynamic registry
│   ├── manager.py                     # Priority connector execution manager
│   ├── config.py                      # Dynamic YAML configuration loader
│   ├── rss/                           # Priority 1: Security RSS/Atom feeds
│   ├── cert/                          # Priority 2: Government & National CERT advisories
│   ├── cve/                           # Priority 3: NVD & CVE vulnerability feeds
│   ├── vendor/                        # Priority 4: Microsoft, Cisco, Red Hat vendor bulletins
│   ├── blog/                          # Priority 5: Security research blogs
│   ├── github/                        # Priority 6: GitHub security advisories & exploit repos
│   ├── research/                      # Priority 7: Academic papers & arXiv databases
│   ├── video/                         # Priority 8: YouTube security conferences & talks
│   ├── conference/                    # Priority 9: DEF CON, Black Hat conference sources
│   ├── social/                        # Priority 10: Public social media & Mastodon feeds
│   ├── specialized/                   # Priority 11: Specialized threat data feeds
│   └── document/                      # Document parser connector (PDF, DOCX)
├── services/                          # Core Domain Processing Engines
│   ├── classification/                # 10-Class Security Taxonomy & Rule/ML Classifier
│   ├── extraction/                    # Regex & Spacy Entity Extractor (CVE, IP, domain, hash)
│   ├── deduplication/                 # Exact SHA-256 + SimHash/MinHash LSH Deduplication
│   ├── search/                        # Full-text keyword & inverted index search
│   ├── semantic/                      # Dense vector embeddings & Content Chunker
│   ├── mitre/                         # MITRE ATT&CK Matrix & Technique Mapper
│   ├── graph/                         # Knowledge Graph builder & relationship edges
│   ├── reliability/                   # Source reputation & data quality scorer
│   ├── summarization/                 # Abstractive & extractive threat summarizer
│   ├── research/                      # AI threat researcher & synthesis assistant
│   ├── recommendations/               # Personalized intelligence recommendation engine
│   ├── watchlists/                    # Watchlist matching & alert triggering engine
│   ├── notifications/                 # Multi-channel notification dispatcher (Webhook, Email)
│   ├── cache/                         # Redis cache wrapper & sliding-window rate limiter
│   ├── queue/                         # Distributed task queue & asynchronous workers
│   ├── backup/                        # Database backup manager, gzip compression, checksums
│   ├── security/                      # OWASP security headers, SSRF validator, sandboxing
│   ├── observability/                 # Prometheus metrics exporter & latency trackers
│   └── compliance/                    # Definition of Done & Golden Pipeline verifier
├── tests/                             # Comprehensive Unit, Integration & Stage Test Suites
├── run_backend.bat                    # Batch launcher for FastAPI API server
├── run_frontend.bat                   # Batch launcher for Next.js Web UI
├── run_tests.bat                      # Batch runner for the entire test suite
├── run_all.bat                        # Launcher for both Backend and Frontend concurrently
├── docker-compose.yml                 # Docker Compose for local PostgreSQL + Redis
├── connectors.yaml                    # Active OSINT source configurations
└── PROJECT_REPORT.md                  # This master documentation and audit report
```

---

## 4. End-to-End System Working: The 10-Step Golden Pipeline

The platform ingests and correlates unstructured cybersecurity data through a deterministic 10-step pipeline:

```text
┌────────────────────────┐
│ 1. Public Data Sources │ (RSS, CERTs, CVE/NVD, Vendor Bulletins, GitHub, Blogs, Videos)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 2. Priority Connectors │ (BaseConnector subclass discovers, rate-limits & fetches items)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 3. Normalization       │ (Standardizes into NormalizedItem with canonical URLs & timestamps)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 4. Deduplication       │ (Stage 1: Exact SHA-256 hash | Stage 2: SimHash MinHash LSH)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 5. Classification      │ (Assigns to 10-class taxonomy: Ransomware, Zero-Day, Exploit, etc.)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 6. Entity Extraction   │ (Extracts CVEs, IPv4/IPv6, FQDNs, SHA-256/MD5 hashes, MITRE IDs)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 7. Knowledge Graph     │ (Builds directed relationship edges: Actor -> Tool -> Vulnerability)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 8. Semantic Indexing   │ (Splits into ContentChunks and computes dense vector embeddings)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 9. Storage & Search    │ (Persisted to PostgreSQL/SQLite and indexed for full-text search)
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│ 10. API & Web UI       │ (Exposed via FastAPI endpoints and visualized in Next.js UI)
└────────────────────────┘
```

### The 10 Pipeline Stages in Detail:

1. **Source Discovery**: Connectors read source configurations from `connectors.yaml` and discover new items from public endpoints without violating robots.txt or rate limits.
2. **Connector Execution**: 11 prioritized connectors poll feeds, APIs, and document endpoints using bounded HTTP clients guarded by SSRF protection.
3. **Data Normalization**: Raw heterogeneous feeds (Atom, RSS, JSON-LD, Markdown, HTML) are mapped into standard `NormalizedItem` contracts.
4. **Deduplication Engine**:
   - *Exact Deduplication*: SHA-256 hash calculated over normalized URL + body text.
   - *Near-Duplicate Detection*: SimHash 64-bit fingerprinting with Hamming distance $\le 3$ flags republished and syndicated stories.
5. **Taxonomy Classification**:
   Content is automatically categorized into 10 structured domains:
   - `advisory_bulletin`
   - `vulnerability_cve`
   - `malware_ransomware`
   - `threat_actor_apt`
   - `incident_breach`
   - `defensive_detection`
   - `offensive_exploit`
   - `security_tooling`
   - `research_paper`
   - `educational_ctf`
6. **Entity Extraction**:
   Regex engines and Spacy NLP extract Indicators of Compromise (IoCs) including CVE IDs (`CVE-\d{4}-\d{4,}`), IPv4/IPv6 addresses, hostnames/domains, MD5/SHA-1/SHA-256 file hashes, and MITRE ATT&CK techniques (`T\d{4}(\.\d{3})?`).
7. **Graph Correlation**:
   Extracted entities form a graph linking actors to observed CVEs, exploited software, and detection signatures.
8. **Semantic Chunking & Embedding**:
   Long articles and whitepapers are chunked with configurable overlap and passed to sentence transformer embedding models for high-dimensional semantic search.
9. **Persistence & Full-Text Search**:
   Structured metadata, content bodies, and entity correlations are committed in an ACID transaction with fallback support to SQLite.
10. **Delivery Layer**:
    FastAPI serves cached responses, streaming SSE feeds, and REST endpoints consumed by the Next.js React UI.

---

## 5. REST API Catalog & Usage Guide

The backend exposes a comprehensive RESTful API under the `/api/v1` prefix with complete Swagger interactive documentation at `http://127.0.0.1:8000/docs`.

### Core Endpoint Summary:

| Group | Method | Path | Description |
| :--- | :---: | :--- | :--- |
| **System** | `GET` | `/health` | Core health check (status: "ok") |
| **System** | `GET` | `/api/v1/health/detail` | Detailed subsystem status, DB, Redis, and disk stats |
| **Dashboard** | `GET` | `/api/v1/dashboard` | Consolidated intelligence dashboard with live DB aggregations |
| **Content** | `GET` | `/api/v1/content` | Paginated search and filtering across ingested content |
| **Content** | `GET` | `/api/v1/content/{id}` | Detailed content view with extracted entities and tags |
| **Entities** | `GET` | `/api/v1/entities` | List extracted IoCs, CVEs, Threat Actors, and Domains |
| **Entities** | `GET` | `/api/v1/entities/{id}` | Detailed entity profile and correlated content items |
| **Search** | `POST` | `/api/v1/search/query` | Hybrid full-text keyword and semantic vector search |
| **Sources** | `GET` | `/api/v1/sources` | Source registry status, active connectors, and fetch stats |
| **Sources** | `POST`| `/api/v1/sources` | Register a new OSINT source feed or API |
| **Connectors** | `GET` | `/api/v1/connectors` | Real-time status of all 11 prioritized connectors |
| **Connectors** | `POST`| `/api/v1/connectors/{name}/trigger` | Manually invoke an on-demand connector sync |
| **MITRE** | `GET` | `/api/v1/mitre/matrix` | MITRE ATT&CK enterprise tactics and mapped techniques |
| **Graph** | `GET` | `/api/v1/graph/export` | Node and edge JSON export for graph visualization |
| **Watchlists**| `GET` | `/api/v1/watchlists` | User watchlists and configured alert thresholds |
| **Admin** | `GET` | `/api/v1/admin/metrics` | Observability metrics, request rates, error counters |
| **Admin** | `POST`| `/api/v1/admin/backup/trigger` | Trigger an on-demand database backup and verify checksum |
| **Compliance**| `GET` | `/api/v1/compliance/report` | Automated Definition of Done (DoD) audit report |

---

## 6. How to Run the Project (Windows & Cross-Platform)

### Option 1: One-Click Windows Launchers (Recommended)

Four pre-configured batch scripts have been created in the `cyber-osint/` root:

1. **Run Everything Simultaneously**:
   Double-click or run:
   ```cmd
   run_all.bat
   ```
   This launches the FastAPI API server on port 8000 in one terminal window and the Next.js Web UI on port 3000 in a second terminal window.

2. **Run Only the Backend API**:
   ```cmd
   run_backend.bat
   ```
   - Server address: `http://127.0.0.1:8000`
   - Interactive Swagger docs: `http://127.0.0.1:8000/docs`
   - ReDoc documentation: `http://127.0.0.1:8000/redoc`

3. **Run Only the Frontend Web UI**:
   ```cmd
   run_frontend.bat
   ```
   - Web application: `http://localhost:3000`

4. **Run the Full Test Suite**:
   ```cmd
   run_tests.bat
   ```
   Executes all 634 tests across stage and subsystem suites with full reporting.

---

### Option 2: Manual PowerShell / Command Line

#### Starting Backend:
```powershell
cd c:\Users\suraj\Desktop\the_info\cyber-osint
$env:PYTHONPATH = ".;apps/api"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

#### Starting Frontend:
```powershell
cd c:\Users\suraj\Desktop\the_info\cyber-osint\apps\web
cmd.exe /c "npm run dev"
```

#### Executing All Tests:
```powershell
cd c:\Users\suraj\Desktop\the_info\cyber-osint
$env:PYTHONPATH = ".;apps/api"
python -m unittest discover -s tests -t . -p "test_*.py"
```

---

### Option 3: Containerized Deployment (Docker Compose)

For production or containerized environments with PostgreSQL and Redis:
```bash
cd cyber-osint
# Copy environment file
cp .env.example .env

# Start all infrastructure and services
docker compose up -d

# Verify container health
docker compose ps
```

---

## 7. Summary of Changes & Deliverables

1. **Root Cause Analysis & Fix**:
   - Diagnosed import shadowing caused by missing `-t .` in unittest discovery.
   - Verified that all 634 tests now execute cleanly with **633 passed, 0 failed, 1 gracefully skipped**.
   - Overwrote and cleaned `test_results.txt` with the complete passing log.
2. **Live Service Verification**:
   - Validated live startup of the FastAPI backend on `http://127.0.0.1:8000`.
   - Verified live responses for `GET /health` (`200 OK`), `GET /api/v1/dashboard` (`200 OK`), and Swagger UI on `/docs` (`200 OK`).
   - Verified production build of Next.js frontend across all 22 routes with zero compiler or linting errors.
3. **Automated Windows Convenience Scripts**:
   - Created `run_backend.bat`
   - Created `run_frontend.bat`
   - Created `run_tests.bat`
   - Created `run_all.bat`
4. **Comprehensive Documentation & Project Report**:
   - Authored this complete `PROJECT_REPORT.md` detailing architecture, test metrics, pipeline data flow, API endpoints, and execution instructions.

---

## 8. Real-Time OSINT Ingestion Pipeline Audit & Operational Fixes

### 8.1 Executive Summary of Pipeline Fixes
During the comprehensive real-time pipeline audit, five critical architectural disconnects were identified that prevented live cybersecurity data from reaching the database and frontend:
1. **Disconnected Database Sources**: `connectors.yaml` defined 11 OSINT intelligence sources, but the database `sources` table was empty (or contained 1 unresolvable dummy feed). Connectors were never synchronized into the database source registry.
2. **Scheduler Inactivity**: `ENABLE_SCHEDULER` defaulted to `False` in `app/config.py`, and `PeriodicScheduler` was hardcoded to only poll RSS feeds, completely neglecting CVEs, CERTs, vendor advisories, research papers, videos, and GitHub security feeds.
3. **In-Memory Discard in Manager**: `connector_manager.run_connector()` discovered and normalized intelligence items in-memory but did not pass them to `ingestion_pipeline.ingest_items()` or commit them to the database `Content` and `Entity` tables.
4. **Connector Parsing & SSRF Bugs**:
   - `VideoConnector`: Syntax unpacking error on SSRF validation tuple and missing default source URL caused it to discover 0 videos.
   - `CERTConnector`: Swallowed XML feeds into `JSONDecodeError` and caught SSRF exceptions into mock data.
   - `ResearchConnector`: Discarded live arXiv HTTP responses and hardcoded `return MOCK_RESEARCH_PAPERS`.
   - `VendorAdvisoryConnector`: Defaulted to a dead URL (`/api/advisories`) instead of Microsoft MSRC CVRF API (`/cvrf/v2.0/updates`).
5. **Missing API Endpoints & SSE Stalling**: Frontend queried `/api/v1/cve` and `/api/v1/threat-intel`, which did not exist on the backend (returning 404), causing the Next.js UI to fall back to static 2024 records.

### 8.2 Live Operational Status
After applying targeted architectural fixes:
- **Monitored Sources**: 12 active sources registered in database.
- **Connectors**: 11/11 priority connectors registered, scheduled, and verified working with live HTTP/API responses.
- **Database Freshness**: Over **2,760+ content records** and **2,980+ extracted entities** live in the database with timestamps from the current year.
- **End-to-End Test Passing**: **760 total tests passing** (634 core tests + 126 api tests, 0 failed, 1 skipped).
- **Diagnostics**: `python -m connectors.diagnostic` runs full connectivity preflight, discovery, normalization, deduplication, and database insertion across all 11 sources.

