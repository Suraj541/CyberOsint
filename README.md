# Cybersecurity OSINT Intelligence Platform (`cyber-osint`)

> A centralized, automated intelligence platform that continuously discovers, normalizes, classifies, extracts, and correlates cybersecurity intelligence from publicly accessible internet sources into a queryable knowledge and intelligence layer.

[![Platform Architecture](https://img.shields.io/badge/Architecture-OSINT--Pipeline-blue.svg)](#system-architecture)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Stage%201%20Repository%20Initialized-orange.svg)](#roadmap)

---

## 1. System Overview

The **Cybersecurity OSINT Intelligence Platform** aggregates and correlates:
- Security advisories, vendor bulletins, and CERT warnings
- CVEs, CWEs, and exploit intelligence
- Malware research and threat actor profiles
- Incident reports, breach disclosures, and forensics notes
- Technical documentation, security frameworks, and research papers
- Curated educational material, CTF writeups, and open-source tooling

### Strict OSINT Scope & Legal Compliance

This platform operates strictly as an **Open-Source Intelligence (OSINT)** platform:
- **No unauthorized access**: Never circumvents authentication, paywalls, or CAPTCHAs.
- **No private surveillance**: Never accesses private accounts or scrapes restricted communications.
- **Ethical collection**: Respects terms of service, `robots.txt`, rate limits, copyright, and privacy laws.
- When full content cannot legally or technically be retained, only metadata and canonical source URLs are preserved.
- Full details are codified in [SECURITY.md](SECURITY.md).

---

## 2. System Architecture

The ingestion and intelligence processing follows a clean, decoupled data pipeline:

```text
               ┌───────────────────────────────┐
               │         Data Sources          │
               └───────────────┬───────────────┘
                               │
            ┌──────────────────┼──────────────────┐
            ▼                  ▼                  ▼
     Search Connectors   API Connectors    Feed Connectors
            │                  │                  │
            └──────────────────┼──────────────────┘
                               ▼
               ┌───────────────────────────────┐
               │    Source Discovery Engine    │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │ Collection / Fetching Pipeline │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │        Raw Data Storage       │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │     Parsing & Normalization   │
               └───────────────┬───────────────┘
                               ▼
       ┌───────────────────────┼───────────────────────┐
       ▼                       ▼                       ▼
 Classification         Entity Extraction        Deduplication
       │                       │                       │
       └───────────────────────┼───────────────────────┘
                               ▼
               ┌───────────────────────────────┐
               │    Intelligence Enrichment    │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │   PostgreSQL + OpenSearch     │
               └───────────────┬───────────────┘
                               ▼
               ┌───────────────────────────────┐
               │    API & Searchable Web UI    │
               └───────────────────────────────┘
```

---

## 3. Repository Structure

```text
cyber-osint/
├── README.md               # Project overview, architecture, and quickstart
├── PLAN.md                 # Complete platform architecture blueprint
├── IMPLEMENT.md            # Step-by-step milestone implementation roadmap
├── SECURITY.md             # Ethical OSINT scope & vulnerability disclosure policy
├── LICENSE                 # Apache License 2.0
├── .gitignore              # Environment, dependency, and build ignore rules
├── .env.example            # Environment configuration template
├── docker-compose.yml      # Containerized runtime (PostgreSQL, Redis)
├── apps/                   # Application packages (API, Web frontend)
│   └── api/                # FastAPI backend service (Stage 2)
└── tests/                  # Integration and verification test suites
```

---

## 4. Quickstart

### Prerequisites
- Python >= 3.11
- Docker and Docker Compose
- Git

### Initializing Environment
```bash
# Clone or enter directory
cd cyber-osint

# Copy environment template
cp .env.example .env

# Start core infrastructure (PostgreSQL, Redis)
docker compose up -d

# Verify services
docker compose ps
```

---

## 5. Implementation Roadmap & Verification

The project is executed incrementally following the sequence specified in [`IMPLEMENT.md`](IMPLEMENT.md):

1. **[x] Step 1: Create the Repository** — Repository scaffold, Docker compose services, environment baseline, security policy, and Stage 1 verification tests.
2. **[ ] Step 2: Create the Backend** — FastAPI service (`apps/api/`), configuration, database session factory, and `GET /health` endpoint.
3. **[ ] Step 3: Create PostgreSQL Models** — Core tables (`users`, `sources`, `content`, `entities`, `content_entities`, `tags`, `content_tags`).
4. **[ ] Step 4: Source Registry & Connector Interface** — `BaseConnector` contract and source registration service.
5. **[ ] Step 5: RSS Connector** — First operational connector for security feeds.
6. **[ ] Step 6: Ingestion Pipeline** — Discovery, normalization, deduplication, and persistence.
7. **[ ] Step 7: Scheduler & Background Workers** — Periodic feed ingestion.

---

## 6. License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
