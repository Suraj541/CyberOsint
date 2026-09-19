"""
API Version 1 Master Router
Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    backup,
    cache,
    classifier,
    compliance,
    connectors,
    content,
    cve_intel,
    dashboard,
    deduplication,
    documents,
    entities,
    extractor,
    graph,
    health,
    intelligence,
    mitre,
    notifications,
    observability,
    queue,
    recommendations,
    research,
    scale,
    scheduler,
    search,
    secrets,
    security,
    semantic,
    sources,
    summaries,
    taxonomy,
    watchlists,
)

api_router = APIRouter()

# Health endpoints
api_router.include_router(health.router, tags=["Health"])

# Section 43 Step 42: Database Backup & Disaster Recovery
api_router.include_router(backup.router)

# Section 41 Step 40: Observability & Admin Metrics endpoints
api_router.include_router(observability.router)

# Security Hardening & Posture Controls (Section 37 Step 36)
api_router.include_router(security.router)

# Secret Management & Security Audit (Section 36 Step 35)
api_router.include_router(secrets.router)

# Advanced OSINT Connectors (Section 34 Step 33)
api_router.include_router(connectors.router)

# Source registry endpoints
api_router.include_router(sources.router)

# Normalized content endpoints
api_router.include_router(content.router)

# Real-time CVE, Threat Intel, and Live SSE Feeds
api_router.include_router(cve_intel.router)

# Watchlists & Surveillance endpoints (Section 32)
api_router.include_router(watchlists.router)

# Notifications & Alerting endpoints (Section 33 / Step 32)
api_router.include_router(notifications.router)


# Personalized Recommendations endpoints (Section 31)
api_router.include_router(recommendations.router)

# AI Summarization endpoints (Section 29)
api_router.include_router(summaries.router)

# AI Research Assistant endpoints (Section 30)
api_router.include_router(research.router)

# Document Intelligence endpoints (Section 25)
api_router.include_router(documents.router)

# Dashboard intelligence aggregator endpoints (Section 21)
api_router.include_router(dashboard.router)

# Extracted entities & CVE intelligence
api_router.include_router(entities.router)

# MITRE ATT&CK Enterprise Matrix & Graph endpoints (Section 26)
api_router.include_router(mitre.router)

# Knowledge Graph endpoints (Section 27)
api_router.include_router(graph.router)

# Section 48 (Step 47): Version 3 Advanced Intelligence endpoints
api_router.include_router(intelligence.router)

# Section 49 (Step 48): Version 4 Scale Architecture endpoints
api_router.include_router(scale.router)

# Section 50 & 51 (Step 49): Compliance, System Readiness & Definition of Done
api_router.include_router(compliance.router)




# Cybersecurity Taxonomy endpoints
api_router.include_router(taxonomy.router)

# Content Classification Engine endpoints
api_router.include_router(classifier.router)

# Deterministic Entity Extraction endpoints
api_router.include_router(extractor.router)

# Advanced Deduplication Engine & Cluster endpoints
api_router.include_router(deduplication.router)

# OpenSearch Full-Text and Faceted Search endpoints
api_router.include_router(search.router)

# Semantic & Hybrid Vector Search endpoints
api_router.include_router(semantic.router)

# Background scheduler endpoints
api_router.include_router(scheduler.router)

# Cache & Redis diagnostics
api_router.include_router(cache.router)

# Task Queue endpoints
api_router.include_router(queue.router)
