"""
API Version 1 Master Router
Aggregates all endpoint routers under /api/v1.
"""

from fastapi import APIRouter
from app.api.v1.endpoints import (
    cache,
    classifier,
    content,
    dashboard,
    deduplication,
    documents,
    entities,
    extractor,
    graph,
    health,
    mitre,
    queue,
    recommendations,
    research,
    scheduler,
    search,
    semantic,
    sources,
    summaries,
    taxonomy,
)

api_router = APIRouter()

# Health endpoints
api_router.include_router(health.router, tags=["Health"])

# Source registry endpoints
api_router.include_router(sources.router)

# Normalized content endpoints
api_router.include_router(content.router)

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
