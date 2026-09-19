"""Section 49 (Step 48): Version 4 Scale REST API Endpoints.

Provides unified REST APIs for:
  1. Distributed Ingestion & Backpressure Control
  2. Connector Marketplace
  3. Multi-Region Deployment & Geo-Routing
  4. Advanced Multi-Tier Caching & Invalidation
  5. Large-Scale Search & ILM Policies
  6. Advanced Graph Analytics (Centrality, Communities, Blast Radius)
  7. Model Routing & SLA Gateway
  8. Automated Pipeline Evaluation & Drift Benchmarks
  9. Source Quality Learning & Bayesian Reputation
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.scale import (
    BenchmarkRunModel,
    MarketplaceConnectorModel,
    RegionNodeModel,
    SourceReputationModel,
)
from app.schemas.scale import (
    BackpressureStatus,
    BackpressureUpdateRequest,
    BenchmarkRunOut,
    BlastRadiusRequest,
    BlastRadiusResponse,
    CacheInvalidateRequest,
    CacheInvalidateResponse,
    CacheStatsOut,
    CentralityRankingItem,
    CommunityClusterItem,
    EvaluationTriggerRequest,
    FailoverRequest,
    FederatedSearchRequest,
    FederatedSearchResponse,
    GeoRouteRequest,
    GeoRouteResponse,
    ILMPolicyOut,
    MarketplaceConnectorOut,
    MarketplacePublishRequest,
    ModelRouteConfig,
    ModelRouteRequest,
    ModelRouteResponse,
    RegionNodeOut,
    ReputationUpdateRequest,
    ScaleOverviewOut,
    SourceReputationOut,
)
from services.scale import (
    advanced_cache,
    auto_evaluation,
    connector_marketplace,
    distributed_ingestion,
    graph_analytics,
    large_scale_search,
    model_router,
    multi_region,
    source_quality_learning,
)

router = APIRouter(prefix="/scale", tags=["Scale & Version 4 Architecture"])


# ─── Global Overview ──────────────────────────────────────────────────────────
@router.get("/overview", response_model=ScaleOverviewOut, summary="Get Scale Architecture Overview")
def get_scale_overview(db: Session = Depends(get_db)) -> ScaleOverviewOut:
    """Returns aggregated high-level telemetry across all 9 scale domains."""
    connector_marketplace.seed_marketplace(db)
    multi_region.seed_regions(db)
    auto_evaluation.seed_benchmarks(db)
    source_quality_learning.seed_source_reputations(db)

    bp = distributed_ingestion.get_status()
    all_conns = db.query(MarketplaceConnectorModel).all()
    installed_conns = [c for c in all_conns if c.is_installed]
    regions = db.query(RegionNodeModel).all()
    benchmarks = db.query(BenchmarkRunModel).all()
    reputations = db.query(SourceReputationModel).all()
    cache_stats = advanced_cache.get_stats()

    avg_f1 = sum(b.f1_score for b in benchmarks) / len(benchmarks) if benchmarks else 0.94
    gold_sources = len([s for s in reputations if s.tier == "gold"])

    return ScaleOverviewOut(
        total_workers_active=bp.active_workers_count,
        ingestion_backpressure_ratio=bp.ingestion_rate_multiplier,
        marketplace_connectors_count=len(all_conns),
        installed_connectors_count=len(installed_conns),
        active_regions_count=len([r for r in regions if r.status == "healthy"]),
        cache_hit_ratio=cache_stats.overall_hit_ratio,
        total_indices_managed=len(large_scale_search.get_ilm_policies()),
        model_routes_count=len(model_router.get_model_routes()),
        average_benchmark_f1=round(avg_f1, 3),
        gold_tier_sources_count=gold_sources,
    )


# ─── 1. Distributed Ingestion & Backpressure ──────────────────────────────────
@router.get("/ingestion/status", response_model=BackpressureStatus, summary="Get Ingestion Backpressure Status")
def get_ingestion_status() -> BackpressureStatus:
    """Returns active ingestion partitions, worker heartbeats, and rate multipliers."""
    return distributed_ingestion.get_status()


@router.post("/ingestion/backpressure", response_model=BackpressureStatus, summary="Update Ingestion Backpressure")
def update_ingestion_backpressure(req: BackpressureUpdateRequest) -> BackpressureStatus:
    """Manually modifies the ingestion rate multiplier or watermarks for simulation."""
    distributed_ingestion.rate_multiplier = req.target_rate_multiplier
    if req.high_watermark:
        distributed_ingestion.high_watermark = req.high_watermark
    return distributed_ingestion.get_status()


# ─── 2. Connector Marketplace ──────────────────────────────────────────────────
@router.get("/marketplace", response_model=List[MarketplaceConnectorOut], summary="List Marketplace Connectors")
def list_marketplace_connectors(
    category: Optional[str] = Query(default=None),
    installed_only: bool = Query(default=False),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> List[MarketplaceConnectorOut]:
    """Lists community connectors with category and keyword filtering."""
    return connector_marketplace.list_marketplace_connectors(
        db, category=category, installed_only=installed_only, search=search
    )


@router.get("/marketplace/{connector_id}", response_model=MarketplaceConnectorOut, summary="Get Marketplace Connector")
def get_marketplace_connector(connector_id: int, db: Session = Depends(get_db)) -> MarketplaceConnectorOut:
    """Retrieves detailed manifest for a single marketplace connector."""
    conn = connector_marketplace.get_connector_by_id(db, connector_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Marketplace connector not found")
    return conn


@router.post("/marketplace/install/{connector_id}", response_model=MarketplaceConnectorOut, summary="Install Connector")
def install_connector(connector_id: int, db: Session = Depends(get_db)) -> MarketplaceConnectorOut:
    """Installs a community connector into the local runtime."""
    res = connector_marketplace.toggle_install_connector(db, connector_id, install=True)
    if not res:
        raise HTTPException(status_code=404, detail="Marketplace connector not found")
    return res


@router.post("/marketplace/uninstall/{connector_id}", response_model=MarketplaceConnectorOut, summary="Uninstall Connector")
def uninstall_connector(connector_id: int, db: Session = Depends(get_db)) -> MarketplaceConnectorOut:
    """Uninstalls a community connector."""
    res = connector_marketplace.toggle_install_connector(db, connector_id, install=False)
    if not res:
        raise HTTPException(status_code=404, detail="Marketplace connector not found")
    return res


@router.post(
    "/marketplace/publish",
    response_model=MarketplaceConnectorOut,
    status_code=status.HTTP_201_CREATED,
    summary="Publish Community Connector",
)
def publish_community_connector(req: MarketplacePublishRequest, db: Session = Depends(get_db)) -> MarketplaceConnectorOut:
    """Validates manifest and publishes a new community connector to the catalog."""
    try:
        return connector_marketplace.publish_connector(db, req)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ─── 3. Multi-Region Deployment ────────────────────────────────────────────────
@router.get("/multi-region/topology", response_model=List[RegionNodeOut], summary="List Multi-Region Nodes")
def get_multi_region_topology(db: Session = Depends(get_db)) -> List[RegionNodeOut]:
    """Returns regional deployment clusters, replication lag, and health status."""
    return multi_region.list_region_nodes(db)


@router.post("/multi-region/route", response_model=GeoRouteResponse, summary="Resolve Geo-Routing")
def resolve_client_geo_route(req: GeoRouteRequest, db: Session = Depends(get_db)) -> GeoRouteResponse:
    """Resolves optimal datacenter destination based on client IP or preferred region."""
    return multi_region.resolve_geo_route(db, req)


@router.post("/multi-region/failover", response_model=List[RegionNodeOut], summary="Simulate Disaster Recovery Failover")
def trigger_disaster_recovery_failover(req: FailoverRequest, db: Session = Depends(get_db)) -> List[RegionNodeOut]:
    """Executes a regional failover promotion for high availability verification."""
    return multi_region.execute_failover(db, req)


# ─── 4. Advanced Caching ───────────────────────────────────────────────────────
@router.get("/cache/stats", response_model=CacheStatsOut, summary="Get Multi-Tier Cache Telemetry")
def get_cache_telemetry() -> CacheStatsOut:
    """Returns real-time hit ratios, latencies, and stampede prevention metrics."""
    return advanced_cache.get_stats()


@router.post("/cache/invalidate", response_model=CacheInvalidateResponse, summary="Invalidate Cache by Tags")
def invalidate_cache_tags(req: CacheInvalidateRequest) -> CacheInvalidateResponse:
    """Invalidates cached entries across L1 memory and L2 Redis matching specified tags."""
    return advanced_cache.invalidate_by_tags(req.tags)


# ─── 5. Large-Scale Search & ILM ───────────────────────────────────────────────
@router.get("/search/ilm", response_model=List[ILMPolicyOut], summary="Get Index Lifecycle Management Tiers")
def get_search_ilm_policies() -> List[ILMPolicyOut]:
    """Returns time-series Hot/Warm/Cold/Frozen retention and shard allocations."""
    return large_scale_search.get_ilm_policies()


@router.post("/search/federated", response_model=FederatedSearchResponse, summary="Execute Federated Multi-Cluster Search")
def execute_federated_search(req: FederatedSearchRequest) -> FederatedSearchResponse:
    """Broadcasts query to multiple regional search clusters and merges normalized results."""
    return large_scale_search.execute_federated_search(req)


# ─── 6. Advanced Graph Analytics ───────────────────────────────────────────────
@router.get("/graph/centrality", response_model=List[CentralityRankingItem], summary="Get Graph PageRank Centrality")
def get_graph_centrality() -> List[CentralityRankingItem]:
    """Returns top threat actors and vulnerabilities ranked by PageRank centrality."""
    return graph_analytics.get_centrality_rankings()


@router.get("/graph/communities", response_model=List[CommunityClusterItem], summary="Get Graph Community Clusters")
def get_graph_communities() -> List[CommunityClusterItem]:
    """Returns cohesive threat communities detected through modularity partitioning."""
    return graph_analytics.get_community_clusters()


@router.post("/graph/blast-radius", response_model=BlastRadiusResponse, summary="Calculate Entity Blast Radius")
def calculate_blast_radius(req: BlastRadiusRequest) -> BlastRadiusResponse:
    """Calculates multi-hop downstream impact and breach paths from a target asset."""
    return graph_analytics.calculate_blast_radius(req)


# ─── 7. Model Routing ──────────────────────────────────────────────────────────
@router.get("/models/routes", response_model=List[ModelRouteConfig], summary="Get Model Gateway Routes")
def get_model_routes() -> List[ModelRouteConfig]:
    """Returns configured model routes, circuit breakers, and SLA cost/latency limits."""
    return model_router.get_model_routes()


@router.post("/models/route-query", response_model=ModelRouteResponse, summary="Route Query Through Model Gateway")
def route_model_query(req: ModelRouteRequest) -> ModelRouteResponse:
    """Evaluates task type, SLA constraints, and circuit breakers to route inference."""
    return model_router.route_query(req)


# ─── 8. Automated Evaluation ───────────────────────────────────────────────────
@router.get("/evaluation/benchmarks", response_model=List[BenchmarkRunOut], summary="List Evaluation Benchmarks")
def list_evaluation_benchmarks(db: Session = Depends(get_db)) -> List[BenchmarkRunOut]:
    """Returns historical precision, recall, F1, and drift benchmark runs."""
    return auto_evaluation.list_benchmark_runs(db)


@router.post(
    "/evaluation/run",
    response_model=BenchmarkRunOut,
    status_code=status.HTTP_201_CREATED,
    summary="Trigger Automated Pipeline Benchmark",
)
def trigger_evaluation_benchmark(req: EvaluationTriggerRequest, db: Session = Depends(get_db)) -> BenchmarkRunOut:
    """Executes an automated evaluation run on a golden test dataset."""
    return auto_evaluation.run_evaluation_suite(db, req)


# ─── 9. Source Quality Learning ────────────────────────────────────────────────
@router.get("/quality/reputation", response_model=List[SourceReputationOut], summary="List Bayesian Source Reputations")
def list_source_reputations(db: Session = Depends(get_db)) -> List[SourceReputationOut]:
    """Lists sources ranked by dynamic Bayesian credibility score and quality tier."""
    return source_quality_learning.list_source_reputations(db)


@router.post("/quality/reputation/feedback", response_model=SourceReputationOut, summary="Submit Corroboration Feedback")
def submit_source_feedback(req: ReputationUpdateRequest, db: Session = Depends(get_db)) -> SourceReputationOut:
    """Submits corroboration feedback to continuously update a source's Bayesian reputation."""
    return source_quality_learning.update_source_reputation(db, req)
