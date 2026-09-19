"""Section 48 (Step 47): Version 3 Advanced Intelligence Endpoints.

Provides unified REST APIs for:
  - Threat Actor Tracking
  - Malware Tracking
  - Campaign Tracking
  - Incident Timelines
  - Cross-Source Correlation
  - Cybersecurity Learning Paths
  - AI Research Assistant Dossier Generation
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.intelligence import (
    CampaignModel,
    CorrelationClusterModel,
    IncidentTimelineModel,
    LearningPathModel,
    MalwareFamilyModel,
    ThreatActorModel,
)
from app.schemas.intelligence import (
    CampaignCreate,
    CampaignOut,
    CorrelationClusterOut,
    IncidentTimelineCreate,
    IncidentTimelineOut,
    IntelligenceOverviewOut,
    LearningPathOut,
    MalwareFamilyCreate,
    MalwareFamilyOut,
    ResearchAssistantDossier,
    ResearchAssistantRequest,
    ThreatActorCreate,
    ThreatActorOut,
)
from services.intelligence import (
    campaign_service,
    correlation_engine,
    learning_service,
    malware_service,
    research_assistant_engine,
    threat_actor_service,
    timeline_engine,
)

router = APIRouter(prefix="/intelligence", tags=["Intelligence"])


# ─── Overview ──────────────────────────────────────────────────────────────────
@router.get(
    "/overview",
    response_model=IntelligenceOverviewOut,
    summary="Get Version 3 Advanced Intelligence Overview",
)
def get_intelligence_overview(db: Session = Depends(get_db)) -> IntelligenceOverviewOut:
    """Returns high-level statistics across actors, malware, campaigns, and timelines."""
    threat_actor_service.seed_initial_actors(db)
    malware_service.seed_initial_malware(db)
    campaign_service.seed_initial_campaigns(db)
    timeline_engine.seed_initial_timelines(db)
    correlation_engine.seed_initial_clusters(db)
    learning_service.seed_initial_paths(db)

    actors = db.query(ThreatActorModel).all()
    malware = db.query(MalwareFamilyModel).all()
    campaigns = db.query(CampaignModel).all()
    timelines = db.query(IncidentTimelineModel).all()
    clusters = db.query(CorrelationClusterModel).all()
    paths = db.query(LearningPathModel).all()

    active_actors = [a for a in actors if a.status == "active"]
    active_campaigns = [c for c in campaigns if c.status == "active"]

    return IntelligenceOverviewOut(
        total_threat_actors=len(actors),
        active_threat_actors=len(active_actors),
        total_malware_families=len(malware),
        active_campaigns=len(active_campaigns),
        incident_timelines_count=len(timelines),
        correlated_clusters_count=len(clusters),
        learning_paths_count=len(paths),
        top_threat_actors=actors[:5],
        recent_campaigns=campaigns[:5],
    )


# ─── Threat Actors ─────────────────────────────────────────────────────────────
@router.get("/actors", response_model=List[ThreatActorOut], summary="List Threat Actors")
def list_threat_actors(
    status: Optional[str] = Query(default=None, description="Filter by status (active, dormant)"),
    country: Optional[str] = Query(default=None, description="Filter by country (RU, KP, CN)"),
    search: Optional[str] = Query(default=None, description="Search by name, alias, or malware"),
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[ThreatActorOut]:
    """Lists tracked threat actors with multi-field filtering."""
    return threat_actor_service.list_actors(db, status=status, country=country, search=search, limit=limit, skip=skip)


@router.get("/actors/{actor_id}", response_model=ThreatActorOut, summary="Get Threat Actor")
def get_threat_actor(actor_id: int, db: Session = Depends(get_db)) -> ThreatActorOut:
    """Retrieves detailed profile for a specific threat actor."""
    actor = threat_actor_service.get_actor_by_id(db, actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    return actor


@router.post("/actors", response_model=ThreatActorOut, status_code=status.HTTP_201_CREATED, summary="Create Threat Actor")
def create_threat_actor(data: ThreatActorCreate, db: Session = Depends(get_db)) -> ThreatActorOut:
    """Registers a new threat actor profile."""
    return threat_actor_service.create_actor(db, data)


# ─── Malware Tracking ──────────────────────────────────────────────────────────
@router.get("/malware", response_model=List[MalwareFamilyOut], summary="List Malware Families")
def list_malware_families(
    malware_type: Optional[str] = Query(default=None, description="Filter by type (ransomware, infostealer, c2)"),
    platform: Optional[str] = Query(default=None, description="Filter by platform (Windows, Linux)"),
    search: Optional[str] = Query(default=None, description="Keyword search"),
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[MalwareFamilyOut]:
    """Lists cataloged malware families."""
    return malware_service.list_malware(db, malware_type=malware_type, platform=platform, search=search, limit=limit, skip=skip)


@router.get("/malware/{malware_id}", response_model=MalwareFamilyOut, summary="Get Malware Family")
def get_malware_family(malware_id: int, db: Session = Depends(get_db)) -> MalwareFamilyOut:
    """Retrieves malware family details including YARA rules and sample hashes."""
    fam = malware_service.get_malware_by_id(db, malware_id)
    if not fam:
        raise HTTPException(status_code=404, detail="Malware family not found")
    return fam


@router.post("/malware", response_model=MalwareFamilyOut, status_code=status.HTTP_201_CREATED, summary="Create Malware Family")
def create_malware_family(data: MalwareFamilyCreate, db: Session = Depends(get_db)) -> MalwareFamilyOut:
    """Registers a new malware family profile."""
    return malware_service.create_malware(db, data)


# ─── Campaigns ─────────────────────────────────────────────────────────────────
@router.get("/campaigns", response_model=List[CampaignOut], summary="List Threat Campaigns")
def list_campaigns(
    status: Optional[str] = Query(default=None, description="Filter by status (active, historical)"),
    actor: Optional[str] = Query(default=None, description="Filter by threat actor"),
    search: Optional[str] = Query(default=None, description="Keyword search"),
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[CampaignOut]:
    """Lists active and historical threat campaigns."""
    return campaign_service.list_campaigns(db, status=status, actor_name=actor, search=search, limit=limit, skip=skip)


@router.get("/campaigns/{campaign_id}", response_model=CampaignOut, summary="Get Campaign Detail")
def get_campaign(campaign_id: int, db: Session = Depends(get_db)) -> CampaignOut:
    """Retrieves details of a threat campaign."""
    camp = campaign_service.get_campaign_by_id(db, campaign_id)
    if not camp:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return camp


@router.post("/campaigns", response_model=CampaignOut, status_code=status.HTTP_201_CREATED, summary="Create Campaign")
def create_campaign(data: CampaignCreate, db: Session = Depends(get_db)) -> CampaignOut:
    """Registers a new threat campaign."""
    return campaign_service.create_campaign(db, data)


# ─── Incident Timelines ────────────────────────────────────────────────────────
@router.get("/timelines", response_model=List[IncidentTimelineOut], summary="List Incident Timelines")
def list_incident_timelines(
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[IncidentTimelineOut]:
    """Lists reconstructed incident timelines."""
    return timeline_engine.list_timelines(db, limit=limit, skip=skip)


@router.get("/timelines/{timeline_id}", response_model=IncidentTimelineOut, summary="Get Incident Timeline")
def get_incident_timeline(timeline_id: int, db: Session = Depends(get_db)) -> IncidentTimelineOut:
    """Retrieves milestone events for an incident timeline."""
    tl = timeline_engine.get_timeline_by_id(db, timeline_id)
    if not tl:
        raise HTTPException(status_code=404, detail="Incident timeline not found")
    return tl


@router.post("/timelines", response_model=IncidentTimelineOut, status_code=status.HTTP_201_CREATED, summary="Create Timeline")
def create_incident_timeline(data: IncidentTimelineCreate, db: Session = Depends(get_db)) -> IncidentTimelineOut:
    """Creates a new incident timeline with ordered milestones."""
    return timeline_engine.create_timeline(db, data)


# ─── Cross-Source Correlation ──────────────────────────────────────────────────
@router.get("/correlations", response_model=List[CorrelationClusterOut], summary="List Correlation Clusters")
def list_correlation_clusters(
    cve: Optional[str] = Query(default=None, description="Filter by CVE"),
    actor: Optional[str] = Query(default=None, description="Filter by Actor"),
    limit: int = Query(default=50, ge=1, le=100),
    skip: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[CorrelationClusterOut]:
    """Lists multi-source convergence clusters linking disparate feeds."""
    if cve or actor:
        return correlation_engine.correlate_entities(db, cve_id=cve, actor_name=actor)
    return correlation_engine.list_clusters(db, limit=limit, skip=skip)


@router.get("/correlations/{cluster_id}", response_model=CorrelationClusterOut, summary="Get Correlation Cluster")
def get_correlation_cluster(cluster_id: int, db: Session = Depends(get_db)) -> CorrelationClusterOut:
    """Retrieves a correlation cluster by ID."""
    cluster = correlation_engine.get_cluster_by_id(db, cluster_id)
    if not cluster:
        raise HTTPException(status_code=404, detail="Correlation cluster not found")
    return cluster


# ─── Learning Paths ────────────────────────────────────────────────────────────
@router.get("/learning/paths", response_model=List[LearningPathOut], summary="List Learning Paths")
def list_learning_paths(
    difficulty: Optional[str] = Query(default=None, description="Filter by difficulty (beginner, intermediate, advanced)"),
    role: Optional[str] = Query(default=None, description="Filter by career role"),
    db: Session = Depends(get_db),
) -> List[LearningPathOut]:
    """Lists structured cybersecurity curricula and learning pathways."""
    return learning_service.list_paths(db, difficulty=difficulty, role=role)


@router.get("/learning/paths/{slug}", response_model=LearningPathOut, summary="Get Learning Path")
def get_learning_path(slug: str, db: Session = Depends(get_db)) -> LearningPathOut:
    """Retrieves a learning pathway by unique slug."""
    path = learning_service.get_path_by_slug(db, slug)
    if not path:
        raise HTTPException(status_code=404, detail="Learning path not found")
    return path


# ─── AI Research Assistant ─────────────────────────────────────────────────────
@router.post(
    "/assistant/investigate",
    response_model=ResearchAssistantDossier,
    summary="Investigate with AI Research Assistant",
)
def investigate_query(
    request: ResearchAssistantRequest,
    db: Session = Depends(get_db),
) -> ResearchAssistantDossier:
    """Executes a 4-stage agentic OSINT research investigation and generates a cited dossier."""
    return research_assistant_engine.investigate(db, request)
