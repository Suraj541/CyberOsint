"""
Dashboard API Endpoint
Provides real database aggregated intelligence for the central command dashboard.
Conforms strictly to IMPLEMENT.md Section 21:
- Latest News
- Critical Vulnerabilities
- New Research
- Trending Topics
- New Tools
- Latest Videos
- Threat Intelligence
"""

from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from app.schemas.dashboard import DashboardResponse, DashboardStats, TrendingTopic

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get(
    "",
    response_model=DashboardResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Consolidated Dashboard Intelligence",
)
def get_dashboard_data(
    limit: int = Query(default=6, ge=1, le=20, description="Items per component"),
    db: Session = Depends(get_db),
) -> DashboardResponse:
    """
    Retrieve real database records for all 7 Section 21 dashboard components.
    Ensures zero hardcoded mock data is returned once data exists in the database.
    """
    # 1. Real Database Aggregate Metrics
    total_content = db.query(func.count(Content.id)).scalar() or 0
    active_sources = db.query(func.count(Source.id)).filter(Source.active == True).scalar() or 0
    tracked_cves = db.query(func.count(Content.id)).filter(Content.content_type == "cve").scalar() or 0
    threat_advisories = db.query(func.count(Content.id)).filter(Content.content_type == "advisory").scalar() or 0
    total_entities = db.query(func.count(Entity.id)).scalar() or 0

    metrics = DashboardStats(
        total_content=total_content,
        active_sources=active_sources,
        tracked_cves=tracked_cves,
        threat_advisories=threat_advisories,
        total_entities=total_entities,
        system_health="healthy" if active_sources > 0 or total_content > 0 else "standby",
        last_updated=datetime.now(timezone.utc),
    )

    # 2. Component 1: Latest News (articles & general advisories)
    latest_news = (
        db.query(Content)
        .filter(Content.content_type.in_(["article", "advisory"]))
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    # 3. Component 2: Critical Vulnerabilities (CVE intelligence)
    critical_vulnerabilities = (
        db.query(Content)
        .filter(Content.content_type == "cve")
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    # 4. Component 3: New Research (whitepapers, exploit research, academic papers)
    new_research = (
        db.query(Content)
        .filter(Content.content_type.in_(["paper", "research"]))
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    # 5. Component 4: Trending Topics (most frequently linked entities in ContentEntity)
    trending_topics: List[TrendingTopic] = []
    entity_counts = (
        db.query(
            Entity.name,
            Entity.entity_type,
            func.count(ContentEntity.id).label("mention_count"),
            func.avg(ContentEntity.confidence).label("avg_conf"),
        )
        .join(ContentEntity, Entity.id == ContentEntity.entity_id)
        .group_by(Entity.name, Entity.entity_type)
        .order_by(func.count(ContentEntity.id).desc())
        .limit(8)
        .all()
    )

    for row in entity_counts:
        trending_topics.append(
            TrendingTopic(
                name=row[0],
                entity_type=row[1],
                mention_count=row[2],
                confidence=float(row[3] or 1.0),
            )
        )

    # 6. Component 5: New Tools (security tools, GitHub repos, exploits)
    new_tools = (
        db.query(Content)
        .filter(Content.content_type == "tool")
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    # 7. Component 6: Latest Videos (conference talks, webinars, recordings)
    latest_videos = (
        db.query(Content)
        .filter(Content.content_type == "video")
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    # 8. Component 7: Threat Intelligence (APT actors, campaigns, advisories)
    threat_intelligence = (
        db.query(Content)
        .filter(Content.content_type.in_(["article", "advisory", "report"]))
        .order_by(Content.published_at.desc().nullslast(), Content.created_at.desc())
        .limit(limit)
        .all()
    )

    return DashboardResponse(
        metrics=metrics,
        latest_news=latest_news,
        critical_vulnerabilities=critical_vulnerabilities,
        new_research=new_research,
        trending_topics=trending_topics,
        new_tools=new_tools,
        latest_videos=latest_videos,
        threat_intelligence=threat_intelligence,
    )
