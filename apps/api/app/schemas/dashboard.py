"""
Dashboard Pydantic Schemas
Defines request and response schemas for Section 21 / Step 20 Dashboard.
Conforms strictly to IMPLEMENT.md Section 21.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.content import ContentResponse


class DashboardStats(BaseModel):
    """Real-time system telemetry and database aggregate metrics."""
    total_content: int = Field(default=0, description="Total normalized content records in database")
    active_sources: int = Field(default=0, description="Total active feed and connector sources")
    tracked_cves: int = Field(default=0, description="Total CVE vulnerability items tracked")
    threat_advisories: int = Field(default=0, description="Total high/critical security advisories")
    total_entities: int = Field(default=0, description="Total extracted entity records")
    system_health: str = Field(default="healthy", description="Operational health status")
    last_updated: datetime = Field(default_factory=datetime.utcnow)


class TrendingTopic(BaseModel):
    """Trending security topic derived from extracted entity frequency."""
    name: str = Field(..., description="Entity or topic name")
    entity_type: str = Field(..., description="Entity classification (cve, threat_actor, malware, tool)")
    mention_count: int = Field(default=1, description="Number of content items linking to this entity")
    confidence: float = Field(default=1.0, description="Average extraction confidence")


class DashboardResponse(BaseModel):
    """
    Consolidated real-database dashboard response conforming to IMPLEMENT.md Section 21:
    - Latest News
    - Critical Vulnerabilities
    - New Research
    - Trending Topics
    - New Tools
    - Latest Videos
    - Threat Intelligence
    """
    metrics: DashboardStats
    latest_news: List[ContentResponse] = Field(default_factory=list)
    critical_vulnerabilities: List[ContentResponse] = Field(default_factory=list)
    new_research: List[ContentResponse] = Field(default_factory=list)
    trending_topics: List[TrendingTopic] = Field(default_factory=list)
    new_tools: List[ContentResponse] = Field(default_factory=list)
    latest_videos: List[ContentResponse] = Field(default_factory=list)
    threat_intelligence: List[ContentResponse] = Field(default_factory=list)
