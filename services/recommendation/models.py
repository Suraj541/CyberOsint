"""
Recommendation Service Data Models and Enums
Defines transfer objects for recommendation scoring, topic mapping, and feed filtering.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DifficultyLevel(str, Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


class ContentTypeFilter(str, Enum):
    ALL = "all"
    ARTICLE = "article"
    VIDEO = "video"
    RESEARCH = "research"
    TOOL = "tool"
    COURSE = "course"
    DOCUMENT = "document"


class RecommendationItem(BaseModel):
    """An individual recommended intelligence artifact with ranking score and explanation."""

    content_id: int
    title: str
    description: Optional[str] = None
    summary: Optional[str] = None
    canonical_url: str
    content_type: str  # article, video, research, tool, course, document, advisory, cve
    category: Optional[str] = None
    difficulty_level: str = DifficultyLevel.INTERMEDIATE.value
    score: float = Field(..., ge=0.0, description="Composite recommendation relevance score")
    match_reasons: List[str] = Field(default_factory=list, description="Human-readable justification chips")
    source: str
    author: Optional[str] = None
    published_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    is_saved: bool = False
    source_quality_tier: Optional[str] = None
    source_quality_score: Optional[float] = None


class TopicRecommendation(BaseModel):
    """Semantic topic recommendation derived from knowledge correlations."""

    topic: str
    score: float
    reason: str
    related_from: Optional[str] = None


class UserProfileDTO(BaseModel):
    """User profile data transfer object."""

    session_id: str
    user_id: Optional[int] = None
    interests: List[str] = Field(default_factory=list)
    difficulty_level: str = DifficultyLevel.INTERMEDIATE.value
    preferred_types: List[str] = Field(default_factory=list)
    saved_count: int = 0
    viewed_count: int = 0
    search_count: int = 0


class PersonalizedFeedResponse(BaseModel):
    """Unified response containing recommended content items and semantic topic recommendations."""

    items: List[RecommendationItem]
    suggested_topics: List[TopicRecommendation]
    profile_summary: UserProfileDTO
    total_matched: int
