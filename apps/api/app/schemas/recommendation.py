"""
Pydantic Schemas for Recommendation API Endpoints
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class InteractionCreateRequest(BaseModel):
    """Schema for recording a user telemetry/interaction event."""

    session_id: str = Field(..., description="Browser or client session identifier")
    interaction_type: str = Field(..., description="Event type: view, save, unsave, search, click")
    content_id: Optional[int] = Field(None, description="Target content ID (if applicable)")
    search_query: Optional[str] = Field(None, description="Search query string (if applicable)")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context telemetry")


class UserProfileUpdateRequest(BaseModel):
    """Schema for updating user recommendation settings and skill level."""

    session_id: str = Field(..., description="Session identifier")
    interests: Optional[List[str]] = Field(None, description="List of cybersecurity interest topics")
    difficulty_level: Optional[str] = Field(None, description="beginner, intermediate, advanced, expert")
    preferred_types: Optional[List[str]] = Field(None, description="Preferred content types")


class UserProfileResponse(BaseModel):
    """Schema for user profile state and engagement statistics."""

    session_id: str
    user_id: Optional[int] = None
    interests: List[str] = Field(default_factory=list)
    difficulty_level: str
    preferred_types: List[str] = Field(default_factory=list)
    saved_count: int = 0
    viewed_count: int = 0
    search_count: int = 0


class RecommendationItemSchema(BaseModel):
    """Individual recommended intelligence item."""

    content_id: int
    title: str
    description: Optional[str] = None
    summary: Optional[str] = None
    canonical_url: str
    content_type: str
    category: Optional[str] = None
    difficulty_level: str
    score: float
    match_reasons: List[str] = Field(default_factory=list)
    source: str
    author: Optional[str] = None
    published_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    is_saved: bool = False
    source_quality_tier: Optional[str] = None
    source_quality_score: Optional[float] = None


class TopicRecommendationSchema(BaseModel):
    """Semantic topic recommendation schema."""

    topic: str
    score: float
    reason: str
    related_from: Optional[str] = None


class RecommendationsListResponse(BaseModel):
    """Personalized recommendations response with items and topic expansions."""

    items: List[RecommendationItemSchema]
    suggested_topics: List[TopicRecommendationSchema]
    profile_summary: UserProfileResponse
    total_matched: int
