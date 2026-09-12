"""
Pydantic Schemas for Watchlist REST API
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WatchlistItemCreateRequest(BaseModel):
    """Schema for adding an item to a watchlist."""

    item_type: str = Field(..., description="cve, product, vendor, threat_actor, malware, technology, topic, researcher, tool, keyword")
    item_value: str = Field(..., min_length=1, max_length=255, description="Target value to match")
    severity_threshold: Optional[str] = Field(None, description="Optional minimum severity: CRITICAL, HIGH, MEDIUM, LOW")
    notify_on_match: bool = Field(True, description="Whether to trigger alerts upon matching")


class WatchlistCreateRequest(BaseModel):
    """Schema for creating a new watchlist."""

    session_id: str = Field("guest_analyst_session", description="Analyst session identifier")
    name: str = Field(..., min_length=1, max_length=120, description="Descriptive name of the watchlist")
    description: Optional[str] = Field(None, description="Detailed explanation of the surveillance scope")
    notification_channel: str = Field("in_app", description="in_app, email, or webhook")
    items: List[WatchlistItemCreateRequest] = Field(default_factory=list, description="Initial watched targets")


class WatchlistUpdateRequest(BaseModel):
    """Schema for updating watchlist attributes."""

    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    notification_channel: Optional[str] = None


class WatchlistItemResponse(BaseModel):
    """Schema for an individual watched item."""

    id: int
    watchlist_id: int
    item_type: str
    item_value: str
    severity_threshold: Optional[str] = None
    notify_on_match: bool = True
    created_at: Optional[str] = None


class WatchlistResponse(BaseModel):
    """Schema for a watchlist with its item list."""

    id: int
    session_id: str
    user_id: Optional[int] = None
    name: str
    description: Optional[str] = None
    is_active: bool = True
    notification_channel: str = "in_app"
    item_count: int = 0
    items: List[WatchlistItemResponse] = Field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class MatchedWatchlistItemResponse(BaseModel):
    """Details of a matched watchlist target."""

    watchlist_id: int
    watchlist_name: str
    item_id: int
    item_type: str
    item_value: str
    matched_field: str
    matched_text: str


class MatchedContentItemResponse(BaseModel):
    """Content item that satisfied one or more watchlist criteria."""

    content_id: int
    title: str
    description: Optional[str] = None
    summary: Optional[str] = None
    canonical_url: str
    content_type: str
    source: str
    published_at: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    matched_items: List[MatchedWatchlistItemResponse] = Field(default_factory=list)
    match_score: float = 1.0


class WatchlistFeedResponse(BaseModel):
    """Feed of intelligence items matching a specific watchlist."""

    watchlist_id: int
    watchlist_name: str
    total_matches: int
    items: List[MatchedContentItemResponse]


class WatchlistMatchTestRequest(BaseModel):
    """Diagnostic request testing content text/entities against active watchlists."""

    title: str
    description: Optional[str] = None
    summary: Optional[str] = None
    content_type: str = "article"
    source: str = "Test Source"
    severity: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
