"""
Watchlist Service Data Models and Enums
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WatchlistItemType(str, Enum):
    """The 10 mandated cybersecurity watchlist item types."""

    CVE = "cve"
    PRODUCT = "product"
    VENDOR = "vendor"
    THREAT_ACTOR = "threat_actor"
    MALWARE = "malware"
    TECHNOLOGY = "technology"
    TOPIC = "topic"
    RESEARCHER = "researcher"
    TOOL = "tool"
    KEYWORD = "keyword"


class WatchlistItemCreateDTO(BaseModel):
    """Schema for adding an item to a watchlist."""

    item_type: WatchlistItemType
    item_value: str = Field(..., min_length=1, max_length=255)
    severity_threshold: Optional[str] = Field(None, description="Optional minimum severity: CRITICAL, HIGH, MEDIUM, LOW")
    notify_on_match: bool = True


class WatchlistItemDTO(BaseModel):
    """Data transfer object for a watched target item."""

    id: int
    watchlist_id: int
    item_type: str
    item_value: str
    severity_threshold: Optional[str] = None
    notify_on_match: bool = True
    created_at: Optional[str] = None


class WatchlistCreateDTO(BaseModel):
    """Schema for creating a new watchlist."""

    session_id: str
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    notification_channel: str = "in_app"
    items: List[WatchlistItemCreateDTO] = Field(default_factory=list)


class WatchlistUpdateDTO(BaseModel):
    """Schema for updating watchlist attributes."""

    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = None
    is_active: Optional[bool] = None
    notification_channel: Optional[str] = None


class WatchlistDTO(BaseModel):
    """Data transfer object representing a full watchlist with items."""

    id: int
    session_id: str
    user_id: Optional[int] = None
    name: str
    description: Optional[str] = None
    is_active: bool = True
    notification_channel: str = "in_app"
    item_count: int = 0
    items: List[WatchlistItemDTO] = Field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class MatchedWatchlistItem(BaseModel):
    """Describes a specific watchlist item hit."""

    watchlist_id: int
    watchlist_name: str
    item_id: int
    item_type: str
    item_value: str
    matched_field: str
    matched_text: str


class MatchedContentItem(BaseModel):
    """A content record that matched one or more watched targets."""

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
    matched_items: List[MatchedWatchlistItem] = Field(default_factory=list)
    match_score: float = 1.0


class WatchlistFeedResponse(BaseModel):
    """Feed of intelligence matching a specific watchlist."""

    watchlist_id: int
    watchlist_name: str
    total_matches: int
    items: List[MatchedContentItem]
