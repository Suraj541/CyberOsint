"""
Notification Service Data Models and Enums
Conforms strictly to IMPLEMENT.md Section 33 (Step 32: Build Notifications).
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NotificationChannel(str, Enum):
    """Supported notification dispatch channels."""

    WEB = "web"
    EMAIL = "email"
    PUSH = "push"
    WEBHOOK = "webhook"


class ImportanceLevel(str, Enum):
    """Categorical importance levels for alert classification."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NotificationStatus(str, Enum):
    """Delivery and lifecycle status of a notification."""

    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class ImportanceScoreResult(BaseModel):
    """Calculated importance score and breakdown factors."""

    score: float = Field(..., ge=0.0, le=1.0, description="Composite importance score between 0.0 and 1.0")
    level: ImportanceLevel
    factors: Dict[str, float] = Field(default_factory=dict)
    exceeds_threshold: bool
    threshold_used: float
    reason: str


class NotificationDTO(BaseModel):
    """Data transfer object for a stored notification."""

    id: int
    user_id: Optional[int] = None
    session_id: str
    watchlist_id: Optional[int] = None
    watchlist_name: Optional[str] = None
    content_id: Optional[int] = None
    content_title: Optional[str] = None
    content_url: Optional[str] = None
    title: str
    body: str
    summary: Optional[str] = None
    importance_score: float
    importance_level: str
    channel: str
    status: str
    is_read: bool = False
    read_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class NotificationCreateDTO(BaseModel):
    """Payload for creating a new notification."""

    session_id: str
    user_id: Optional[int] = None
    watchlist_id: Optional[int] = None
    watchlist_name: Optional[str] = None
    content_id: Optional[int] = None
    content_title: Optional[str] = None
    content_url: Optional[str] = None
    title: str = Field(..., min_length=1, max_length=255)
    body: str
    summary: Optional[str] = None
    importance_score: float = Field(..., ge=0.0, le=1.0)
    importance_level: str
    channel: NotificationChannel = NotificationChannel.WEB
    status: NotificationStatus = NotificationStatus.PENDING
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NotificationChannelConfigDTO(BaseModel):
    """Configuration for user notification destinations and channel thresholds."""

    id: Optional[int] = None
    session_id: str
    channel_type: NotificationChannel
    destination: Optional[str] = None  # email address, push endpoint, or webhook URL
    is_enabled: bool = True
    min_importance_threshold: float = Field(0.50, ge=0.0, le=1.0)
    secret_token: Optional[str] = None  # for webhook HMAC signature
    description: Optional[str] = None


class WebhookPayloadDTO(BaseModel):
    """Standardized JSON payload dispatched to external webhook endpoints."""

    event: str = "security.alert"
    notification_id: int
    importance_level: str
    importance_score: float
    timestamp: str
    title: str
    summary: str
    content_url: Optional[str] = None
    matched_watchlist: Optional[str] = None
    matched_items: List[Dict[str, Any]] = Field(default_factory=list)
    signature: Optional[str] = None


class NotificationPipelineResult(BaseModel):
    """Complete execution output of the 5-stage notification pipeline."""

    content_id: Optional[int] = None
    content_title: str
    matched_watchlists_count: int = 0
    matched_items_count: int = 0
    matched_watchlists: List[Dict[str, Any]] = Field(default_factory=list)
    importance: ImportanceScoreResult
    notifications_created: List[NotificationDTO] = Field(default_factory=list)
    dispatch_results: List[Dict[str, Any]] = Field(default_factory=list)
    status: str = "completed"  # completed, suppressed_below_threshold, no_match
