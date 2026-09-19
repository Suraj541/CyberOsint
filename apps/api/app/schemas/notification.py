"""
Pydantic Schemas for Notification REST API
Conforms strictly to IMPLEMENT.md Section 33 (Step 32: Build Notifications).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NotificationResponse(BaseModel):
    """Schema for returning a notification alert."""

    id: int
    session_id: str
    user_id: Optional[int] = None
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


class NotificationCreateRequest(BaseModel):
    """Schema for creating a manual notification alert."""

    session_id: str = Field("guest_analyst_session", description="Analyst session ID")
    watchlist_id: Optional[int] = None
    content_id: Optional[int] = None
    title: str = Field(..., min_length=1, max_length=255)
    body: str
    summary: Optional[str] = None
    importance_score: float = Field(0.5, ge=0.0, le=1.0)
    importance_level: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    channel: str = Field("web", description="web, email, push, webhook")


class NotificationChannelConfigRequest(BaseModel):
    """Schema for updating or creating a notification channel destination and threshold."""

    session_id: str = Field("guest_analyst_session")
    channel_type: str = Field(..., description="web, email, push, webhook")
    destination: Optional[str] = Field(None, description="Destination URL, email, or endpoint")
    is_enabled: bool = True
    min_importance_threshold: float = Field(0.50, ge=0.0, le=1.0, description="Minimum importance to dispatch")
    secret_token: Optional[str] = Field(None, description="Secret token for HMAC signing")
    description: Optional[str] = None


class NotificationChannelConfigResponse(BaseModel):
    """Schema for returning channel destination configuration."""

    id: Optional[int] = None
    session_id: str
    channel_type: str
    destination: Optional[str] = None
    is_enabled: bool
    min_importance_threshold: float
    secret_token: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class NotificationSummaryResponse(BaseModel):
    """Schema for aggregate telemetry across all notifications."""

    total_count: int
    unread_count: int
    critical_count: int
    high_count: int
    by_channel: Dict[str, int] = Field(default_factory=dict)
    by_level: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)


class NotificationPipelineRunRequest(BaseModel):
    """Schema for triggering the 5-stage notification pipeline on content."""

    session_id: Optional[str] = None
    content_id: Optional[int] = None
    content_payload: Optional[Dict[str, Any]] = None
    force_dispatch: bool = False
    threshold_override: Optional[float] = None


class NotificationChannelTestRequest(BaseModel):
    """Schema for test dispatching a notification to a destination."""

    channel: str = Field("webhook", description="web, email, push, webhook")
    destination: Optional[str] = None
    secret_token: Optional[str] = None
