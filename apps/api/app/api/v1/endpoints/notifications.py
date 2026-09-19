"""
Notifications & Alerting REST API Endpoints
Conforms strictly to IMPLEMENT.md Section 33 (Step 32: Build Notifications).
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.content import Content
from app.schemas.notification import (
    NotificationChannelConfigRequest,
    NotificationChannelConfigResponse,
    NotificationChannelTestRequest,
    NotificationPipelineRunRequest,
    NotificationResponse,
    NotificationSummaryResponse,
)
from services.notification import (
    NotificationChannel,
    NotificationChannelConfigDTO,
    notification_pipeline,
    notification_service,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=List[NotificationResponse])
def list_notifications(
    session_id: Optional[str] = Query(None, description="Filter by analyst session ID"),
    channel: Optional[str] = Query(None, description="Filter by channel: web, email, push, webhook"),
    importance: Optional[str] = Query(None, description="Filter by importance level: CRITICAL, HIGH, MEDIUM, LOW"),
    is_read: Optional[bool] = Query(None, description="Filter by read status"),
    watchlist_id: Optional[int] = Query(None, description="Filter by matched watchlist ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """
    Lists intelligence alert notifications with multi-attribute filtering and pagination.
    """
    try:
        dtos = notification_service.list_notifications(
            db=db,
            session_id=session_id,
            channel=channel,
            importance_level=importance,
            is_read=is_read,
            watchlist_id=watchlist_id,
            limit=limit,
            offset=offset,
        )
        return [NotificationResponse(**d.model_dump()) for d in dtos]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve notifications: {str(e)}",
        )


@router.get("/summary", response_model=NotificationSummaryResponse)
def get_notification_summary(
    session_id: Optional[str] = Query(None, description="Filter by session ID"),
    db: Session = Depends(get_db),
):
    """
    Returns aggregate telemetry metrics across all alerts (unread, critical, channels, levels).
    """
    try:
        data = notification_service.get_summary(db=db, session_id=session_id)
        return NotificationSummaryResponse(**data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to calculate notification summary: {str(e)}",
        )


@router.get("/channels", response_model=List[NotificationChannelConfigResponse])
def list_channel_configs(
    session_id: str = Query("guest_analyst_session", description="Analyst session ID"),
    db: Session = Depends(get_db),
):
    """
    Lists configured dispatch channels (Web, Email, Push, Webhook) and importance thresholds.
    """
    try:
        configs = notification_service.list_channel_configs(db=db, session_id=session_id)
        return [
            NotificationChannelConfigResponse(
                id=c.id,
                session_id=c.session_id,
                channel_type=c.channel_type.value,
                destination=c.destination,
                is_enabled=c.is_enabled,
                min_importance_threshold=c.min_importance_threshold,
                secret_token=c.secret_token,
                description=c.description,
            )
            for c in configs
        ]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve channel configurations: {str(e)}",
        )


@router.post("/channels", response_model=NotificationChannelConfigResponse)
def save_channel_config(
    payload: NotificationChannelConfigRequest,
    db: Session = Depends(get_db),
):
    """
    Creates or updates a channel destination and minimum importance threshold to prevent alert fatigue.
    """
    try:
        c_enum = NotificationChannel(payload.channel_type.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid channel_type '{payload.channel_type}'. Must be one of: web, email, push, webhook",
        )

    dto = NotificationChannelConfigDTO(
        session_id=payload.session_id,
        channel_type=c_enum,
        destination=payload.destination,
        is_enabled=payload.is_enabled,
        min_importance_threshold=payload.min_importance_threshold,
        secret_token=payload.secret_token,
        description=payload.description,
    )
    try:
        res = notification_service.save_channel_config(db=db, dto=dto)
        return NotificationChannelConfigResponse(
            id=res.id,
            session_id=res.session_id,
            channel_type=res.channel_type.value,
            destination=res.destination,
            is_enabled=res.is_enabled,
            min_importance_threshold=res.min_importance_threshold,
            secret_token=res.secret_token,
            description=res.description,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save channel configuration: {str(e)}",
        )


@router.post("/channels/test")
def test_channel_dispatch(payload: NotificationChannelTestRequest):
    """
    Dispatches a test notification probe to verify channel destination connectivity (Webhook, Email, Push).
    """
    ch_val = getattr(payload, "channel", None) or getattr(payload, "channel_type", "web")
    try:
        c_enum = NotificationChannel(ch_val.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid channel '{ch_val}'. Must be one of: web, email, push, webhook",
        )

    try:
        return notification_service.test_dispatch_channel(
            channel=c_enum,
            destination=payload.destination,
            secret_token=payload.secret_token,
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Channel test failed: {str(e)}",
        )


@router.post("/mark-all-read")
def mark_all_read(
    session_id: str = Query("guest_analyst_session", description="Analyst session ID"),
    db: Session = Depends(get_db),
):
    """
    Marks all unread notifications for a session as read.
    """
    try:
        updated = notification_service.mark_all_as_read(db=db, session_id=session_id)
        return {"session_id": session_id, "marked_read": updated}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to mark all as read: {str(e)}",
        )


@router.post("/pipeline/run")
def run_notification_pipeline(
    payload: NotificationPipelineRunRequest,
    db: Session = Depends(get_db),
):
    """
    Executes the 5-stage Notification Pipeline:
    New Content -> Match Watchlists -> Calculate Importance -> Create Notification -> Send
    """
    content_item = None
    if payload.content_id:
        content_item = db.query(Content).filter(Content.id == payload.content_id).first()
        if not content_item:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Content #{payload.content_id} not found",
            )
    elif payload.content_payload:
        content_item = payload.content_payload
    else:
        # Grab latest ingested content as default test target
        content_item = db.query(Content).order_by(Content.id.desc()).first()
        if not content_item:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No content specified and no existing content available in database.",
            )

    try:
        result = notification_pipeline.process_content(
            db=db,
            content_or_dict=content_item,
            session_id=payload.session_id,
            force_dispatch=payload.force_dispatch,
            threshold_override=payload.threshold_override,
        )
        return result.model_dump()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Notification pipeline execution failed: {str(e)}",
        )


@router.get("/{notification_id}", response_model=NotificationResponse)
def get_notification(
    notification_id: int,
    db: Session = Depends(get_db),
):
    """
    Retrieves a single alert notification by ID.
    """
    dto = notification_service.get_notification(db=db, notification_id=notification_id)
    if not dto:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification #{notification_id} not found",
        )
    return NotificationResponse(**dto.model_dump())


@router.patch("/{notification_id}/read", response_model=NotificationResponse)
def toggle_read_status(
    notification_id: int,
    is_read: bool = Query(True, description="Target read status"),
    db: Session = Depends(get_db),
):
    """
    Updates the read/unread state of an individual alert notification.
    """
    dto = notification_service.mark_as_read(db=db, notification_id=notification_id, is_read=is_read)
    if not dto:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification #{notification_id} not found",
        )
    return NotificationResponse(**dto.model_dump())


@router.delete("/{notification_id}", status_code=status.HTTP_200_OK)
def delete_notification(
    notification_id: int,
    db: Session = Depends(get_db),
):
    """
    Dismisses and deletes an alert notification.
    """
    success = notification_service.delete_notification(db=db, notification_id=notification_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification #{notification_id} not found",
        )
    return {"id": notification_id, "deleted": True}
