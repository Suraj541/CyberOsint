"""
Notification Service Business Logic and Data Access Layer
Provides CRUD operations, status management, telemetry aggregation, and test triggers.
Conforms strictly to IMPLEMENT.md Section 33 (Step 32: Build Notifications).
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models.notification import Notification, NotificationChannelConfig
from services.notification.dispatchers import dispatcher_registry
from services.notification.models import (
    ImportanceLevel,
    NotificationChannel,
    NotificationChannelConfigDTO,
    NotificationDTO,
    NotificationStatus,
)

logger = logging.getLogger("cyber_osint.services.notification.service")


class NotificationService:
    """Manages notifications, channel configurations, and read state."""

    def list_notifications(
        self,
        db: Session,
        session_id: Optional[str] = None,
        channel: Optional[str] = None,
        importance_level: Optional[str] = None,
        is_read: Optional[bool] = None,
        watchlist_id: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[NotificationDTO]:
        """Query notifications with flexible filtering and sorting."""
        query = db.query(Notification)

        if session_id:
            query = query.filter(Notification.session_id == session_id)
        if channel:
            query = query.filter(Notification.channel == channel.lower())
        if importance_level:
            query = query.filter(Notification.importance_level == importance_level.upper())
        if is_read is not None:
            query = query.filter(Notification.is_read.is_(is_read))
        if watchlist_id is not None:
            query = query.filter(Notification.watchlist_id == watchlist_id)

        rows = query.order_by(desc(Notification.created_at)).offset(offset).limit(limit).all()
        return [self._to_dto(r) for r in rows]

    def get_notification(self, db: Session, notification_id: int) -> Optional[NotificationDTO]:
        """Fetch single notification by ID."""
        row = db.query(Notification).filter(Notification.id == notification_id).first()
        return self._to_dto(row) if row else None

    def mark_as_read(
        self, db: Session, notification_id: int, is_read: bool = True
    ) -> Optional[NotificationDTO]:
        """Toggle or mark notification as read/unread."""
        row = db.query(Notification).filter(Notification.id == notification_id).first()
        if not row:
            return None

        row.is_read = is_read
        row.read_at = datetime.now(timezone.utc) if is_read else None
        db.commit()
        db.refresh(row)
        return self._to_dto(row)

    def mark_all_as_read(self, db: Session, session_id: str) -> int:
        """Mark all unread notifications for a session as read."""
        now = datetime.now(timezone.utc)
        updated_count = (
            db.query(Notification)
            .filter(
                Notification.session_id == session_id,
                Notification.is_read.is_(False),
            )
            .update({"is_read": True, "read_at": now}, synchronize_session=False)
        )
        db.commit()
        return updated_count

    def delete_notification(self, db: Session, notification_id: int) -> bool:
        """Delete notification by ID."""
        row = db.query(Notification).filter(Notification.id == notification_id).first()
        if not row:
            return False
        db.delete(row)
        db.commit()
        return True

    def get_summary(self, db: Session, session_id: Optional[str] = None) -> Dict[str, Any]:
        """Computes summary metrics: unread count, critical alerts, channel breakdown."""
        query = db.query(Notification)
        if session_id:
            query = query.filter(Notification.session_id == session_id)

        all_notifications = query.all()
        total_count = len(all_notifications)
        unread_count = sum(1 for n in all_notifications if not n.is_read)
        critical_count = sum(1 for n in all_notifications if n.importance_level == "CRITICAL")
        high_count = sum(1 for n in all_notifications if n.importance_level == "HIGH")

        by_channel: Dict[str, int] = {}
        by_level: Dict[str, int] = {}
        by_status: Dict[str, int] = {}

        for n in all_notifications:
            by_channel[n.channel] = by_channel.get(n.channel, 0) + 1
            by_level[n.importance_level] = by_level.get(n.importance_level, 0) + 1
            by_status[n.status] = by_status.get(n.status, 0) + 1

        return {
            "total_count": total_count,
            "unread_count": unread_count,
            "critical_count": critical_count,
            "high_count": high_count,
            "by_channel": by_channel,
            "by_level": by_level,
            "by_status": by_status,
        }

    # Channel Configurations
    def list_channel_configs(
        self, db: Session, session_id: str
    ) -> List[NotificationChannelConfigDTO]:
        """List configured notification destinations for a session."""
        rows = (
            db.query(NotificationChannelConfig)
            .filter(NotificationChannelConfig.session_id == session_id)
            .order_by(NotificationChannelConfig.channel_type)
            .all()
        )
        return [
            NotificationChannelConfigDTO(
                id=r.id,
                session_id=r.session_id,
                channel_type=NotificationChannel(r.channel_type),
                destination=r.destination,
                is_enabled=r.is_enabled,
                min_importance_threshold=r.min_importance_threshold,
                secret_token=r.secret_token,
                description=r.description,
            )
            for r in rows
        ]

    def save_channel_config(
        self, db: Session, dto: NotificationChannelConfigDTO
    ) -> NotificationChannelConfigDTO:
        """Create or update a channel configuration."""
        existing = (
            db.query(NotificationChannelConfig)
            .filter(
                NotificationChannelConfig.session_id == dto.session_id,
                NotificationChannelConfig.channel_type == dto.channel_type.value,
            )
            .first()
        )

        if existing:
            existing.destination = dto.destination
            existing.is_enabled = dto.is_enabled
            existing.min_importance_threshold = dto.min_importance_threshold
            if dto.secret_token is not None:
                existing.secret_token = dto.secret_token
            existing.description = dto.description
            db.commit()
            db.refresh(existing)
            target_obj = existing
        else:
            new_obj = NotificationChannelConfig(
                session_id=dto.session_id,
                channel_type=dto.channel_type.value,
                destination=dto.destination,
                is_enabled=dto.is_enabled,
                min_importance_threshold=dto.min_importance_threshold,
                secret_token=dto.secret_token,
                description=dto.description,
            )
            db.add(new_obj)
            db.commit()
            db.refresh(new_obj)
            target_obj = new_obj

        return NotificationChannelConfigDTO(
            id=target_obj.id,
            session_id=target_obj.session_id,
            channel_type=NotificationChannel(target_obj.channel_type),
            destination=target_obj.destination,
            is_enabled=target_obj.is_enabled,
            min_importance_threshold=target_obj.min_importance_threshold,
            secret_token=target_obj.secret_token,
            description=target_obj.description,
        )

    def test_dispatch_channel(
        self,
        channel: NotificationChannel,
        destination: Optional[str] = None,
        secret_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Dispatches a test notification to verify channel connectivity."""
        sample_notif = NotificationDTO(
            id=999999,
            session_id="test_channel_probe",
            title="[TEST ALERT] Channel Connectivity Verification",
            body="This is a test notification verifying dispatch delivery for Cyber-OSINT alerting channels.",
            summary="Channel dispatch probe confirmed successful integration.",
            importance_score=0.88,
            importance_level=ImportanceLevel.HIGH.value,
            channel=channel.value,
            status=NotificationStatus.PENDING.value,
            content_url="https://cyber-osint.local/test-alert",
            metadata={"probe": True, "dispatched_at": datetime.now(timezone.utc).isoformat()},
        )

        return dispatcher_registry.dispatch(
            channel=channel,
            notification=sample_notif,
            destination=destination,
            secret_token=secret_token,
        )

    def _to_dto(self, row: Notification) -> NotificationDTO:
        data = row.to_dict()
        return NotificationDTO(
            id=data["id"],
            user_id=data["user_id"],
            session_id=data["session_id"],
            watchlist_id=data["watchlist_id"],
            watchlist_name=data.get("watchlist_name"),
            content_id=data["content_id"],
            content_title=data.get("content_title"),
            content_url=data.get("content_url"),
            title=data["title"],
            body=data["body"],
            summary=data.get("summary"),
            importance_score=data["importance_score"],
            importance_level=data["importance_level"],
            channel=data["channel"],
            status=data["status"],
            is_read=data["is_read"],
            read_at=data.get("read_at"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


notification_service = NotificationService()
