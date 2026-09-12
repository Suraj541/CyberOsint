"""
Watchlist and WatchlistItem Models
Stores analyst watchlists and individual monitored targets across 10 security intelligence categories.
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.models.base import BaseModel


class Watchlist(BaseModel):
    """
    Watchlist collection representing a cohesive monitoring scope
    (e.g., 'Critical Edge Appliance Watchlist', 'Kubernetes & Container Security').
    """

    __tablename__ = "watchlists"

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(64), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    notification_channel = Column(String(50), default="in_app", nullable=False)

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    items = relationship(
        "WatchlistItem",
        back_populates="watchlist",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="WatchlistItem.created_at.desc()",
    )

    __table_args__ = (
        Index("ix_watchlists_session_active", session_id, is_active),
    )

    def to_dict(self, include_items: bool = True) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "id": self.id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "name": self.name,
            "description": self.description,
            "is_active": self.is_active,
            "notification_channel": self.notification_channel,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "item_count": len(self.items) if self.items else 0,
        }
        if include_items and self.items:
            data["items"] = [item.to_dict() for item in self.items]
        elif include_items:
            data["items"] = []
        return data

    def __repr__(self) -> str:
        return f"<Watchlist(id={self.id}, name='{self.name}', items={len(self.items) if self.items else 0})>"


class WatchlistItem(BaseModel):
    """
    Individual monitored target within a watchlist.
    Matches against: CVE, Product, Vendor, Threat Actor, Malware, Technology, Topic, Researcher, Tool, or Keyword.
    """

    __tablename__ = "watchlist_items"

    watchlist_id = Column(
        Integer,
        ForeignKey("watchlists.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    # The 10 mandated types: cve, product, vendor, threat_actor, malware, technology, topic, researcher, tool, keyword
    item_type = Column(String(50), nullable=False, index=True)
    item_value = Column(String(255), nullable=False, index=True)
    severity_threshold = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    notify_on_match = Column(Boolean, default=True, nullable=False)

    # Relationships
    watchlist = relationship("Watchlist", back_populates="items")

    __table_args__ = (
        Index("ix_watchlist_items_watchlist_type", watchlist_id, item_type),
        Index("ix_watchlist_items_type_value", item_type, item_value),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "watchlist_id": self.watchlist_id,
            "item_type": self.item_type,
            "item_value": self.item_value,
            "severity_threshold": self.severity_threshold,
            "notify_on_match": self.notify_on_match,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<WatchlistItem(id={self.id}, watchlist_id={self.watchlist_id}, type='{self.item_type}', value='{self.item_value}')>"
