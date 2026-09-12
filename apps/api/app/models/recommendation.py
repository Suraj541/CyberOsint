"""
UserProfile and UserInteraction Models
Stores user interests, reading history, saved content, search history, and technical difficulty level.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.models.base import BaseModel, Base


class UserProfile(BaseModel):
    """
    User/Session profile storing cybersecurity interest domains, difficulty preference,
    and preferred content delivery types.
    """

    __tablename__ = "user_profiles"

    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(64), nullable=False, unique=True, index=True)
    interests_json = Column(Text, default="[]", nullable=False)
    difficulty_level = Column(String(20), default="intermediate", nullable=False)  # beginner, intermediate, advanced, expert
    preferred_types_json = Column(Text, default="[]", nullable=False)  # article, video, research, tool, course, document

    # Relationships
    user = relationship("User", foreign_keys=[user_id])

    @property
    def interests(self) -> List[str]:
        try:
            return json.loads(self.interests_json or "[]")
        except Exception:
            return []

    @interests.setter
    def interests(self, val: List[str]) -> None:
        self.interests_json = json.dumps(val or [])

    @property
    def preferred_types(self) -> List[str]:
        try:
            return json.loads(self.preferred_types_json or "[]")
        except Exception:
            return []

    @preferred_types.setter
    def preferred_types(self, val: List[str]) -> None:
        self.preferred_types_json = json.dumps(val or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "interests": self.interests,
            "difficulty_level": self.difficulty_level,
            "preferred_types": self.preferred_types,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<UserProfile(session_id='{self.session_id}', difficulty='{self.difficulty_level}', interests={len(self.interests)})>"


class UserInteraction(Base):
    """
    Interaction event ledger capturing viewed content, saved bookmarks, search history,
    and user telemetry to power the recommendation engine.
    """

    __tablename__ = "user_interactions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    session_id = Column(String(64), nullable=False, index=True)
    content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    interaction_type = Column(
        String(30), nullable=False, index=True
    )  # view, save, unsave, search, click
    search_query = Column(String(255), nullable=True, index=True)
    metadata_json = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    content = relationship("Content", foreign_keys=[content_id])

    __table_args__ = (
        Index("ix_user_interactions_session_type", session_id, interaction_type),
        Index("ix_user_interactions_session_content", session_id, content_id),
        Index("ix_user_interactions_created_at_desc", created_at.desc()),
    )

    def to_dict(self) -> Dict[str, Any]:
        meta = {}
        if self.metadata_json:
            try:
                meta = json.loads(self.metadata_json)
            except Exception:
                meta = {"raw": self.metadata_json}
        return {
            "id": self.id,
            "user_id": self.user_id,
            "session_id": self.session_id,
            "content_id": self.content_id,
            "interaction_type": self.interaction_type,
            "search_query": self.search_query,
            "metadata": meta,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f"<UserInteraction(session='{self.session_id[:8]}', type='{self.interaction_type}', content_id={self.content_id})>"
