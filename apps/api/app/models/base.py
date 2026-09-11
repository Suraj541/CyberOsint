"""
Base Database Model and Mixins
Provides standard primary keys and timestamp tracking for all entities.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer
from app.database import Base


class TimestampMixin:
    """Provides created_at and updated_at datetime columns."""

    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class BaseModel(Base, TimestampMixin):
    """Abstract base model with auto-incrementing integer primary key and timestamps."""

    __abstract__ = True

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
