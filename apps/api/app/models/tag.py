"""
Tag and ContentTag Models
Represents cybersecurity taxonomy topics, categories, and their association to content items.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.models.base import Base, BaseModel


class Tag(BaseModel):
    """Taxonomy tag (e.g. ransomware, zero-day, cloud-security, incident-response)."""

    __tablename__ = "tags"

    name = Column(String(100), unique=True, nullable=False, index=True)
    category = Column(String(100), nullable=True, index=True)  # threat_type, platform, defense, vulnerability

    # Relationship to linking records
    content_links = relationship(
        "ContentTag",
        back_populates="tag",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Tag(id={self.id}, name='{self.name}', category='{self.category}')>"


class ContentTag(Base):
    """Many-to-Many association linking Content to Tag."""

    __tablename__ = "content_tags"

    id = Column(Integer, primary_key=True, autoincrement=True)
    content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    tag_id = Column(
        Integer,
        ForeignKey("tags.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    confidence = Column(Float, default=1.0, nullable=False)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    content = relationship("Content", back_populates="content_tags")
    tag = relationship("Tag", back_populates="content_links")

    __table_args__ = (
        UniqueConstraint("content_id", "tag_id", name="uq_content_tag"),
    )

    def __repr__(self) -> str:
        return f"<ContentTag(content_id={self.content_id}, tag_id={self.tag_id})>"
