"""
Content Model
Represents normalized cybersecurity articles, advisories, research reports, and CVE announcements.
Conforms strictly to IMPLEMENT.md Section 6 specification.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship
from app.models.base import BaseModel


class Content(BaseModel):
    """Normalized content storage with provenance, confidence scores, and deduplication hashes."""

    __tablename__ = "content"

    source_id = Column(
        Integer,
        ForeignKey("sources.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    content_type = Column(String(50), default="article", nullable=False, index=True)  # article, advisory, cve, report
    canonical_url = Column(String(2048), nullable=False, index=True)
    author = Column(String(255), nullable=True)
    published_at = Column(DateTime(timezone=True), nullable=True, index=True)
    discovered_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    language = Column(String(10), default="en", nullable=False)
    summary = Column(Text, nullable=True)
    raw_content = Column(Text, nullable=True)
    content_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash for deduplication
    quality_score = Column(Float, default=0.0, nullable=False)
    relevance_score = Column(Float, default=0.0, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    status = Column(String(50), default="discovered", nullable=False, index=True)  # discovered, parsed, indexed

    # Relationships
    source = relationship("Source", back_populates="contents")
    content_entities = relationship(
        "ContentEntity",
        back_populates="content",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    content_tags = relationship(
        "ContentTag",
        back_populates="content",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        Index("ix_content_published_at_desc", published_at.desc()),
        Index("ix_content_source_published", source_id, published_at.desc()),
        Index("ix_content_type_published", content_type, published_at.desc()),
        Index("ix_content_hash_canonical", content_hash, canonical_url),
    )

    def __repr__(self) -> str:
        return f"<Content(id={self.id}, title='{self.title[:40]}...', type='{self.content_type}')>"
