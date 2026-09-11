"""
DuplicateLink Model
Represents duplicate and near-duplicate relationships between normalized content records,
enabling clustering and auditability without silently deleting records.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
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
from app.models.base import Base


class DuplicateLink(Base):
    """
    Stores duplicate relationship connecting a duplicate item to its canonical counterpart.
    Supports exact URL, exact content hash, title similarity, and multi-signal clusters.
    """

    __tablename__ = "duplicate_links"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    canonical_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    duplicate_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    cluster_id = Column(String(64), nullable=False, index=True)
    match_type = Column(String(50), nullable=False, index=True)  # exact_url, exact_hash, similar_title, near_duplicate
    similarity_score = Column(Float, nullable=False, default=1.0)
    metadata_json = Column(Text, nullable=True)  # Detailed metrics (title_sim, desc_sim, entity_overlap)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    canonical_content = relationship(
        "Content",
        foreign_keys=[canonical_id],
        backref="duplicate_relationships",
    )
    duplicate_content = relationship(
        "Content",
        foreign_keys=[duplicate_id],
    )

    __table_args__ = (
        Index("ix_dup_cluster_canonical", cluster_id, canonical_id),
    )

    def __repr__(self) -> str:
        return f"<DuplicateLink(id={self.id}, canonical_id={self.canonical_id}, type='{self.match_type}', score={self.similarity_score})>"
