"""
Source Quality SQLAlchemy Model
Represents multi-dimensional quality assessment for intelligence sources.
Calculates: authority, accuracy, technical_depth, originality, historical_reliability.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
Note: This is an internal ranking indicator, not an unquestionable truth score.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship as orm_relationship

from app.models.base import Base, BaseModel


class SourceQuality(BaseModel):
    """
    Tracks multi-dimensional reliability and intelligence quality metrics for a source.
    Internal ranking mechanism per IMPLEMENT.md Section 28.
    """

    __tablename__ = "source_quality"

    source_id = Column(
        Integer,
        ForeignKey("sources.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    # 5 Mandated Metrics (0.0 to 1.0)
    authority = Column(Float, default=0.70, nullable=False)
    accuracy = Column(Float, default=0.80, nullable=False)
    technical_depth = Column(Float, default=0.60, nullable=False)
    originality = Column(Float, default=0.70, nullable=False)
    historical_reliability = Column(Float, default=0.80, nullable=False)

    # Composite & Tier Indicator
    overall_score = Column(Float, default=0.72, nullable=False)
    quality_tier = Column(String(64), default="Tier 2 (High)", nullable=False)
    indicator_symbol = Column(String(10), default="A", nullable=False)

    # Evaluation Metadata / Rationale JSON
    eval_metadata = Column(Text, nullable=True)

    # Relationship back to Source
    source = orm_relationship("Source", back_populates="quality", lazy="joined")

    def __repr__(self) -> str:
        return (
            f"<SourceQuality(source_id={self.source_id}, "
            f"tier='{self.quality_tier}', score={self.overall_score:.2f})>"
        )
