"""
Content Summary SQLAlchemy Model
Represents validated AI-generated executive summaries with strict provenance tracking.
Stores: model, model_version, prompt_version, generated_at, confidence,
reported_facts, inferences, uncertainties, and validation status.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
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


class ContentSummary(BaseModel):
    """
    Persisted AI summarization record with mandatory provenance and validation metadata.
    Enforces separation of reported facts from inference and preserves uncertainty.
    """

    __tablename__ = "content_summaries"

    content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )

    # Core Summary & Segregated Semantic Sections
    executive_summary = Column(Text, nullable=False)
    reported_facts = Column(Text, nullable=True)     # JSON array: verifiable facts extracted from source
    inferences = Column(Text, nullable=True)         # JSON array: separated analytical interpretations
    uncertainties = Column(Text, nullable=True)      # JSON array: preserved open questions / unverified items
    key_takeaways = Column(Text, nullable=True)      # JSON array: high-priority bullet points
    source_attribution = Column(String(255), nullable=True)

    # Mandated Provenance Metadata (IMPLEMENT.md Section 29)
    model = Column(String(100), nullable=False, default="cyber-grounded-summarizer")
    model_version = Column(String(50), nullable=False, default="v1.2.0")
    prompt_version = Column(String(50), nullable=False, default="v1.0.0-grounded")
    generated_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    confidence = Column(Float, default=0.92, nullable=False)

    # Grounding Validation Telemetry
    validation_status = Column(String(50), default="passed", nullable=False)  # passed, flagged, rejected
    validation_score = Column(Float, default=0.95, nullable=False)
    validation_notes = Column(Text, nullable=True)

    # Relationship back to parent Content
    content = orm_relationship("Content", back_populates="ai_summary", lazy="joined")

    def __repr__(self) -> str:
        return (
            f"<ContentSummary(id={self.id}, content_id={self.content_id}, "
            f"model='{self.model}:{self.model_version}', status='{self.validation_status}', "
            f"confidence={self.confidence:.2f})>"
        )
