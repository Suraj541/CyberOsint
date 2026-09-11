"""
Entity and ContentEntity Models
Represents extracted cybersecurity intelligence entities (CVEs, malware, threat actors,
MITRE techniques, tools, IOCs) and their association to normalized content records.
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
    UniqueConstraint,
)
from sqlalchemy.orm import relationship
from app.models.base import Base, BaseModel


class Entity(BaseModel):
    """Extracted cybersecurity entity (e.g. CVE-2024-38077, LockBit 3.0, T1059)."""

    __tablename__ = "entities"

    name = Column(String(255), nullable=False, index=True)
    entity_type = Column(
        String(50),
        nullable=False,
        index=True,
    )  # cve, malware, threat_actor, vendor, product, mitre_technique, tool, ioc
    normalized_name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    metadata_json = Column(Text, nullable=True)  # JSON-encoded extra attributes (CVSS score, references, etc.)

    # Relationship to linking records
    content_links = relationship(
        "ContentEntity",
        back_populates="entity",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        UniqueConstraint("entity_type", "normalized_name", name="uq_entity_type_normalized_name"),
    )

    def __repr__(self) -> str:
        return f"<Entity(id={self.id}, type='{self.entity_type}', name='{self.name}')>"


class ContentEntity(Base):
    """Many-to-Many association linking Content to Entity with confidence and extraction context."""

    __tablename__ = "content_entities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    entity_id = Column(
        Integer,
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    confidence = Column(Float, default=1.0, nullable=False)
    extraction_method = Column(String(50), default="regex", nullable=False)  # regex, ner, dictionary, llm
    context_snippet = Column(Text, nullable=True)
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    content = relationship("Content", back_populates="content_entities")
    entity = relationship("Entity", back_populates="content_links")

    __table_args__ = (
        UniqueConstraint("content_id", "entity_id", name="uq_content_entity"),
    )

    def __repr__(self) -> str:
        return f"<ContentEntity(content_id={self.content_id}, entity_id={self.entity_id}, conf={self.confidence})>"
