"""
Knowledge Graph SQLAlchemy Models
Represents directional relationships between cybersecurity entities (Threat Actors,
Malware, CVEs, Techniques, Products, Campaigns) with provenance tracking to source content.
Conforms strictly to IMPLEMENT.md Section 27.
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
from sqlalchemy.orm import relationship as orm_relationship

from app.models.base import Base, BaseModel


class EntityRelationship(BaseModel):
    """
    Directional cybersecurity entity relationship edge:
    source_entity_id -> relationship -> target_entity_id
    Provenance: source_content_id references the report/article establishing this link.
    """

    __tablename__ = "entity_relationships"

    source_entity_id = Column(
        Integer,
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relationship = Column(
        String(64),
        nullable=False,
        index=True,
    )  # uses, exploits, targets, delivers, operates, implements, affects, associated_with
    target_entity_id = Column(
        Integer,
        ForeignKey("entities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    confidence = Column(
        Float,
        default=1.0,
        nullable=False,
    )
    source_content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ORM navigation relationships
    source_entity = orm_relationship(
        "Entity",
        foreign_keys=[source_entity_id],
        lazy="joined",
    )
    target_entity = orm_relationship(
        "Entity",
        foreign_keys=[target_entity_id],
        lazy="joined",
    )
    source_content = orm_relationship(
        "Content",
        foreign_keys=[source_content_id],
        lazy="select",
    )

    __table_args__ = (
        UniqueConstraint(
            "source_entity_id",
            "relationship",
            "target_entity_id",
            "source_content_id",
            name="uq_entity_rel_source_target_content",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<EntityRelationship(id={self.id}, "
            f"source={self.source_entity_id}, rel='{self.relationship}', target={self.target_entity_id})>"
        )
