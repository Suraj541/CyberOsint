"""
SQLAlchemy Domain Models Package
Aggregates and exposes all core database entities for the Cybersecurity OSINT Platform.
"""

from app.models.base import Base, BaseModel, TimestampMixin
from app.models.user import User
from app.models.source import Source
from app.models.content import Content
from app.models.entity import Entity, ContentEntity
from app.models.tag import Tag, ContentTag
from app.models.duplicate import DuplicateLink
from app.models.chunk import ContentChunk
from app.models.mitre import (
    MitreDataSourceModel,
    MitreGroupModel,
    MitreMitigationModel,
    MitreRelationshipModel,
    MitreSoftwareModel,
    MitreTacticModel,
    MitreTechniqueModel,
)
from app.models.graph import EntityRelationship
from app.models.source_quality import SourceQuality
from app.models.summary import ContentSummary


__all__ = [
    "Base",
    "BaseModel",
    "TimestampMixin",
    "User",
    "Source",
    "Content",
    "Entity",
    "ContentEntity",
    "Tag",
    "ContentTag",
    "DuplicateLink",
    "ContentChunk",
    "MitreTacticModel",
    "MitreTechniqueModel",
    "MitreGroupModel",
    "MitreSoftwareModel",
    "MitreMitigationModel",
    "MitreDataSourceModel",
    "MitreRelationshipModel",
    "EntityRelationship",
    "SourceQuality",
    "ContentSummary",
]


