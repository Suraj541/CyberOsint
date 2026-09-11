"""
Services Extractor Adapter Package
Re-exports the core deterministic entity extraction engine for use across background services and ingestion pipelines.
"""

from packages.extractor import (
    DeterministicEntityExtractor,
    ExtractedEntity,
    entity_extractor,
    extract_entities,
    extract_from_content,
)

__all__ = [
    "ExtractedEntity",
    "DeterministicEntityExtractor",
    "entity_extractor",
    "extract_entities",
    "extract_from_content",
]
