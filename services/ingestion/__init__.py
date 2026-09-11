"""
Ingestion Pipeline Package
Provides modular ingestion, validation, deduplication, and metrics for OSINT collectors.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

from services.ingestion.deduplication import Deduplicator, compute_content_hash, normalize_url
from services.ingestion.metrics import IngestionMetrics
from services.ingestion.pipeline import IngestionPipeline, ingestion_pipeline
from services.ingestion.validation import ItemValidator, ValidationError

__all__ = [
    "IngestionPipeline",
    "ingestion_pipeline",
    "IngestionMetrics",
    "Deduplicator",
    "compute_content_hash",
    "normalize_url",
    "ItemValidator",
    "ValidationError",
]
