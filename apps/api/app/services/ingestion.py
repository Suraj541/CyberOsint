"""
Ingestion Service Adapter
Exposes IngestionPipeline and metrics to the FastAPI application layer.
"""

from services.ingestion import (
    IngestionPipeline,
    ingestion_pipeline,
    IngestionMetrics,
    Deduplicator,
    compute_content_hash,
    ItemValidator,
)

__all__ = [
    "IngestionPipeline",
    "ingestion_pipeline",
    "IngestionMetrics",
    "Deduplicator",
    "compute_content_hash",
    "ItemValidator",
]
