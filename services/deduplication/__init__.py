"""
Services Deduplication Package
Provides advanced multi-factor deduplication (Exact URL, Content Hash, Similar Title,
Multi-Signal, and Duplicate Clusters) for the Cybersecurity OSINT Ingestion Pipeline.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from services.deduplication.engine import (
    DeduplicationEngine,
    deduplication_engine,
)
from services.deduplication.hashing import (
    compute_content_hash,
    compute_simhash,
    normalize_title_text,
    simhash_hamming_distance,
    simhash_similarity,
)
from services.deduplication.models import (
    DeduplicationResult,
    DuplicateCluster,
)
from services.deduplication.similarity import (
    calculate_description_similarity,
    calculate_entity_overlap,
    calculate_multi_signal_similarity,
    calculate_semantic_similarity,
    calculate_title_similarity,
)
from services.deduplication.url import (
    STRIP_QUERY_PARAMS,
    get_url_domain,
    normalize_url,
)

__all__ = [
    "DeduplicationEngine",
    "deduplication_engine",
    "DeduplicationResult",
    "DuplicateCluster",
    "compute_content_hash",
    "compute_simhash",
    "normalize_title_text",
    "simhash_hamming_distance",
    "simhash_similarity",
    "calculate_title_similarity",
    "calculate_description_similarity",
    "calculate_entity_overlap",
    "calculate_semantic_similarity",
    "calculate_multi_signal_similarity",
    "STRIP_QUERY_PARAMS",
    "normalize_url",
    "get_url_domain",
]
