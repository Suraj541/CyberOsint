"""
Services Semantic Package
Provides text chunking, 384-dimensional vector embeddings, vector similarity search,
and Reciprocal Rank Fusion (RRF) hybrid search.
Conforms to IMPLEMENT.md Section 19.
"""

from services.semantic.chunker import TextChunker, text_chunker
from services.semantic.embedder import (
    EMBEDDING_DIMENSION,
    BaseEmbedder,
    DeterministicLocalEmbedder,
    embedder,
    get_embedder,
)
from services.semantic.models import (
    HybridHit,
    HybridSearchQuery,
    HybridSearchResult,
    SemanticHit,
)
from services.semantic.service import SemanticService, semantic_service
from services.semantic.similarity import cosine_similarity

__all__ = [
    "SemanticService",
    "semantic_service",
    "TextChunker",
    "text_chunker",
    "BaseEmbedder",
    "DeterministicLocalEmbedder",
    "embedder",
    "get_embedder",
    "EMBEDDING_DIMENSION",
    "cosine_similarity",
    "SemanticHit",
    "HybridSearchQuery",
    "HybridHit",
    "HybridSearchResult",
]
