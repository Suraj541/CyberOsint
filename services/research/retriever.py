"""
Multi-Modal Hybrid Retriever for AI Research Pipeline (Stages 3, 4, 5, 6)
Executes:
- Stage 3: Full-Text Lexical Search
- Stage 4: Entity Search (CVEs, techniques, threat actors, products)
- Stage 5: Vector Semantic Search across chunk embeddings
- Stage 6: Source Reliability Ranking (weighting results by source authority)
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.chunk import ContentChunk
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from services.reliability import source_reliability_service
from services.research.models import QueryExpansionResult
from services.search import SearchQuery, search_service
from services.semantic import SemanticHit, semantic_service

logger = logging.getLogger("cyber_osint.services.research.retriever")


class CandidateContent:
    """Intermediate container for multi-modal scoring and source ranking."""

    def __init__(self, content: Content):
        self.content = content
        self.lexical_score: float = 0.0
        self.entity_score: float = 0.0
        self.vector_score: float = 0.0
        self.matched_entities: Set[str] = set()
        self.matched_chunks: List[str] = []
        self.quality_score: float = 0.80
        self.quality_tier: str = "Tier 2 (High)"
        self.final_rank_score: float = 0.0


class HybridRetriever:
    """Executes Stages 3-6 of the AI Research Pipeline."""

    def retrieve_and_rank(
        self,
        db: Session,
        expansion: QueryExpansionResult,
        top_k: int = 8,
        min_reliability: float = 0.0,
    ) -> List[CandidateContent]:
        """
        Execute Search -> Entity Search -> Vector Search -> Source Ranking.
        """
        candidates: Dict[int, CandidateContent] = {}

        # -------------------------------------------------------------
        # Stage 3: Lexical / Full-Text Search
        # -------------------------------------------------------------
        # 1. Search OpenSearch / full-text
        try:
            sq = SearchQuery(query=expansion.search_keywords, page_size=20)
            sr = search_service.search(sq)
            for hit in sr.hits:
                content = db.query(Content).filter(Content.id == hit.id).first()
                if content:
                    if content.id not in candidates:
                        candidates[content.id] = CandidateContent(content)
                    candidates[content.id].lexical_score = max(candidates[content.id].lexical_score, min(1.0, hit.score / 5.0))
        except Exception as e:
            logger.warning("OpenSearch lexical query failed, using SQL fallback: %s", e)

        # SQL keyword fallback search to ensure 100% coverage
        search_terms = expansion.expanded_terms[:8] + [expansion.original_query]
        for term in search_terms:
            if len(term) < 3:
                continue
            like_pat = f"%{term}%"
            matched_items = (
                db.query(Content)
                .filter(
                    (Content.title.ilike(like_pat))
                    | (Content.description.ilike(like_pat))
                    | (Content.raw_content.ilike(like_pat))
                )
                .limit(10)
                .all()
            )
            for c in matched_items:
                if c.id not in candidates:
                    candidates[c.id] = CandidateContent(c)
                candidates[c.id].lexical_score = max(candidates[c.id].lexical_score, 0.75)

        # -------------------------------------------------------------
        # Stage 4: Entity Search
        # -------------------------------------------------------------
        entity_search_targets = set(expansion.detected_entities) | set(expansion.expanded_terms[:6])
        for term in entity_search_targets:
            if len(term) < 2:
                continue
            matching_entities = (
                db.query(Entity)
                .filter(
                    (Entity.name.ilike(f"%{term}%"))
                    | (Entity.normalized_name.ilike(f"%{term}%"))
                )
                .limit(10)
                .all()
            )
            for ent in matching_entities:
                for link in ent.content_links:
                    cid = link.content_id
                    content = link.content or db.query(Content).filter(Content.id == cid).first()
                    if content:
                        if cid not in candidates:
                            candidates[cid] = CandidateContent(content)
                        candidates[cid].entity_score = max(candidates[cid].entity_score, link.confidence or 0.85)
                        candidates[cid].matched_entities.add(ent.name)

        # -------------------------------------------------------------
        # Stage 5: Vector Search
        # -------------------------------------------------------------
        try:
            vector_hits: List[SemanticHit] = semantic_service.search_vector(
                db=db,
                query=expansion.original_query,
                limit=15,
                threshold=0.15,
            )
            for vh in vector_hits:
                cid = vh.content_id
                content = db.query(Content).filter(Content.id == cid).first()
                if content:
                    if cid not in candidates:
                        candidates[cid] = CandidateContent(content)
                    candidates[cid].vector_score = max(candidates[cid].vector_score, vh.similarity)
                    if vh.chunk_text and vh.chunk_text not in candidates[cid].matched_chunks:
                        candidates[cid].matched_chunks.append(vh.chunk_text)
        except Exception as e:
            logger.warning("Vector search step encountered warning: %s", e)

        # -------------------------------------------------------------
        # Stage 6: Source Ranking
        # -------------------------------------------------------------
        ranked_candidates: List[CandidateContent] = []
        for cand in candidates.values():
            src = cand.content.source
            # Check source quality
            if src:
                if getattr(src, "quality", None):
                    cand.quality_score = src.quality.overall_score
                    cand.quality_tier = src.quality.quality_tier
                else:
                    # On-the-fly reliability evaluation
                    quality = source_reliability_service.calculate_quality(db, src)
                    cand.quality_score = quality.overall_score
                    cand.quality_tier = quality.quality_tier
            else:
                cand.quality_score = 0.70
                cand.quality_tier = "Tier 3 (Moderate)"

            # Filter by minimum reliability threshold if specified
            if cand.quality_score < min_reliability:
                continue

            # Composite retrieval score: Lexical (35%), Entity (35%), Vector (30%)
            retrieval_score = (
                0.35 * cand.lexical_score
                + 0.35 * cand.entity_score
                + 0.30 * cand.vector_score
            )
            # Guarantee baseline relevance for matched items
            if retrieval_score == 0:
                retrieval_score = 0.50

            # Rank Score weights retrieval relevance with source quality
            cand.final_rank_score = retrieval_score * (0.65 + 0.35 * cand.quality_score)
            ranked_candidates.append(cand)

        # Sort descending by final rank score
        ranked_candidates.sort(key=lambda c: c.final_rank_score, reverse=True)
        return ranked_candidates[:top_k]


# Global retriever singleton
hybrid_retriever = HybridRetriever()
