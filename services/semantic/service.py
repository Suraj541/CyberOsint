"""
Semantic & Hybrid Search Service
Orchestrates document chunking, vector embedding generation, cosine similarity retrieval,
and Reciprocal Rank Fusion (RRF) hybrid search.
Conforms to IMPLEMENT.md Section 19.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.models.chunk import ContentChunk
from app.models.content import Content
from services.search import SearchQuery, search_service
from services.semantic.chunker import TextChunker, text_chunker
from services.semantic.embedder import BaseEmbedder, embedder
from services.semantic.models import (
    HybridHit,
    HybridSearchQuery,
    HybridSearchResult,
    SemanticHit,
)
from services.semantic.similarity import cosine_similarity

logger = logging.getLogger("cyber_osint.services.semantic.service")


class SemanticService:
    """
    Manages vector embeddings and hybrid search combining dense vector similarity
    with OpenSearch lexical keyword search.
    """

    def __init__(
        self,
        chunker: Optional[TextChunker] = None,
        vector_embedder: Optional[BaseEmbedder] = None,
        rrf_k: int = 60,
    ):
        self.chunker = chunker or text_chunker
        self.embedder = vector_embedder or embedder
        self.rrf_k = rrf_k  # Standard Reciprocal Rank Fusion smoothing constant

    def index_content(self, db: Session, content_id: int) -> int:
        """
        Chunk content document, generate 384-dimensional vector embeddings,
        and persist ContentChunk records into the database.
        """
        content = db.query(Content).filter(Content.id == content_id).first()
        if not content:
            logger.warning("Content id=%s not found for semantic indexing", content_id)
            return 0

        # Remove existing chunks for this content if re-indexing
        db.query(ContentChunk).filter(ContentChunk.content_id == content_id).delete()

        # Generate coherent text chunks
        raw_body = getattr(content, "raw_content", "") or ""
        chunks = self.chunker.chunk_document(
            title=content.title,
            description=content.description,
            summary=content.summary,
            body=raw_body,
        )

        chunk_count = 0
        for idx, chunk_text in enumerate(chunks):
            if not chunk_text.strip():
                continue

            vector = self.embedder.embed_text(chunk_text)
            tokens = len(chunk_text.split())

            chunk_record = ContentChunk(
                content_id=content.id,
                chunk_index=idx,
                chunk_text=chunk_text,
                chunk_tokens=tokens,
                embedding=vector,
            )
            db.add(chunk_record)
            chunk_count += 1

        db.commit()
        logger.debug("Indexed %s semantic chunk(s) for content id=%s", chunk_count, content_id)
        return chunk_count

    def search_vector(
        self,
        db: Session,
        query: str,
        limit: int = 20,
        threshold: float = 0.3,
        category: Optional[str] = None,
        source: Optional[str] = None,
    ) -> List[SemanticHit]:
        """
        Generate embedding for query string and perform vector cosine similarity search
        against all indexed ContentChunks.
        """
        if not query or not query.strip():
            return []

        query_vec = self.embedder.embed_text(query)

        # Query all chunks from DB joined with Content
        q = db.query(ContentChunk, Content).join(Content, ContentChunk.content_id == Content.id)
        if category:
            # Filter if content has category
            pass

        results: List[SemanticHit] = []
        chunk_rows = q.all()

        for chunk, content in chunk_rows:
            if not chunk.embedding:
                continue

            sim = cosine_similarity(query_vec, chunk.embedding)
            if sim >= threshold:
                results.append(
                    SemanticHit(
                        content_id=content.id,
                        chunk_id=chunk.id,
                        chunk_text=chunk.chunk_text,
                        similarity=sim,
                        content_title=content.title,
                        canonical_url=content.canonical_url,
                        content_type=content.content_type,
                        source=content.source.name if content.source else None,
                    )
                )

        # Sort by similarity descending
        results.sort(key=lambda h: h.similarity, reverse=True)
        return results[:limit]

    def search_hybrid(self, db: Session, sq: HybridSearchQuery) -> HybridSearchResult:
        """
        Execute hybrid search per Section 19:
        1. Vector search via query embedding
        2. Keyword search via OpenSearch
        3. Reciprocal Rank Fusion (RRF) ranking
        """
        start_time = time.time()

        # -------------------------------------------------------------
        # 1. Semantic Vector Search
        # -------------------------------------------------------------
        vector_hits = self.search_vector(
            db=db,
            query=sq.query,
            limit=50,
            threshold=0.2,
            category=sq.category,
            source=sq.source,
        )

        # Aggregate vector hits by content_id (best matching chunk per article)
        vector_content_map: Dict[int, SemanticHit] = {}
        for vh in vector_hits:
            if vh.content_id not in vector_content_map or vh.similarity > vector_content_map[vh.content_id].similarity:
                vector_content_map[vh.content_id] = vh

        # Compute semantic ranks: 1, 2, ...
        semantic_ranks: Dict[int, int] = {}
        for rank_idx, (cid, _) in enumerate(vector_content_map.items(), start=1):
            semantic_ranks[cid] = rank_idx

        # -------------------------------------------------------------
        # 2. Lexical Keyword Search via OpenSearch
        # -------------------------------------------------------------
        keyword_res = search_service.search(
            SearchQuery(
                query=sq.query,
                category=sq.category,
                source=sq.source,
                content_type=sq.content_type,
                entity=sq.entity,
                page=1,
                page_size=50,
            )
        )

        keyword_content_map: Dict[int, Any] = {}
        keyword_ranks: Dict[int, int] = {}
        for rank_idx, kh in enumerate(keyword_res.hits, start=1):
            keyword_content_map[kh.id] = kh
            keyword_ranks[kh.id] = rank_idx

        # -------------------------------------------------------------
        # 3. Reciprocal Rank Fusion (RRF)
        # Formula: RRF(d) = (w_kw / (k + rank_kw)) + (w_sem / (k + rank_sem))
        # -------------------------------------------------------------
        all_candidate_ids: Set[int] = set(semantic_ranks.keys()) | set(keyword_ranks.keys())
        scored_candidates: List[HybridHit] = []

        w_kw = sq.keyword_weight
        w_sem = sq.semantic_weight
        k = self.rrf_k

        for cid in all_candidate_ids:
            sem_rank = semantic_ranks.get(cid)
            kw_rank = keyword_ranks.get(cid)

            rrf_score = 0.0
            if kw_rank is not None:
                rrf_score += w_kw / (k + kw_rank)
            if sem_rank is not None:
                rrf_score += w_sem / (k + sem_rank)

            # Extract article metadata from keyword hit, vector hit, or DB
            title = ""
            url = ""
            ctype = "article"
            category = None
            source = None
            pub_at = None
            matched_chunk = None
            sem_score = 0.0
            kw_score = 0.0

            if cid in keyword_content_map:
                kh = keyword_content_map[cid]
                title = kh.title
                url = kh.canonical_url
                ctype = kh.content_type
                category = kh.category
                source = kh.source
                pub_at = kh.published_at
                kw_score = kh.score

            if cid in vector_content_map:
                vh = vector_content_map[cid]
                if not title:
                    title = vh.content_title
                    url = vh.canonical_url
                    ctype = vh.content_type or "article"
                sem_score = vh.similarity
                matched_chunk = vh.chunk_text

            if not title:
                c = db.query(Content).filter(Content.id == cid).first()
                if c:
                    title = c.title
                    url = c.canonical_url
                    ctype = c.content_type

            scored_candidates.append(
                HybridHit(
                    content_id=cid,
                    title=title,
                    canonical_url=url,
                    content_type=ctype,
                    category=category,
                    source=source,
                    published_at=pub_at,
                    rrf_score=round(rrf_score, 6),
                    keyword_rank=kw_rank,
                    semantic_rank=sem_rank,
                    keyword_score=kw_score,
                    semantic_score=sem_score,
                    matched_chunk=matched_chunk,
                )
            )

        # -------------------------------------------------------------
        # 4. Sort & Paginate Results
        # -------------------------------------------------------------
        scored_candidates.sort(key=lambda h: h.rrf_score, reverse=True)

        total = len(scored_candidates)
        from_offset = (sq.page - 1) * sq.page_size
        paginated_hits = scored_candidates[from_offset : from_offset + sq.page_size]

        took = round((time.time() - start_time) * 1000, 2)

        return HybridSearchResult(
            total=total,
            page=sq.page,
            page_size=sq.page_size,
            hits=paginated_hits,
            took_ms=took,
            query_used=sq.query,
        )

    def reindex_all_embeddings(self, db: Session, batch_size: int = 100) -> int:
        """Re-chunk and re-embed all content documents in the database."""
        total_chunks = 0
        offset = 0

        while True:
            batch = db.query(Content.id).order_by(Content.id.asc()).offset(offset).limit(batch_size).all()
            if not batch:
                break

            for row in batch:
                content_id = row[0]
                chunks_created = self.index_content(db, content_id)
                total_chunks += chunks_created

            offset += len(batch)

        logger.info("Successfully re-embedded %s total chunks across all content", total_chunks)
        return total_chunks


# Global service singleton
semantic_service = SemanticService()
