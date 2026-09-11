"""
Search Service Orchestrator
High-level service coordinating querying, indexing, and statistics
between database storage and the search engine.
Conforms to IMPLEMENT.md Section 18.
"""

import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.content import Content
from services.search.client import OpenSearchClient, opensearch_client
from services.search.indexer import serialize_content_document
from services.search.models import SearchFacetBucket, SearchHit, SearchQuery, SearchResult
from services.search.query import OpenSearchQueryBuilder

logger = logging.getLogger("cyber_osint.services.search.service")


class SearchService:
    """
    Coordinates full-text search, facet aggregations, and automatic content indexing.
    Conforms to IMPLEMENT.md Section 18.
    """

    def __init__(self, client: Optional[OpenSearchClient] = None):
        self.client = client or opensearch_client

    def search(self, sq: SearchQuery) -> SearchResult:
        """
        Execute structured SearchQuery against OpenSearch and return formatted SearchResult.
        """
        query_dsl = OpenSearchQueryBuilder.build(sq)
        raw_res = self.client.search(query_dsl)

        # Parse hits
        hits_data = raw_res.get("hits", {})
        total_hits = hits_data.get("total", {}).get("value", 0)
        raw_hit_list = hits_data.get("hits", [])

        search_hits: List[SearchHit] = []
        for rh in raw_hit_list:
            src = rh.get("_source", {})
            search_hits.append(
                SearchHit(
                    id=src.get("id") or int(rh.get("_id", 0)),
                    title=src.get("title", ""),
                    canonical_url=src.get("canonical_url", ""),
                    content_type=src.get("content_type", "article"),
                    description=src.get("description"),
                    summary=src.get("summary"),
                    source=src.get("source"),
                    category=src.get("category"),
                    author=src.get("author"),
                    published_at=src.get("published_at"),
                    tags=src.get("tags", []),
                    entities=src.get("entities", []),
                    score=float(rh.get("_score", 1.0)),
                    highlights=rh.get("highlight", {}),
                )
            )

        # Parse facets from aggregations
        facets: Dict[str, List[SearchFacetBucket]] = {}
        for agg_name, agg_data in raw_res.get("aggregations", {}).items():
            buckets = agg_data.get("buckets", [])
            facets[agg_name] = [
                SearchFacetBucket(key=b["key"], count=b["doc_count"]) for b in buckets
            ]

        engine_type = "opensearch" if self.client.ping() else "in_memory_fallback"

        return SearchResult(
            total=total_hits,
            page=sq.page,
            page_size=sq.page_size,
            hits=search_hits,
            facets=facets,
            took_ms=float(raw_res.get("took", 0)),
            query_used=sq.query or sq.phrase,
            engine=engine_type,
        )

    def index_content(
        self,
        db: Session,
        content_id: int,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        entities: Optional[List[Dict[str, Any]]] = None,
    ) -> bool:
        """
        Extract Content record from DB, serialize with metadata, and index.
        """
        try:
            content = db.query(Content).filter(Content.id == content_id).first()
            if not content:
                logger.warning("Content id=%s not found for search indexing", content_id)
                return False

            doc = serialize_content_document(
                content=content,
                category=category,
                tags=tags,
                entities=entities,
            )
            return self.client.index_document(content.id, doc)
        except Exception as exc:
            logger.error("Failed to index content id=%s: %s", content_id, exc)
            return False

    def index_direct(self, doc: Dict[str, Any]) -> bool:
        """Index pre-serialized document dictionary directly."""
        doc_id = doc.get("id", 0)
        return self.client.index_document(doc_id, doc)

    def reindex_all(self, db: Session, batch_size: int = 100) -> int:
        """Reindex all content records in the database."""
        total_indexed = 0
        offset = 0

        while True:
            batch = db.query(Content).order_by(Content.id.asc()).offset(offset).limit(batch_size).all()
            if not batch:
                break

            docs = [serialize_content_document(item) for item in batch]
            indexed_count = self.client.bulk_index(docs)
            total_indexed += indexed_count
            offset += len(batch)

        logger.info("Successfully reindexed %s content items into search index", total_indexed)
        return total_indexed

    def stats(self) -> Dict[str, Any]:
        """Return search index health and statistics."""
        return self.client.stats()


# Global service singleton
search_service = SearchService()
