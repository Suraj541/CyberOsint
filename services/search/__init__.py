"""
Services Search Package
Provides OpenSearch full-text querying, multi-field faceted search,
schema mappings, and automated content indexing.
Conforms to IMPLEMENT.md Section 18.
"""

from services.search.client import OpenSearchClient, opensearch_client
from services.search.indexer import (
    CYBER_OSINT_INDEX_NAME,
    INDEX_MAPPING,
    serialize_content_document,
)
from services.search.models import (
    SearchFacetBucket,
    SearchHit,
    SearchQuery,
    SearchResult,
)
from services.search.query import OpenSearchQueryBuilder
from services.search.service import SearchService, search_service

__all__ = [
    "SearchService",
    "search_service",
    "OpenSearchClient",
    "opensearch_client",
    "OpenSearchQueryBuilder",
    "SearchQuery",
    "SearchHit",
    "SearchResult",
    "SearchFacetBucket",
    "serialize_content_document",
    "INDEX_MAPPING",
    "CYBER_OSINT_INDEX_NAME",
]
