"""
Tests for Subsystem 7: Search (OpenSearch).
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing) and Section 18.
Validates OpenSearch index mapping for all 10 mandated fields, Query DSL generation,
SearchService contract, facet aggregations, and in-memory search fallback.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.search import (
    CYBER_OSINT_INDEX_NAME,
    INDEX_MAPPING,
    OpenSearchClient,
    OpenSearchQueryBuilder,
    SearchFacetBucket,
    SearchHit,
    SearchQuery,
    SearchResult,
    SearchService,
    search_service,
    serialize_content_document,
)


class TestSearchSubsystem(unittest.TestCase):
    """Subsystem 7: Search Unit Tests."""

    def test_01_all_ten_mandated_fields_in_index_mapping(self):
        """
        Verify OpenSearch index schema mapping includes all 10 fields mandated
        by IMPLEMENT.md Section 18: title, description, summary, tags, entities,
        author, source, category, content_type, published_at.
        """
        properties = INDEX_MAPPING["mappings"]["properties"]
        mandated_fields = [
            "title",
            "description",
            "summary",
            "tags",
            "entities",
            "author",
            "source",
            "category",
            "content_type",
            "published_at",
        ]
        for field in mandated_fields:
            self.assertIn(field, properties, f"Mandated field '{field}' not found in OpenSearch mapping")
        self.assertEqual(CYBER_OSINT_INDEX_NAME, "cyber_osint_content")

    def test_02_query_dsl_builder_construction(self):
        """Verify OpenSearchQueryBuilder produces valid query DSL with bool filters and aggregations."""
        query_obj = SearchQuery(
            query="cve buffer overflow",
            phrase="remote code execution",
            category="vulnerability_management",
            source="NVD",
            content_type="cve",
            tag="zeroday",
            sort_by="newest",
        )
        dsl = OpenSearchQueryBuilder.build(query_obj)
        self.assertIn("query", dsl)
        self.assertIn("bool", dsl["query"])
        self.assertIn("aggs", dsl)
        self.assertIn("categories", dsl["aggs"])
        self.assertIn("sources", dsl["aggs"])
        self.assertIn("highlight", dsl)

    def test_03_search_models_contract(self):
        """Verify SearchHit, SearchFacetBucket, and SearchResult models."""
        hit = SearchHit(
            id=42,
            title="Palo Alto Networks Advisory",
            canonical_url="https://security.paloaltonetworks.com/PAN-SA-2024-0001",
            content_type="advisory",
            source="Palo Alto",
            category="vulnerability_management",
            score=2.8,
        )
        self.assertEqual(hit.id, 42)
        self.assertEqual(hit.score, 2.8)

        bucket = SearchFacetBucket(key="vulnerability_management", count=15)
        self.assertEqual(bucket.key, "vulnerability_management")
        self.assertEqual(bucket.count, 15)

        res = SearchResult(
            total=1,
            page=1,
            page_size=20,
            hits=[hit],
            facets={"categories": [bucket]},
            took_ms=3.2,
            engine="in_memory_fallback",
        )
        self.assertEqual(res.total, 1)
        self.assertEqual(len(res.hits), 1)

    def test_04_search_service_singleton_and_contract(self):
        """Verify SearchService singleton methods."""
        self.assertIsInstance(search_service, SearchService)
        self.assertTrue(callable(getattr(search_service, "search", None)))
        self.assertTrue(callable(getattr(search_service, "index_direct", None)))
        self.assertTrue(callable(getattr(search_service, "stats", None)))

    def test_05_in_memory_indexing_and_search_fallback(self):
        """Verify indexing documents and querying via search_service fallback."""
        doc = {
            "id": 999,
            "title": "Ivanti Connect Secure Zero-Day Exploit",
            "description": "Exploit chain CVE-2023-46805 and CVE-2024-21887 observed active in wild.",
            "canonical_url": "https://ivanti.com/advisory/999",
            "content_type": "advisory",
            "source": "Ivanti",
            "category": "vulnerability_management",
            "author": "Ivanti PSIRT",
            "published_at": "2026-09-17T12:00:00Z",
            "tags": ["ivanti", "vpn", "zeroday"],
            "entities": [{"name": "CVE-2023-46805", "entity_type": "cve"}],
        }
        search_service.index_direct(doc)
        res = search_service.search(SearchQuery(query="Ivanti Connect Secure"))
        self.assertGreaterEqual(res.total, 1)
        matching_hits = [h for h in res.hits if h.id == 999]
        self.assertTrue(len(matching_hits) >= 1)


if __name__ == "__main__":
    unittest.main()
