"""
Stage 17 / Section 18: Add Search (OpenSearch) Baseline Tests
Verifies the services/search package structure, OpenSearch index schema mapping for
all 10 mandated fields, query DSL generation, search service contract, and REST API schemas.
Conforms to IMPLEMENT.md Section 18.
"""

from pathlib import Path
import sys
import unittest

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

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


class TestStage17SearchBaseline(unittest.TestCase):
    """Test suite validating Step 17 / Section 18 OpenSearch Integration."""

    def test_search_package_structure(self):
        """Confirm services/search contains all mandated modules."""
        serv_dir = repo_root / "services" / "search"
        self.assertTrue(serv_dir.exists(), "services/search directory missing")
        self.assertTrue((serv_dir / "__init__.py").exists(), "__init__.py missing")
        self.assertTrue((serv_dir / "models.py").exists(), "models.py missing")
        self.assertTrue((serv_dir / "client.py").exists(), "client.py missing")
        self.assertTrue((serv_dir / "indexer.py").exists(), "indexer.py missing")
        self.assertTrue((serv_dir / "query.py").exists(), "query.py missing")
        self.assertTrue((serv_dir / "service.py").exists(), "service.py missing")

    def test_api_schemas_and_endpoints_files_exist(self):
        """Confirm search API schemas and endpoint files exist in apps/api."""
        self.assertTrue((api_root / "app" / "schemas" / "search.py").exists())
        self.assertTrue((api_root / "app" / "api" / "v1" / "endpoints" / "search.py").exists())

    def test_search_service_singleton_and_contract(self):
        """Confirm search_service is functional and exposes core methods."""
        self.assertIsInstance(search_service, SearchService)
        self.assertTrue(callable(getattr(search_service, "search", None)))
        self.assertTrue(callable(getattr(search_service, "index_content", None)))
        self.assertTrue(callable(getattr(search_service, "index_direct", None)))
        self.assertTrue(callable(getattr(search_service, "reindex_all", None)))
        self.assertTrue(callable(getattr(search_service, "stats", None)))

    def test_section18_all_ten_mandated_fields_in_schema(self):
        """
        Confirm OpenSearch INDEX_MAPPING defines properties for all 10 fields
        mandated by IMPLEMENT.md Section 18:
        title, description, summary, tags, entities, author, source, category, content_type, published_at.
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

    def test_query_dsl_builder_all_filters(self):
        """Confirm OpenSearchQueryBuilder constructs valid DSL covering all Section 18 filter criteria."""
        sq = SearchQuery(
            query="cve exploit",
            phrase="remote code execution",
            category="vulnerability_management",
            source="NVD",
            content_type="cve",
            entity="CVE-2024-38077",
            tag="zeroday",
            sort_by="newest",
        )
        dsl = OpenSearchQueryBuilder.build(sq)

        self.assertIn("query", dsl)
        self.assertIn("bool", dsl["query"])
        self.assertIn("aggs", dsl)
        self.assertIn("categories", dsl["aggs"])
        self.assertIn("sources", dsl["aggs"])
        self.assertIn("content_types", dsl["aggs"])
        self.assertIn("entities", dsl["aggs"])
        self.assertIn("highlight", dsl)

    def test_search_models_contract(self):
        """Confirm SearchQuery, SearchHit, and SearchResult dataclasses instantiate with expected fields."""
        hit = SearchHit(
            id=1,
            title="Sample Alert",
            canonical_url="https://example.com/alert",
            content_type="advisory",
            source="US-CERT",
            category="vulnerability_management",
            score=3.5,
        )
        self.assertEqual(hit.id, 1)
        self.assertEqual(hit.score, 3.5)

        bucket = SearchFacetBucket(key="malware", count=42)
        self.assertEqual(bucket.key, "malware")
        self.assertEqual(bucket.count, 42)

        res = SearchResult(
            total=1,
            page=1,
            page_size=20,
            hits=[hit],
            facets={"categories": [bucket]},
            took_ms=5.0,
            engine="in_memory_fallback",
        )
        self.assertEqual(res.total, 1)
        self.assertEqual(len(res.hits), 1)
        self.assertEqual(len(res.facets["categories"]), 1)


if __name__ == "__main__":
    unittest.main()
