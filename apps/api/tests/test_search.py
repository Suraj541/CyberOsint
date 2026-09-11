"""
Unit & Integration Tests for OpenSearch Full-Text & Faceted Search Service
Conforms strictly to IMPLEMENT.md Section 18.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import unittest

api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from app.models.tag import ContentTag, Tag
from connectors.base import BaseConnector, NormalizedItem
from services.ingestion.pipeline import IngestionPipeline
from services.search import (
    CYBER_OSINT_INDEX_NAME,
    INDEX_MAPPING,
    OpenSearchClient,
    OpenSearchQueryBuilder,
    SearchFacetBucket,
    SearchHit,
    SearchQuery,
    SearchResult,
    search_service,
    serialize_content_document,
)


class TestSearchServiceAndEndpoints(unittest.TestCase):
    """Test suite validating OpenSearch indexing, querying, and REST endpoints."""

    def setUp(self):
        # Create an isolated in-memory SQLite database for test session
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db: Session = self.SessionLocal()

        # Override dependency
        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

        # Clear search service in-memory store before each test
        search_service.client.clear_in_memory_index()

    def tearDown(self):
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        search_service.client.clear_in_memory_index()

    # -----------------------------------------------------------------
    # 1. Schema Mapping & Serialization Tests
    # -----------------------------------------------------------------
    def test_schema_mapping_contains_ten_mandated_fields(self):
        """Confirm INDEX_MAPPING defines properties for all 10 mandated Section 18 fields."""
        props = INDEX_MAPPING["mappings"]["properties"]
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
        for f in mandated_fields:
            self.assertIn(f, props, f"Mandated search field {f} missing in mapping")

    def test_serialize_content_document_fields(self):
        """Confirm serialize_content_document populates all search attributes."""
        source = Source(name="CISA Alerts", url="https://cisa.gov", source_type="cert")
        self.db.add(source)
        self.db.commit()

        content = Content(
            source_id=source.id,
            title="Active Exploitation of PAN-OS Zero-Day Vulnerability",
            description="Threat actors leverage remote code execution flaw in PAN-OS appliances.",
            summary="CISA urges immediate patching of PAN-OS devices.",
            canonical_url="https://cisa.gov/advisories/aa24-001",
            content_type="advisory",
            author="CISA Threat Intel",
            published_at=datetime(2024, 8, 15, 12, 0, 0, tzinfo=timezone.utc),
            content_hash="hash123",
        )
        self.db.add(content)
        self.db.commit()

        doc = serialize_content_document(
            content=content,
            category="vulnerability_management",
            tags=["pan-os", "zero-day", "firewall"],
            entities=[{"entity_type": "cve", "name": "CVE-2024-3400", "normalized_name": "CVE-2024-3400"}],
        )

        self.assertEqual(doc["id"], content.id)
        self.assertEqual(doc["title"], content.title)
        self.assertEqual(doc["source"], "CISA Alerts")
        self.assertEqual(doc["category"], "vulnerability_management")
        self.assertEqual(doc["content_type"], "advisory")
        self.assertIn("zero-day", doc["tags"])
        self.assertEqual(len(doc["entities"]), 1)
        self.assertEqual(doc["entities"][0]["normalized_name"], "CVE-2024-3400")

    # -----------------------------------------------------------------
    # 2. Query Builder DSL Tests
    # -----------------------------------------------------------------
    def test_query_builder_dsl_construction(self):
        """Confirm OpenSearchQueryBuilder constructs valid DSL with filters and aggs."""
        sq = SearchQuery(
            query="ransomware attack",
            category="malware",
            source="ThreatPost",
            content_type="article",
            entity="LockBit",
            date_from=datetime(2024, 1, 1),
            date_to=datetime(2024, 12, 31),
            page=2,
            page_size=15,
            sort_by="newest",
        )
        dsl = OpenSearchQueryBuilder.build(sq)

        self.assertEqual(dsl["from"], 15)
        self.assertEqual(dsl["size"], 15)
        self.assertIn("query", dsl)
        self.assertIn("bool", dsl["query"])
        self.assertIn("must", dsl["query"]["bool"])
        self.assertIn("filter", dsl["query"]["bool"])

        # Check multi_match query
        must = dsl["query"]["bool"]["must"][0]
        self.assertEqual(must["multi_match"]["query"], "ransomware attack")

        # Check filter terms
        filters = dsl["query"]["bool"]["filter"]
        terms = [list(f.get("term", {}).keys())[0] for f in filters if "term" in f]
        self.assertIn("category", terms)
        self.assertIn("source", terms)
        self.assertIn("content_type", terms)

        # Check aggregations
        self.assertIn("categories", dsl["aggs"])
        self.assertIn("sources", dsl["aggs"])
        self.assertIn("entities", dsl["aggs"])

    def test_query_builder_phrase_match(self):
        """Confirm phrase query creates phrase multi_match."""
        sq = SearchQuery(phrase="supply chain compromise")
        dsl = OpenSearchQueryBuilder.build(sq)
        must = dsl["query"]["bool"]["must"][0]
        self.assertEqual(must["multi_match"]["type"], "phrase")
        self.assertEqual(must["multi_match"]["query"], "supply chain compromise")

    # -----------------------------------------------------------------
    # 3. In-Memory Search Engine & Filtering Tests
    # -----------------------------------------------------------------
    def test_search_by_keyword_and_scoring(self):
        """Confirm keyword search ranks document with title match higher than description match."""
        doc1 = {
            "id": 1,
            "title": "LockBit Ransomware Disrupts Hospital Networks",
            "description": "General incident report.",
            "summary": "Healthcare sector impacted.",
            "category": "malware",
            "source": "SecurityWeek",
            "content_type": "article",
            "published_at": "2024-05-10T10:00:00",
            "tags": ["ransomware", "lockbit"],
            "entities": [{"name": "LockBit", "normalized_name": "lockbit", "entity_type": "malware"}],
        }
        doc2 = {
            "id": 2,
            "title": "Quarterly Threat Trends",
            "description": "Adversaries were observed deploying LockBit ransomware tools.",
            "summary": "Quarterly overview.",
            "category": "threat_intelligence",
            "source": "DarkReading",
            "content_type": "report",
            "published_at": "2024-05-09T10:00:00",
            "tags": ["trends"],
            "entities": [],
        }

        search_service.index_direct(doc1)
        search_service.index_direct(doc2)

        sq = SearchQuery(query="LockBit")
        res = search_service.search(sq)

        self.assertEqual(res.total, 2)
        # Doc 1 has "LockBit" in title (+3.0) and entities (+2.5), should score higher than Doc 2
        self.assertEqual(res.hits[0].id, 1)
        self.assertGreater(res.hits[0].score, res.hits[1].score)

    def test_search_by_exact_phrase(self):
        """Confirm exact phrase search matches only contiguous phrases."""
        doc1 = {
            "id": 10,
            "title": "Critical Remote Code Execution Disclosed",
            "description": "Flaw allows arbitrary command injection.",
            "canonical_url": "https://example.com/10",
        }
        doc2 = {
            "id": 11,
            "title": "Remote Servers Under Attack With Malicious Code Execution",
            "description": "Dispersed words without contiguous phrase.",
            "canonical_url": "https://example.com/11",
        }

        search_service.index_direct(doc1)
        search_service.index_direct(doc2)

        # Exact contiguous phrase
        sq = SearchQuery(phrase="Remote Code Execution")
        res = search_service.search(sq)
        self.assertEqual(res.total, 1)
        self.assertEqual(res.hits[0].id, 10)

    def test_search_filters_category_source_and_entity(self):
        """Confirm multiple filter constraints restrict returned documents."""
        docs = [
            {
                "id": 20,
                "title": "Volt Typhoon Targets Water Infrastructure",
                "category": "threat_intelligence",
                "source": "CISA",
                "content_type": "advisory",
                "entities": [{"name": "Volt Typhoon", "normalized_name": "volt typhoon", "entity_type": "threat_actor"}],
            },
            {
                "id": 21,
                "title": "Volt Typhoon Steals Cloud Credentials",
                "category": "cloud_security",
                "source": "Microsoft",
                "content_type": "article",
                "entities": [{"name": "Volt Typhoon", "normalized_name": "volt typhoon", "entity_type": "threat_actor"}],
            },
            {
                "id": 22,
                "title": "Generic Cloud Security Best Practices",
                "category": "cloud_security",
                "source": "AWS",
                "content_type": "article",
                "entities": [],
            },
        ]
        for d in docs:
            search_service.index_direct(d)

        # Filter by category and entity
        sq = SearchQuery(category="cloud_security", entity="volt typhoon")
        res = search_service.search(sq)
        self.assertEqual(res.total, 1)
        self.assertEqual(res.hits[0].id, 21)

        # Verify faceted aggregation counts
        all_res = search_service.search(SearchQuery())
        self.assertIn("categories", all_res.facets)
        cat_keys = {b.key: b.count for b in all_res.facets["categories"]}
        self.assertEqual(cat_keys.get("cloud_security"), 2)
        self.assertEqual(cat_keys.get("threat_intelligence"), 1)

    # -----------------------------------------------------------------
    # 4. Ingestion Pipeline Search Hook Integration
    # -----------------------------------------------------------------
    def test_ingestion_pipeline_auto_indexes_content(self):
        """Confirm that items ingested through IngestionPipeline are automatically searchable."""
        class SearchTestConnector(BaseConnector):
            def discover(self):
                return [{"title": "Kernel Exploit CVE-2024-99999", "link": "https://sec.example/kernel-exploit"}]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title=parsed["title"],
                    url=parsed["link"],
                    source="KernelFeed",
                    content_type="advisory",
                    description="Privilege escalation in Linux kernel eBPF subsystem.",
                    raw_content="Exploiting CVE-2024-99999 allows local root privileges via eBPF.",
                )
            def health_check(self):
                pass

        connector = SearchTestConnector(source_config={"name": "KernelFeed"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="KernelFeed")

        self.assertEqual(metrics.ingested_count, 1)

        # Search immediately for the ingested content
        res = search_service.search(SearchQuery(query="eBPF"))
        self.assertEqual(res.total, 1)
        self.assertIn("Kernel Exploit", res.hits[0].title)

    # -----------------------------------------------------------------
    # 5. REST API Endpoints Tests
    # -----------------------------------------------------------------
    def test_api_get_search_endpoint(self):
        """Verify GET /api/v1/search endpoint returns expected JSON envelope."""
        doc = {
            "id": 101,
            "title": "SaltStack Vulnerability Disclosed by Researchers",
            "description": "Authentication bypass in Salt master daemon.",
            "canonical_url": "https://salt.example/vuln",
            "category": "application_security",
            "source": "BleepingComputer",
            "content_type": "article",
            "tags": ["saltstack", "auth_bypass"],
        }
        search_service.index_direct(doc)

        response = self.client.get("/api/v1/search?q=SaltStack&category=application_security")
        self.assertEqual(response.status_code, 200)
        data = response.json()

        self.assertEqual(data["total"], 1)
        self.assertEqual(data["hits"][0]["id"], 101)
        self.assertEqual(data["hits"][0]["title"], doc["title"])
        self.assertIn("categories", data["facets"])

    def test_api_post_search_endpoint(self):
        """Verify POST /api/v1/search endpoint with complex filter payload."""
        doc = {
            "id": 102,
            "title": "Apache HTTP Server Path Traversal",
            "canonical_url": "https://apache.example/cve",
            "category": "application_security",
            "source": "Apache",
            "content_type": "advisory",
        }
        search_service.index_direct(doc)

        payload = {
            "q": "Apache",
            "category": "application_security",
            "content_type": "advisory",
            "page": 1,
            "page_size": 10,
        }
        response = self.client.post("/api/v1/search", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["hits"][0]["id"], 102)

    def test_api_top_level_alias_endpoint(self):
        """Verify Section 18 top-level alias GET /api/search works identically."""
        doc = {
            "id": 103,
            "title": "DarkGate Loader Malware Campaign",
            "canonical_url": "https://malware.example/darkgate",
            "category": "malware",
        }
        search_service.index_direct(doc)

        response = self.client.get("/api/search?q=DarkGate")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["hits"][0]["id"], 103)

    def test_api_search_stats_endpoint(self):
        """Verify GET /api/v1/search/stats reports health and document counts."""
        doc = {"id": 104, "title": "Test Stat Article", "canonical_url": "https://test.example/stat"}
        search_service.index_direct(doc)

        response = self.client.get("/api/v1/search/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("document_count", data)
        self.assertGreaterEqual(data["document_count"], 1)
        self.assertIn("status", data)
        self.assertEqual(data["index_name"], CYBER_OSINT_INDEX_NAME)

    def test_api_reindex_endpoint(self):
        """Verify POST /api/v1/search/reindex repopulates search index from PostgreSQL."""
        c1 = Content(title="Content Item 1", canonical_url="https://sec.example/1", content_hash="h1")
        c2 = Content(title="Content Item 2", canonical_url="https://sec.example/2", content_hash="h2")
        self.db.add_all([c1, c2])
        self.db.commit()

        # Clear search index
        search_service.client.clear_in_memory_index()
        self.assertEqual(search_service.stats()["document_count"], 0)

        # Trigger reindex
        response = self.client.post("/api/v1/search/reindex")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "completed")
        self.assertEqual(data["indexed_count"], 2)

        # Confirm documents are in search index
        self.assertEqual(search_service.stats()["document_count"], 2)


if __name__ == "__main__":
    unittest.main()
