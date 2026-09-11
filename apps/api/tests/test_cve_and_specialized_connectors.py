"""
Specialized Threat Intelligence Connectors & Entity Extraction Tests
Tests CVEConnector (CISA KEV & NVD 2.0), GitHubSecurityConnector (GHSA), CERTConnector,
SSRF preflight enforcement, automated Entity & ContentEntity database linking,
regex CVE extraction, and the /api/v1/entities REST endpoints.
Conforms strictly to IMPLEMENT.md Section 12 & Section 13.
"""

from datetime import datetime, timezone
import json
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from connectors.base import BaseConnector, NormalizedItem
from connectors.cert.connector import CERTConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError
from services.ingestion.pipeline import IngestionPipeline


class TestSpecializedConnectorsAndEntities(unittest.TestCase):
    """Test suite for CVE, GitHub, and CERT connectors with entity linking."""

    def setUp(self):
        """Set up an isolated in-memory SQLite database for test runs."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up in-memory database and dependency overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        app.dependency_overrides.clear()

    # -------------------------------------------------------------
    # 1. CISA KEV Ingestion Tests
    # -------------------------------------------------------------
    def test_cisa_kev_parsing_and_normalization(self):
        """Confirm CVEConnector correctly ingests and normalizes CISA KEV JSON payloads."""
        kev_payload = {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-38077",
                    "vendorProject": "Microsoft",
                    "product": "Windows Server",
                    "vulnerabilityName": "Microsoft Windows Remote Desktop Licensing Service RCE",
                    "dateAdded": "2024-07-09",
                    "shortDescription": "Microsoft Windows Remote Desktop Licensing Service contains an unspecified heap-based buffer overflow flaw.",
                    "requiredAction": "Apply mitigations per vendor instructions.",
                    "dueDate": "2024-07-30",
                    "knownRansomwareCampaignUse": "Known",
                    "notes": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38077",
                    "cwes": ["CWE-122"],
                }
            ],
        }

        connector = CVEConnector(
            source_config={
                "name": "CISA KEV Test Feed",
                "feed_content": json.dumps(kev_payload),
            }
        )

        entries = connector.discover()
        self.assertEqual(len(entries), 1)

        raw = connector.fetch(entries[0])
        parsed = connector.parse(raw)
        self.assertEqual(parsed["cve_id"], "CVE-2024-38077")
        self.assertEqual(parsed["vendor"], "Microsoft")
        self.assertEqual(parsed["product"], "Windows Server")
        self.assertEqual(parsed["severity"], "CRITICAL")
        self.assertEqual(parsed["cvss_score"], 9.0)
        self.assertEqual(parsed["weakness"], "CWE-122")

        normalized = connector.normalize(parsed)
        self.assertIsInstance(normalized, NormalizedItem)
        self.assertIn("CVE-2024-38077", normalized.title)
        self.assertEqual(normalized.content_type, "cve")
        self.assertIn("CVE", normalized.metadata["tags"])

        # Check structured entities for linking
        entities = normalized.metadata["entities"]
        cve_ent = next((e for e in entities if e["type"] == "cve"), None)
        self.assertIsNotNone(cve_ent)
        self.assertEqual(cve_ent["name"], "CVE-2024-38077")
        self.assertEqual(cve_ent["metadata"]["cvss_score"], 9.0)

        product_ent = next((e for e in entities if e["type"] == "product"), None)
        self.assertIsNotNone(product_ent)
        self.assertEqual(product_ent["name"], "Windows Server")

    # -------------------------------------------------------------
    # 2. NVD CVE API 2.0 Ingestion Tests
    # -------------------------------------------------------------
    def test_nvd_cve_api2_parsing_and_normalization(self):
        """Confirm CVEConnector parses official NVD API 2.0 JSON schema."""
        nvd_payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-44487",
                        "published": "2023-10-10T14:15:10.000",
                        "descriptions": [
                            {"lang": "en", "value": "The HTTP/2 protocol allows a denial of service (server reset stream rapid reset attack)."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "version": "3.1",
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                        "weaknesses": [
                            {
                                "description": [{"lang": "en", "value": "CWE-400"}]
                            }
                        ],
                        "references": [
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487"}
                        ],
                    }
                }
            ]
        }

        connector = CVEConnector(
            source_config={
                "name": "NVD API 2.0 Test Feed",
                "feed_content": json.dumps(nvd_payload),
            }
        )

        entries = connector.discover()
        self.assertEqual(len(entries), 1)

        parsed = connector.parse(connector.fetch(entries[0]))
        self.assertEqual(parsed["cve_id"], "CVE-2023-44487")
        self.assertEqual(parsed["cvss_score"], 7.5)
        self.assertEqual(parsed["severity"], "HIGH")
        self.assertEqual(parsed["weakness"], "CWE-400")

        normalized = connector.normalize(parsed)
        self.assertEqual(normalized.metadata["cvss_score"], 7.5)
        self.assertEqual(normalized.metadata["severity"], "HIGH")

    # -------------------------------------------------------------
    # 3. GitHub Security Advisories Ingestion Tests
    # -------------------------------------------------------------
    def test_github_security_connector_parsing_and_normalization(self):
        """Confirm GitHubSecurityConnector parses GHSA payloads, CVSS, and affected packages."""
        ghsa_payload = [
            {
                "ghsa_id": "GHSA-7rjr-3q55-vv33",
                "cve_id": "CVE-2024-21626",
                "summary": "runc Leaky file descriptor vulnerability allows container breakout",
                "description": "In runc through 1.1.11, as used in Docker Engine before 25.0.2, improper file descriptor management allows container breakout.",
                "severity": "critical",
                "cvss": {"score": 8.6, "vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H"},
                "vulnerabilities": [
                    {"package": {"ecosystem": "Go", "name": "github.com/opencontainers/runc"}}
                ],
                "references": [
                    {"url": "https://github.com/opencontainers/runc/security/advisories/GHSA-7rjr-3q55-vv33"}
                ],
                "published_at": "2024-01-31T22:00:00Z",
            }
        ]

        connector = GitHubSecurityConnector(
            source_config={
                "name": "GHSA In-Memory Feed",
                "feed_content": json.dumps(ghsa_payload),
            }
        )

        entries = connector.discover()
        self.assertEqual(len(entries), 1)

        parsed = connector.parse(connector.fetch(entries[0]))
        self.assertEqual(parsed["ghsa_id"], "GHSA-7rjr-3q55-vv33")
        self.assertEqual(parsed["cve_id"], "CVE-2024-21626")
        self.assertEqual(parsed["severity"], "CRITICAL")
        self.assertEqual(parsed["cvss_score"], 8.6)
        self.assertIn("Go:github.com/opencontainers/runc", parsed["affected_packages"])

        normalized = connector.normalize(parsed)
        self.assertEqual(normalized.content_type, "advisory")
        self.assertIn("GHSA", normalized.metadata["tags"])
        self.assertIn("CVE-2024-21626", normalized.metadata["tags"])

        # Check structured entities
        entities = normalized.metadata["entities"]
        ghsa_ent = next((e for e in entities if e["type"] == "advisory"), None)
        self.assertIsNotNone(ghsa_ent)
        self.assertEqual(ghsa_ent["name"], "GHSA-7rjr-3q55-vv33")

        cve_ent = next((e for e in entities if e["type"] == "cve"), None)
        self.assertIsNotNone(cve_ent)
        self.assertEqual(cve_ent["name"], "CVE-2024-21626")

    # -------------------------------------------------------------
    # 4. CERT / CSIRT Advisories Ingestion Tests
    # -------------------------------------------------------------
    def test_cert_connector_parsing_and_normalization(self):
        """Confirm CERTConnector parses operational alerts and extracts referenced CVEs."""
        cert_payload = [
            {
                "alert_id": "AA24-207A",
                "title": "CISA and FBI Release Advisory on PRC State-Sponsored Cyber Actors",
                "description": "PRC state-sponsored cyber actors are actively exploiting CVE-2024-3400 and CVE-2024-21887 in perimeter edge network appliances.",
                "severity": "HIGH",
                "affected_systems": ["Palo Alto PAN-OS", "Ivanti Connect Secure"],
                "published_at": "2024-07-25T18:00:00Z",
                "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a",
            }
        ]

        connector = CERTConnector(
            source_config={
                "name": "CISA Advisory Feed",
                "feed_content": json.dumps(cert_payload),
            }
        )

        entries = connector.discover()
        self.assertEqual(len(entries), 1)

        parsed = connector.parse(connector.fetch(entries[0]))
        self.assertEqual(parsed["alert_id"], "AA24-207A")
        self.assertIn("CVE-2024-3400", parsed["referenced_cves"])
        self.assertIn("CVE-2024-21887", parsed["referenced_cves"])

        normalized = connector.normalize(parsed)
        self.assertEqual(normalized.content_type, "advisory")
        self.assertIn("CERT", normalized.metadata["tags"])
        self.assertIn("CVE-2024-3400", normalized.metadata["tags"])

        entities = normalized.metadata["entities"]
        cve_names = [e["name"] for e in entities if e["type"] == "cve"]
        self.assertIn("CVE-2024-3400", cve_names)
        self.assertIn("CVE-2024-21887", cve_names)

    # -------------------------------------------------------------
    # 5. SSRF Security Defense Tests
    # -------------------------------------------------------------
    def test_ssrf_protection_across_specialized_connectors(self):
        """Confirm all specialized connectors reject dangerous internal IP endpoints."""
        malicious_urls = [
            "http://127.0.0.1:8000/internal",
            "http://169.254.169.254/latest/meta-data",
            "http://192.168.1.1/admin",
        ]

        connectors = [
            CVEConnector({"name": "Bad CVE", "url": malicious_urls[0]}),
            GitHubSecurityConnector({"name": "Bad GitHub", "url": malicious_urls[1]}),
            CERTConnector({"name": "Bad CERT", "url": malicious_urls[2]}),
        ]

        for conn in connectors:
            # discover() should raise SSRFSecurityError
            with self.assertRaises(SSRFSecurityError):
                conn.discover()

            # health_check() should return status="failing" with SSRF details
            health = conn.health_check()
            self.assertEqual(health.status, "failing")
            self.assertIn("SSRF violation", health.error_message)

    # -------------------------------------------------------------
    # 6. Pipeline Entity & ContentEntity Database Linking Tests
    # -------------------------------------------------------------
    def test_ingestion_pipeline_structured_entity_linking(self):
        """Confirm IngestionPipeline persists structured entities and links them to ContentEntity."""
        kev_payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-38077",
                    "vendorProject": "Microsoft",
                    "product": "Windows Server",
                    "vulnerabilityName": "Windows Remote Desktop Licensing RCE",
                    "shortDescription": "Heap-based buffer overflow flaw in RD Licensing.",
                    "knownRansomwareCampaignUse": "Known",
                    "cwes": ["CWE-122"],
                }
            ]
        }

        source = Source(
            name="CISA KEV Official",
            url="https://www.cisa.gov/feeds/kev.json",
            source_type="cve",
            category="vulnerabilities",
            active=True,
        )
        self.db.add(source)
        self.db.commit()

        connector = CVEConnector(
            source_config={
                "id": source.id,
                "name": source.name,
                "feed_content": json.dumps(kev_payload),
            }
        )

        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_id=source.id, source_name=source.name)

        self.assertEqual(metrics.ingested_count, 1)

        # Verify Content row
        content = self.db.query(Content).first()
        self.assertIsNotNone(content)
        self.assertEqual(content.content_type, "cve")

        # Verify Entity table entries
        entities = self.db.query(Entity).all()
        ent_map = {e.entity_type: e for e in entities}
        self.assertIn("cve", ent_map)
        self.assertIn("product", ent_map)
        self.assertIn("cwe", ent_map)

        cve_entity = ent_map["cve"]
        self.assertEqual(cve_entity.normalized_name, "CVE-2024-38077")
        parsed_meta = json.loads(cve_entity.metadata_json)
        self.assertEqual(parsed_meta["cvss_score"], 9.0)
        self.assertEqual(parsed_meta["severity"], "CRITICAL")

        # Verify ContentEntity link associations
        content_links = self.db.query(ContentEntity).filter(ContentEntity.content_id == content.id).all()
        self.assertGreaterEqual(len(content_links), 3)

        linked_ent_ids = [cl.entity_id for cl in content_links]
        self.assertIn(cve_entity.id, linked_ent_ids)

        cve_link = next(cl for cl in content_links if cl.entity_id == cve_entity.id)
        self.assertEqual(cve_link.confidence, 1.0)
        self.assertEqual(cve_link.extraction_method, "structured")

    def test_ingestion_pipeline_regex_cve_extraction_from_article(self):
        """Confirm IngestionPipeline scans plain text articles and automatically links detected CVEs."""
        class DummyBlogConnector(BaseConnector):
            def discover(self):
                return [{"id": 1}]
            def fetch(self, item):
                return item
            def parse(self, raw):
                return raw
            def normalize(self, parsed):
                return NormalizedItem(
                    title="Critical Alert: Attackers exploiting CVE-2024-99999 in the wild",
                    url="https://threatpost.example/alert-cve-2024-99999",
                    description="Security researchers observed active exploitation of CVE-2024-99999 bypassing authentication.",
                    author="Threat Researcher",
                    published_at="2024-08-01T10:00:00Z",
                    source="ThreatPost",
                    content_type="article",
                    raw_content="Exploiting CVE-2024-99999 allows unauthorized admin access.",
                    metadata={},
                )
            def health_check(self):
                pass

        connector = DummyBlogConnector(source_config={"name": "Threat Blog"})
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="Threat Blog")

        self.assertEqual(metrics.ingested_count, 1)

        # Check that CVE-2024-99999 was extracted into Entity table
        cve_ent = self.db.query(Entity).filter(Entity.normalized_name == "CVE-2024-99999").first()
        self.assertIsNotNone(cve_ent)
        self.assertEqual(cve_ent.entity_type, "cve")

        # Check ContentEntity association
        link = self.db.query(ContentEntity).filter(ContentEntity.entity_id == cve_ent.id).first()
        self.assertIsNotNone(link)
        self.assertEqual(link.confidence, 0.9)
        self.assertEqual(link.extraction_method, "regex")

    # -------------------------------------------------------------
    # 7. Entity REST Endpoints Tests
    # -------------------------------------------------------------
    def test_entities_rest_api_endpoints(self):
        """Confirm /api/v1/entities REST endpoints support listing, filtering, detail, and CVE lookup."""
        # Seed test entities and content
        cve_ent = Entity(
            name="CVE-2024-38077",
            entity_type="cve",
            normalized_name="CVE-2024-38077",
            description="Windows Remote Desktop Licensing RCE",
            metadata_json=json.dumps({"cvss_score": 9.8, "severity": "CRITICAL"}),
        )
        prod_ent = Entity(
            name="Windows Server",
            entity_type="product",
            normalized_name="windows server",
            description="Server operating system",
            metadata_json=json.dumps({"vendor": "Microsoft"}),
        )
        self.db.add_all([cve_ent, prod_ent])
        self.db.flush()

        content = Content(
            title="Microsoft Releases Security Update for CVE-2024-38077",
            description="Emergency security bulletin addressing CVE-2024-38077.",
            content_type="advisory",
            canonical_url="https://msrc.microsoft.com/cve-2024-38077",
            content_hash="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abc1",
            status="discovered",
        )
        self.db.add(content)
        self.db.flush()

        self.db.add(
            ContentEntity(
                content_id=content.id,
                entity_id=cve_ent.id,
                confidence=1.0,
                extraction_method="structured",
            )
        )
        self.db.commit()

        # 1. List entities
        resp = self.client.get("/api/v1/entities")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(len(data), 2)
        cve_item = next(e for e in data if e["normalized_name"] == "CVE-2024-38077")
        self.assertEqual(cve_item["content_count"], 1)
        self.assertEqual(cve_item["parsed_metadata"]["cvss_score"], 9.8)

        # 2. Filter by entity_type
        resp_filter = self.client.get("/api/v1/entities?entity_type=cve")
        self.assertEqual(resp_filter.status_code, 200)
        self.assertTrue(all(e["entity_type"] == "cve" for e in resp_filter.json()))

        # 3. Entity stats summary
        resp_stats = self.client.get("/api/v1/entities/types/summary")
        self.assertEqual(resp_stats.status_code, 200)
        stats = resp_stats.json()
        self.assertGreaterEqual(stats["total_entities"], 2)
        self.assertIn("cve", stats["by_type"])
        self.assertIn("product", stats["by_type"])

        # 4. Lookup by CVE ID
        resp_cve = self.client.get("/api/v1/entities/cve/cve-2024-38077")
        self.assertEqual(resp_cve.status_code, 200)
        cve_detail = resp_cve.json()
        self.assertEqual(cve_detail["name"], "CVE-2024-38077")
        self.assertEqual(cve_detail["content_count"], 1)
        self.assertEqual(len(cve_detail["linked_content"]), 1)
        self.assertEqual(cve_detail["linked_content"][0]["content_id"], content.id)

        # 404 for nonexistent CVE
        resp_missing = self.client.get("/api/v1/entities/cve/CVE-1999-0000")
        self.assertEqual(resp_missing.status_code, 404)

        # 5. Lookup by Entity ID
        resp_by_id = self.client.get(f"/api/v1/entities/{cve_ent.id}")
        self.assertEqual(resp_by_id.status_code, 200)
        self.assertEqual(resp_by_id.json()["id"], cve_ent.id)


if __name__ == "__main__":
    unittest.main()
