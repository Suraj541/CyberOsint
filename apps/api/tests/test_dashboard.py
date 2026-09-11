"""
Dashboard & Content Tests
Verifies GET /api/v1/dashboard returns all 7 components mandated by IMPLEMENT.md Section 21
using real database records, plus GET /api/v1/content/{id}/related (Section 22).
"""

from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure apps/api and root in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source


class TestDashboardAndContent(unittest.TestCase):
    """Test suite validating Section 21 Dashboard and Section 22 Content API endpoints."""

    def setUp(self):
        """Create isolated in-memory SQLite database and test client."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False, autoflush=False, bind=self.engine
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            try:
                yield self.db
            finally:
                pass

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up database connection and dependency overrides."""
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_dashboard_endpoint_all_seven_mandated_components(self):
        """
        Verify GET /api/v1/dashboard returns all 7 Section 21 components:
        Latest News, Critical Vulnerabilities, New Research, Trending Topics,
        New Tools, Latest Videos, Threat Intelligence.
        """
        # 1. Seed Source
        src = Source(
            name="CISA Alerts",
            source_type="advisory",
            platform="rss",
            url="https://cisa.gov/rss",
            active=True,
            category="vulnerabilities",
        )
        self.db.add(src)
        self.db.commit()

        # 2. Seed Content for various components
        c_news = Content(
            source_id=src.id,
            title="LockBit Ransomware Targets Manufacturing",
            content_type="article",
            canonical_url="https://example.com/news1",
            content_hash="h_news1",
        )
        c_cve = Content(
            source_id=src.id,
            title="CVE-2024-3400 PAN-OS Command Injection",
            content_type="cve",
            canonical_url="https://example.com/cve1",
            content_hash="h_cve1",
        )
        c_paper = Content(
            source_id=src.id,
            title="XZ Utils Supply Chain Backdoor Deep Dive",
            content_type="paper",
            canonical_url="https://example.com/paper1",
            content_hash="h_paper1",
        )
        c_tool = Content(
            source_id=src.id,
            title="GhostWire Memory Evasion Framework",
            content_type="tool",
            canonical_url="https://example.com/tool1",
            content_hash="h_tool1",
        )
        c_video = Content(
            source_id=src.id,
            title="DEF CON 32 SATCOM Exploitation Keynote",
            content_type="video",
            canonical_url="https://example.com/video1",
            content_hash="h_video1",
        )
        c_intel = Content(
            source_id=src.id,
            title="Volt Typhoon Living Off the Land Campaign",
            content_type="report",
            canonical_url="https://example.com/intel1",
            content_hash="h_intel1",
        )
        self.db.add_all([c_news, c_cve, c_paper, c_tool, c_video, c_intel])
        self.db.commit()

        # 3. Seed Extracted Entities for Trending Topics
        e1 = Entity(name="LockBit", entity_type="threat_actor", normalized_name="lockbit")
        e2 = Entity(name="CVE-2024-3400", entity_type="cve", normalized_name="cve-2024-3400")
        self.db.add_all([e1, e2])
        self.db.commit()

        ce1 = ContentEntity(content_id=c_news.id, entity_id=e1.id, confidence=0.98)
        ce2 = ContentEntity(content_id=c_intel.id, entity_id=e1.id, confidence=0.95)
        ce3 = ContentEntity(content_id=c_cve.id, entity_id=e2.id, confidence=0.99)
        self.db.add_all([ce1, ce2, ce3])
        self.db.commit()

        # 4. Request /api/v1/dashboard
        resp = self.client.get("/api/v1/dashboard")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Verify Metrics
        self.assertIn("metrics", data)
        self.assertEqual(data["metrics"]["total_content"], 6)
        self.assertEqual(data["metrics"]["active_sources"], 1)
        self.assertEqual(data["metrics"]["tracked_cves"], 1)
        self.assertEqual(data["metrics"]["total_entities"], 2)

        # Verify all 7 components populated with real database records
        self.assertIn("latest_news", data)
        self.assertGreaterEqual(len(data["latest_news"]), 1)
        self.assertEqual(data["latest_news"][0]["title"], c_news.title)

        self.assertIn("critical_vulnerabilities", data)
        self.assertGreaterEqual(len(data["critical_vulnerabilities"]), 1)
        self.assertEqual(data["critical_vulnerabilities"][0]["title"], c_cve.title)

        self.assertIn("new_research", data)
        self.assertGreaterEqual(len(data["new_research"]), 1)
        self.assertEqual(data["new_research"][0]["title"], c_paper.title)

        self.assertIn("new_tools", data)
        self.assertGreaterEqual(len(data["new_tools"]), 1)
        self.assertEqual(data["new_tools"][0]["title"], c_tool.title)

        self.assertIn("latest_videos", data)
        self.assertGreaterEqual(len(data["latest_videos"]), 1)
        self.assertEqual(data["latest_videos"][0]["title"], c_video.title)

        self.assertIn("threat_intelligence", data)
        self.assertGreaterEqual(len(data["threat_intelligence"]), 1)
        self.assertEqual(data["threat_intelligence"][0]["title"], c_intel.title)

        # Trending topics: LockBit mentioned twice, CVE-2024-3400 mentioned once
        self.assertIn("trending_topics", data)
        self.assertEqual(len(data["trending_topics"]), 2)
        self.assertEqual(data["trending_topics"][0]["name"], "LockBit")
        self.assertEqual(data["trending_topics"][0]["mention_count"], 2)

    def test_related_content_endpoint(self):
        """Verify GET /api/v1/content/{id}/related returns items in same category or content_type."""
        src_malware = Source(
            name="Malware Feed",
            source_type="blog",
            platform="rss",
            url="https://example.com/malware-rss",
            active=True,
            category="malware",
        )
        src_cloud = Source(
            name="Cloud Feed",
            source_type="blog",
            platform="rss",
            url="https://example.com/cloud-rss",
            active=True,
            category="cloud_security",
        )
        self.db.add_all([src_malware, src_cloud])
        self.db.commit()

        c1 = Content(
            source_id=src_malware.id,
            title="LockBit Ransomware Extortion",
            content_type="article",
            canonical_url="https://example.com/m1",
            content_hash="h_m1",
        )
        c2 = Content(
            source_id=src_malware.id,
            title="BlackCat ALPHV Encryptor Analysis",
            content_type="article",
            canonical_url="https://example.com/m2",
            content_hash="h_m2",
        )
        c3 = Content(
            source_id=src_cloud.id,
            title="Kubernetes Ingress Controller Vulnerability",
            content_type="article",
            canonical_url="https://example.com/k8s",
            content_hash="h_k8s",
        )
        self.db.add_all([c1, c2, c3])
        self.db.commit()

        resp = self.client.get(f"/api/v1/content/{c1.id}/related?limit=3")
        self.assertEqual(resp.status_code, 200)
        items = resp.json()
        self.assertGreaterEqual(len(items), 1)
        # Should contain c2 (shared source category 'malware')
        self.assertEqual(items[0]["id"], c2.id)


if __name__ == "__main__":
    unittest.main()
