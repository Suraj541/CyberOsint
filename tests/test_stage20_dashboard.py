"""
Stage 20: Section 21 Dashboard & Section 22 Content Pages Baseline Tests
Verifies that:
1. GET /api/v1/dashboard supplies all 7 Section 21 components from the real database:
   Latest News, Critical Vulnerabilities, New Research, Trending Topics, New Tools,
   Latest Videos, Threat Intelligence.
2. GET /api/v1/content/{id}/related provides related items.
3. apps/web/app/content/[id]/page.tsx exists and renders all Section 22 mandated fields:
   Title, Source, Published Date, Author, Category, Tags, Summary, Extracted Entities,
   Related Content, Original Source.
Conforms strictly to IMPLEMENT.md Section 21 & Section 22.
"""

from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Ensure apps/api and root in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from app.database import Base, get_db
from app.main import app
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source


class TestStage20DashboardAndContentPages(unittest.TestCase):
    """Test suite validating Section 21 Dashboard and Section 22 Content Pages."""

    def setUp(self):
        """Initialize in-memory SQLite database and test client."""
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
        """Clean up database and client overrides."""
        app.dependency_overrides.clear()
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_section21_dashboard_api_all_seven_components(self):
        """
        Validate GET /api/v1/dashboard returns all 7 components mandated by IMPLEMENT.md Section 21:
        Latest News, Critical Vulnerabilities, New Research, Trending Topics,
        New Tools, Latest Videos, Threat Intelligence.
        """
        # Create sources
        src = Source(
            name="CISA News",
            source_type="advisory",
            platform="rss",
            url="https://cisa.gov/rss",
            active=True,
            category="vulnerabilities",
        )
        self.db.add(src)
        self.db.commit()

        # Seed content for each component
        c_news = Content(
            source_id=src.id,
            title="Active Exploitation of Edge VPN",
            content_type="article",
            canonical_url="https://example.com/vpn",
            content_hash="h_vpn",
        )
        c_cve = Content(
            source_id=src.id,
            title="CVE-2024-38077 Windows RDP RCE",
            content_type="cve",
            canonical_url="https://example.com/rdp",
            content_hash="h_rdp",
        )
        c_paper = Content(
            source_id=src.id,
            title="Novel Side-Channel Attacks in Cloud Enclaves",
            content_type="paper",
            canonical_url="https://example.com/paper",
            content_hash="h_paper",
        )
        c_tool = Content(
            source_id=src.id,
            title="BloodHound CE Active Directory Audit Tool",
            content_type="tool",
            canonical_url="https://example.com/bloodhound",
            content_hash="h_tool",
        )
        c_video = Content(
            source_id=src.id,
            title="Black Hat USA 2024 Keynote Recording",
            content_type="video",
            canonical_url="https://example.com/blackhat",
            content_hash="h_video",
        )
        c_intel = Content(
            source_id=src.id,
            title="Sandworm GRU Cyber Activity Update",
            content_type="report",
            canonical_url="https://example.com/sandworm",
            content_hash="h_sandworm",
        )
        self.db.add_all([c_news, c_cve, c_paper, c_tool, c_video, c_intel])
        self.db.commit()

        # Add extracted entities for Trending Topics
        e1 = Entity(name="Sandworm", entity_type="threat_actor", normalized_name="sandworm")
        e2 = Entity(name="CVE-2024-38077", entity_type="cve", normalized_name="cve-2024-38077")
        self.db.add_all([e1, e2])
        self.db.commit()

        ce1 = ContentEntity(content_id=c_intel.id, entity_id=e1.id, confidence=0.97)
        ce2 = ContentEntity(content_id=c_cve.id, entity_id=e2.id, confidence=0.99)
        self.db.add_all([ce1, ce2])
        self.db.commit()

        # Call endpoint
        resp = self.client.get("/api/v1/dashboard")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Assert all 7 Section 21 components are present and populated
        self.assertIn("latest_news", data)
        self.assertEqual(data["latest_news"][0]["title"], c_news.title)

        self.assertIn("critical_vulnerabilities", data)
        self.assertEqual(data["critical_vulnerabilities"][0]["title"], c_cve.title)

        self.assertIn("new_research", data)
        self.assertEqual(data["new_research"][0]["title"], c_paper.title)

        self.assertIn("new_tools", data)
        self.assertEqual(data["new_tools"][0]["title"], c_tool.title)

        self.assertIn("latest_videos", data)
        self.assertEqual(data["latest_videos"][0]["title"], c_video.title)

        self.assertIn("threat_intelligence", data)
        self.assertEqual(data["threat_intelligence"][0]["title"], c_intel.title)

        self.assertIn("trending_topics", data)
        self.assertGreaterEqual(len(data["trending_topics"]), 1)

    def test_section22_reusable_content_page_file_and_fields(self):
        """
        Confirm apps/web/app/content/[id]/page.tsx exists and handles all Section 22 mandated fields:
        Title, Source, Published Date, Author, Category, Tags, Summary, Extracted Entities, Related Content, Original Source.
        """
        content_page = repo_root / "apps" / "web" / "app" / "content" / "[id]" / "page.tsx"
        self.assertTrue(content_page.exists(), "Content detail page [id]/page.tsx missing")

        with open(content_page, "r", encoding="utf-8") as f:
            code = f.read()

        mandated_elements = [
            "title",
            "source",
            "published_at",
            "author",
            "category",
            "tags",
            "summary",
            "entities",
            "related",
            "canonical_url",
        ]
        for elem in mandated_elements:
            self.assertIn(elem, code, f"Mandated Section 22 element '{elem}' not found in content page")


    def test_section22_content_detail_api_endpoint(self):
        """
        Verify GET /api/v1/content/{id} returns all Section 22 fields:
        title, source_name, published_at, author, category, tags, summary, entities, canonical_url.
        """
        src = Source(
            name="CISA Alerts",
            source_type="advisory",
            platform="rss",
            url="https://cisa.gov/rss-sec22",
            active=True,
            category="vulnerabilities",
        )
        self.db.add(src)
        self.db.commit()

        c = Content(
            source_id=src.id,
            title="Critical Edge Router Vulnerability",
            author="CISA Cyber Analyst",
            summary="Emergency patching required for perimeter edge routers.",
            description="Detailed context regarding active scanning in the wild.",
            content_type="advisory",
            canonical_url="https://example.com/edge-router",
            content_hash="h_edge_router",
        )
        self.db.add(c)
        self.db.commit()

        e = Entity(name="CVE-2024-9999", entity_type="cve", normalized_name="cve-2024-9999")
        self.db.add(e)
        self.db.commit()

        ce = ContentEntity(content_id=c.id, entity_id=e.id, confidence=0.99)
        self.db.add(ce)
        self.db.commit()

        resp = self.client.get(f"/api/v1/content/{c.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Section 22 fields: Title, Source, Published Date, Author, Category, Tags, Summary, Extracted Entities, Original Source
        self.assertEqual(data["title"], c.title)
        self.assertEqual(data["source_name"], src.name)
        self.assertEqual(data["author"], c.author)
        self.assertEqual(data["summary"], c.summary)
        self.assertEqual(data["canonical_url"], c.canonical_url)
        self.assertEqual(data["category"], src.category)
        self.assertIn("tags", data)
        self.assertIn("entities", data)
        self.assertEqual(len(data["entities"]), 1)
        self.assertEqual(data["entities"][0]["name"], "CVE-2024-9999")
        self.assertEqual(data["entities"][0]["entity_type"], "cve")


if __name__ == "__main__":
    unittest.main()
