"""
Stage 22: Entity Pages Baseline Tests
Validates Section 23 / Step 22 implementation:
- Frontend route /entities/[id]/page.tsx
- For CVE: Overview, Severity, Affected Products, References, Articles, Reports, Related Entities, Timeline
- For Malware: Overview, Aliases, Threat Actors, Campaigns, Techniques, Reports, Tools, Timeline
- Backend API GET /api/v1/entities/{id} returning correlated relations.
Conforms strictly to IMPLEMENT.md Section 23.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.database import get_db
from app.main import app
from app.models.base import Base
from app.models.content import Content
from app.models.entity import ContentEntity, Entity


class TestStage22EntityPages(unittest.TestCase):
    """Test suite validating Section 23 / Step 22 Entity Pages implementation."""

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


    def test_frontend_entity_page_file_exists(self):
        """Confirm apps/web/app/entities/[id]/page.tsx exists and is populated."""
        page_path = repo_root / "apps" / "web" / "app" / "entities" / "[id]" / "page.tsx"
        self.assertTrue(page_path.exists(), "apps/web/app/entities/[id]/page.tsx does not exist")
        content = page_path.read_text(encoding="utf-8")
        self.assertGreater(len(content), 500)

    def test_frontend_cve_mandated_fields_present(self):
        """
        Validate that for a CVE entity, apps/web/app/entities/[id]/page.tsx handles
        all mandated fields from IMPLEMENT.md Section 23:
        Overview, Severity, Affected Products, References, Articles, Reports, Related Entities, Timeline
        """
        page_path = repo_root / "apps" / "web" / "app" / "entities" / "[id]" / "page.tsx"
        content = page_path.read_text(encoding="utf-8")

        cve_mandated_fields = [
            "Overview",
            "Severity",
            "Affected Products",
            "References",
            "Articles",
            "Reports",
            "Related Entities",
            "Timeline",
        ]
        for field in cve_mandated_fields:
            self.assertIn(
                field.lower(),
                content.lower(),
                f"Mandated CVE field '{field}' not found in entity page component",
            )

    def test_frontend_malware_mandated_fields_present(self):
        """
        Validate that for a Malware entity, apps/web/app/entities/[id]/page.tsx handles
        all mandated fields from IMPLEMENT.md Section 23:
        Overview, Aliases, Threat Actors, Campaigns, Techniques, Reports, Tools, Timeline
        """
        page_path = repo_root / "apps" / "web" / "app" / "entities" / "[id]" / "page.tsx"
        content = page_path.read_text(encoding="utf-8")

        malware_mandated_fields = [
            "Overview",
            "Aliases",
            "Threat Actors",
            "Campaigns",
            "Techniques",
            "Reports",
            "Tools",
            "Timeline",
        ]
        for field in malware_mandated_fields:
            self.assertIn(
                field.lower(),
                content.lower(),
                f"Mandated Malware field '{field}' not found in entity page component",
            )

    def test_content_page_cross_links_to_entities(self):
        """Confirm apps/web/app/content/[id]/page.tsx links extracted entities to /entities/:id."""
        content_page = repo_root / "apps" / "web" / "app" / "content" / "[id]" / "page.tsx"
        self.assertTrue(content_page.exists())
        text = content_page.read_text(encoding="utf-8")
        self.assertIn("/entities/", text)

    def test_backend_cve_entity_detail_api(self):
        """
        Verify GET /api/v1/entities/{id} returns all Section 23 CVE fields:
        Overview, Severity, Affected Products, References, Articles, Reports, Related Entities, Timeline.
        """
        # 1. Seed CVE entity
        cve_ent = Entity(
            name="CVE-2024-3400",
            entity_type="cve",
            normalized_name="CVE-2024-3400",
            description="Command injection in PAN-OS GlobalProtect",
            metadata_json=json.dumps({
                "cvss_score": 10.0,
                "severity": "CRITICAL",
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "weakness": "CWE-77",
                "affected_products": ["PAN-OS 10.2", "PAN-OS 11.0"],
                "references": ["https://security.paloaltonetworks.com/CVE-2024-3400"],
            }),
        )
        vendor_ent = Entity(
            name="Palo Alto Networks",
            entity_type="vendor",
            normalized_name="palo alto networks",
            description="Cybersecurity appliance vendor",
        )
        self.db.add_all([cve_ent, vendor_ent])
        self.db.flush()

        # 2. Seed an Article and a Report
        article = Content(
            title="Active Exploitation of CVE-2024-3400 Detected",
            canonical_url="https://news.example/cve-2024-3400",
            content_type="article",
            content_hash="hash_art_111111111111111111111111111111111111111111111111111111111111",
            published_at=datetime(2024, 4, 12, 10, 0, 0, tzinfo=timezone.utc),
            status="ingested",
        )
        report = Content(
            title="CISA Advisory: Urgent Mitigation for CVE-2024-3400",
            canonical_url="https://cisa.gov/advisories/aa24-109a",
            content_type="advisory",
            content_hash="hash_rep_222222222222222222222222222222222222222222222222222222222222",
            published_at=datetime(2024, 4, 14, 12, 0, 0, tzinfo=timezone.utc),
            status="ingested",
        )
        self.db.add_all([article, report])
        self.db.flush()

        # 3. Link CVE and Vendor entities to content
        self.db.add(ContentEntity(content_id=article.id, entity_id=cve_ent.id, confidence=0.99))
        self.db.add(ContentEntity(content_id=article.id, entity_id=vendor_ent.id, confidence=0.95))
        self.db.add(ContentEntity(content_id=report.id, entity_id=cve_ent.id, confidence=1.0))
        self.db.commit()

        # Query API by entity primary key ID
        resp = self.client.get(f"/api/v1/entities/{cve_ent.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Overview
        self.assertEqual(data["name"], "CVE-2024-3400")
        self.assertEqual(data["entity_type"], "cve")
        self.assertIn("Command injection", data["description"])

        # Severity
        self.assertIsNotNone(data["severity"])
        self.assertEqual(data["severity"]["cvss_score"], 10.0)
        self.assertEqual(data["severity"]["severity_rating"], "CRITICAL")
        self.assertEqual(data["severity"]["cwe_id"], "CWE-77")

        # Affected Products
        self.assertIn("PAN-OS 10.2", data["affected_products"])

        # References
        self.assertTrue(any("security.paloaltonetworks.com" in r for r in data["references"]))

        # Articles vs Reports partitioning
        self.assertGreaterEqual(len(data["articles"]), 1)
        self.assertEqual(data["articles"][0]["content_id"], article.id)
        self.assertGreaterEqual(len(data["reports"]), 1)
        self.assertEqual(data["reports"][0]["content_id"], report.id)

        # Related Entities
        rel_names = [re["name"] for re in data["related_entities"]]
        self.assertIn("Palo Alto Networks", rel_names)

        # Timeline
        self.assertGreaterEqual(len(data["timeline"]), 2)

        # Also confirm lookup by CVE ID string works
        resp_by_name = self.client.get("/api/v1/entities/CVE-2024-3400")
        self.assertEqual(resp_by_name.status_code, 200)
        self.assertEqual(resp_by_name.json()["id"], cve_ent.id)

    def test_backend_malware_entity_detail_api(self):
        """
        Verify GET /api/v1/entities/{id} returns all Section 23 Malware fields:
        Overview, Aliases, Threat Actors, Campaigns, Techniques, Reports, Tools, Timeline.
        """
        # 1. Seed Malware and related entities
        malware = Entity(
            name="LockBit",
            entity_type="malware",
            normalized_name="lockbit",
            description="Ransomware-as-a-service syndicate",
            metadata_json=json.dumps({
                "aliases": ["LockBit 3.0", "LockBit Black"],
                "campaigns": ["Operation Cronos Disruption", "Healthcare Wave"],
            }),
        )
        actor = Entity(
            name="Wizard Spider",
            entity_type="threat_actor",
            normalized_name="wizard spider",
            description="Cybercrime group",
        )
        technique = Entity(
            name="T1486",
            entity_type="mitre_technique",
            normalized_name="T1486",
            description="Data Encrypted for Impact",
        )
        tool = Entity(
            name="Mimikatz",
            entity_type="tool",
            normalized_name="mimikatz",
            description="Credential extraction tool",
        )
        self.db.add_all([malware, actor, technique, tool])
        self.db.flush()

        # 2. Seed Intelligence Report
        report = Content(
            title="LockBit 3.0 Technical Analysis and Indicator Profile",
            canonical_url="https://cert.gov/lockbit-analysis",
            content_type="report",
            content_hash="hash_lockbit_33333333333333333333333333333333333333333333333333333333",
            published_at=datetime(2024, 3, 20, 9, 0, 0, tzinfo=timezone.utc),
            status="ingested",
        )
        self.db.add(report)
        self.db.flush()

        # 3. Associate entities to the same report
        for ent in (malware, actor, technique, tool):
            self.db.add(ContentEntity(content_id=report.id, entity_id=ent.id, confidence=0.95))
        self.db.commit()

        # Query API by malware name
        resp = self.client.get("/api/v1/entities/LockBit")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        # Overview
        self.assertEqual(data["name"], "LockBit")
        self.assertEqual(data["entity_type"], "malware")
        self.assertIn("Ransomware", data["description"])

        # Aliases
        self.assertIn("LockBit 3.0", data["aliases"])

        # Threat Actors
        actor_names = [a["name"] for a in data["threat_actors"]]
        self.assertIn("Wizard Spider", actor_names)

        # Campaigns
        self.assertIn("Operation Cronos Disruption", data["campaigns"])

        # Techniques
        tech_names = [t["name"] for t in data["techniques"]]
        self.assertIn("T1486", tech_names)

        # Reports
        self.assertGreaterEqual(len(data["reports"]), 1)
        self.assertEqual(data["reports"][0]["content_id"], report.id)

        # Tools
        tool_names = [t["name"] for t in data["tools"]]
        self.assertIn("Mimikatz", tool_names)

        # Timeline
        self.assertGreaterEqual(len(data["timeline"]), 1)


if __name__ == "__main__":
    unittest.main()
