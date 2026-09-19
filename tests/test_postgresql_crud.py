"""
Real PostgreSQL 16 CRUD Verification Test Suite.
Directly executes against PostgreSQL 16 server at localhost:5432.
Validates INSERT, SELECT, UPDATE, DELETE, relationships, foreign keys,
cascades, unique constraints, and transaction rollbacks.
"""

import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from app.models import (
    Base,
    User,
    Source,
    Content,
    Entity,
    ContentEntity,
    Tag,
    ContentTag,
)
from app.models.duplicate import DuplicateLink
from app.models.watchlist import Watchlist, WatchlistItem
from app.models.notification import Notification
from app.models.intelligence import ThreatActorModel, MalwareFamilyModel, CampaignModel
from app.models.sync_state import ConnectorSyncState
from app.models.mitre import MitreTacticModel, MitreTechniqueModel

POSTGRES_URL = os.environ.get(
    "TEST_POSTGRES_URL",
    "postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint"
)


class TestPostgreSQLCRUD(unittest.TestCase):
    """Empirical CRUD verification against real PostgreSQL 16."""

    @classmethod
    def setUpClass(cls):
        cls.engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
        # Verify it is indeed PostgreSQL
        with cls.engine.connect() as conn:
            val = conn.exec_driver_sql("SELECT version()").scalar()
            assert "PostgreSQL" in val, f"Expected PostgreSQL, got {val}"
        cls.Session = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.session = self.Session()

    def tearDown(self):
        self.session.rollback()
        self.session.close()

    def test_01_user_crud(self):
        """Test User model CRUD operations."""
        unique_email = f"crud_test_{datetime.now().timestamp()}@cyber.local"
        user = User(
            email=unique_email,
            hashed_password="argon2_hashed_secret",
            full_name="Postgres CRUD Tester",
            is_active=True,
            role="admin",
        )
        self.session.add(user)
        self.session.commit()
        self.assertIsNotNone(user.id)

        # SELECT
        fetched = self.session.query(User).filter(User.email == unique_email).first()
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.full_name, "Postgres CRUD Tester")

        # UPDATE
        fetched.full_name = "Updated Admin Name"
        self.session.commit()
        updated = self.session.query(User).filter(User.id == user.id).first()
        self.assertEqual(updated.full_name, "Updated Admin Name")

        # DELETE
        self.session.delete(updated)
        self.session.commit()
        deleted = self.session.query(User).filter(User.id == user.id).first()
        self.assertIsNone(deleted)

    def test_02_source_and_content_crud(self):
        """Test Source and Content CRUD with foreign keys."""
        source = Source(
            name="PG Ingestion Feed",
            url=f"https://pg-feed-{datetime.now().timestamp()}.local/rss",
            source_type="rss",
            platform="web",
            category="vulnerability",
            reliability_score=0.92,
            active=True,
        )
        self.session.add(source)
        self.session.commit()
        self.assertIsNotNone(source.id)

        # Content
        content = Content(
            source_id=source.id,
            title="PostgreSQL 16 Security Advisory",
            description="Buffer boundary checks in PostgreSQL extension handlers.",
            content_type="advisory",
            canonical_url=f"https://advisory.pg-{datetime.now().timestamp()}.org",
            content_hash="b" * 64,
            published_at=datetime.now(timezone.utc),
            status="discovered",
        )
        self.session.add(content)
        self.session.commit()
        self.assertIsNotNone(content.id)
        self.assertEqual(content.source_id, source.id)

        # UPDATE
        content.status = "processed"
        content.quality_score = 0.98
        self.session.commit()

        reloaded = self.session.query(Content).filter(Content.id == content.id).first()
        self.assertEqual(reloaded.status, "processed")
        self.assertAlmostEqual(reloaded.quality_score, 0.98, places=2)

        # CLEANUP
        self.session.delete(content)
        self.session.delete(source)
        self.session.commit()

    def test_03_entity_and_content_entity_cascade(self):
        """Test Entity, ContentEntity junction table and CASCADE DELETE."""
        source = Source(
            name="Cascade Test Source",
            url=f"https://cascade-{datetime.now().timestamp()}.local",
            source_type="api",
            active=True,
        )
        self.session.add(source)
        self.session.commit()

        content = Content(
            source_id=source.id,
            title="CVE Exploitation Bulletin",
            canonical_url=f"https://bulletin-{datetime.now().timestamp()}.local",
            content_hash="c" * 64,
            status="ingested",
        )
        entity = Entity(
            name="CVE-2026-9999",
            entity_type="cve",
            normalized_name="CVE-2026-9999",
        )
        self.session.add_all([content, entity])
        self.session.commit()

        link = ContentEntity(
            content_id=content.id,
            entity_id=entity.id,
            confidence=0.99,
            extraction_method="regex",
        )
        self.session.add(link)
        self.session.commit()
        link_id = link.id

        # Verify join
        links = self.session.query(ContentEntity).filter(ContentEntity.content_id == content.id).all()
        self.assertEqual(len(links), 1)

        # Deleting content should cascade delete ContentEntity
        self.session.delete(content)
        self.session.commit()

        remaining_link = self.session.query(ContentEntity).filter(ContentEntity.id == link_id).first()
        self.assertIsNone(remaining_link)

        # Cleanup
        self.session.delete(entity)
        self.session.delete(source)
        self.session.commit()

    def test_04_unique_constraint_enforcement(self):
        """Verify PostgreSQL strictly enforces unique constraints."""
        u1 = User(
            email="unique_test_pg@cyber.local",
            hashed_password="hash",
            is_active=True,
        )
        self.session.add(u1)
        self.session.commit()

        # Attempt to insert identical email
        u2 = User(
            email="unique_test_pg@cyber.local",
            hashed_password="hash2",
            is_active=True,
        )
        self.session.add(u2)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

        # Cleanup
        self.session.query(User).filter(User.email == "unique_test_pg@cyber.local").delete()
        self.session.commit()

    def test_05_watchlist_and_notification_crud(self):
        """Test Watchlist, WatchlistItem, and Notification models."""
        wl = Watchlist(
            name="Critical Infrastructure Watchlist",
            description="Monitors SCADA and ICS CVEs",
            session_id="test_session_123",
            is_active=True,
        )
        self.session.add(wl)
        self.session.commit()

        item = WatchlistItem(
            watchlist_id=wl.id,
            item_type="keyword",
            item_value="SCADA",
        )
        self.session.add(item)
        self.session.commit()

        notif = Notification(
            watchlist_id=wl.id,
            session_id="test_session_123",
            title="SCADA Alert Detected",
            body="New advisory matches watchlist rule",
            importance_level="critical",
            channel="in_app",
            status="pending",
        )
        self.session.add(notif)
        self.session.commit()

        # Query and verify
        queried_notif = self.session.query(Notification).filter(Notification.id == notif.id).first()
        self.assertEqual(queried_notif.importance_level, "critical")
        self.assertEqual(queried_notif.watchlist_id, wl.id)

        # Cleanup
        self.session.delete(notif)
        self.session.delete(item)
        self.session.delete(wl)
        self.session.commit()

    def test_06_threat_intelligence_crud(self):
        """Test ThreatActorModel, MalwareFamilyModel, CampaignModel CRUD."""
        actor = ThreatActorModel(
            name=f"APT-PG-{int(datetime.now().timestamp())}",
            country="Unknown",
            description="Advanced persistent threat actor monitored in PG",
            motivation="Espionage",
            threat_level="high",
            status="active",
        )
        self.session.add(actor)
        self.session.commit()

        malware = MalwareFamilyModel(
            name=f"Trojan-PG-{int(datetime.now().timestamp())}",
            malware_type="trojan",
            description="Remote access trojan",
            severity="high",
        )
        self.session.add(malware)
        self.session.commit()

        camp = CampaignModel(
            name=f"Operation Postgres-{int(datetime.now().timestamp())}",
            status="active",
            actor_name=actor.name,
        )
        self.session.add(camp)
        self.session.commit()

        self.assertIsNotNone(actor.id)
        self.assertIsNotNone(malware.id)
        self.assertIsNotNone(camp.id)

        # Cleanup
        self.session.delete(camp)
        self.session.delete(malware)
        self.session.delete(actor)
        self.session.commit()

    def test_07_connector_sync_state_crud(self):
        """Test persistent sync state storage for connectors/CVE sync."""
        state = ConnectorSyncState(
            connector_id="cve_test_connector",
            last_successful_sync=datetime.now(timezone.utc),
            cursor="startIndex=500",
            etag="W/12345",
            metadata_json='{"pages_fetched": 5}',
        )
        self.session.add(state)
        self.session.commit()

        queried = self.session.query(ConnectorSyncState).filter(
            ConnectorSyncState.connector_id == "cve_test_connector"
        ).first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.cursor, "startIndex=500")

        # Update metadata
        queried.cursor = "startIndex=1000"
        queried.etag = "W/67890"
        self.session.commit()

        updated = self.session.query(ConnectorSyncState).filter(
            ConnectorSyncState.connector_id == "cve_test_connector"
        ).first()
        self.assertEqual(updated.cursor, "startIndex=1000")
        self.assertEqual(updated.etag, "W/67890")

        # Cleanup
        self.session.delete(updated)
        self.session.commit()

    def test_08_mitre_and_duplicate_links_crud(self):
        """Test MITRE ATT&CK and DuplicateLink models."""
        tactic = MitreTacticModel(
            external_id=f"TA9999_{int(datetime.now().timestamp())}",
            name="Initial Access Test",
            description="Tactic test in PostgreSQL",
            sort_order=1,
        )
        self.session.add(tactic)
        self.session.commit()

        technique = MitreTechniqueModel(
            external_id=f"T9999_{int(datetime.now().timestamp())}",
            name="Spearphishing Test",
            description="Technique test in PostgreSQL",
            tactic_id=tactic.external_id,
            is_subtechnique=False,
        )
        self.session.add(technique)
        self.session.commit()

        # Create parent content records for foreign keys
        c1 = Content(
            title="Canonical Article",
            canonical_url=f"https://art1-{int(datetime.now().timestamp())}.local",
            content_hash="d" * 64,
            status="ingested",
        )
        c2 = Content(
            title="Duplicate Article",
            canonical_url=f"https://art2-{int(datetime.now().timestamp())}.local",
            content_hash="e" * 64,
            status="ingested",
        )
        self.session.add_all([c1, c2])
        self.session.commit()

        # Duplicate link
        dup = DuplicateLink(
            canonical_id=c1.id,
            duplicate_id=c2.id,
            similarity_score=0.96,
            match_type="hash_exact",
            cluster_id=f"cluster_{int(datetime.now().timestamp())}",
        )
        self.session.add(dup)
        self.session.commit()

        # Query
        fetched_dup = self.session.query(DuplicateLink).filter(DuplicateLink.id == dup.id).first()
        self.assertIsNotNone(fetched_dup)
        self.assertAlmostEqual(fetched_dup.similarity_score, 0.96, places=2)

        # Cleanup
        self.session.delete(dup)
        self.session.delete(c2)
        self.session.delete(c1)
        self.session.delete(technique)
        self.session.delete(tactic)
        self.session.commit()

    def test_09_transaction_rollback_and_isolation(self):
        """Test strict transaction rollback isolation in PostgreSQL."""
        initial_users = self.session.query(User).count()
        user = User(
            email=f"rollback_canary_{datetime.now().timestamp()}@cyber.local",
            hashed_password="hashed_pass",
            is_active=True,
        )
        self.session.add(user)
        self.session.flush()

        # User exists within uncommitted session
        self.assertIsNotNone(user.id)
        in_flight = self.session.query(User).filter(User.id == user.id).first()
        self.assertIsNotNone(in_flight)

        # Rollback
        self.session.rollback()

        # Must not exist in database
        final_users = self.session.query(User).count()
        self.assertEqual(initial_users, final_users)


if __name__ == "__main__":
    unittest.main()
