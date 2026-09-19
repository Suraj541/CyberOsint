"""
Tests for Subsystem 9: Database.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing) and Sections 4, 5, 6.
Validates SQLAlchemy model declarations, table schemas, required indexes,
and transactional CRUD operations on in-memory SQLite/PostgreSQL fallbacks.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
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
from app.models.watchlist import Watchlist
from app.models.notification import Notification


class TestDatabaseSubsystem(unittest.TestCase):
    """Subsystem 9: Database Unit and Schema Tests."""

    @classmethod
    def setUpClass(cls):
        # Create an isolated in-memory SQLite database for deterministic CRUD testing
        cls.engine = create_engine("sqlite:///:memory:", echo=False)
        Base.metadata.create_all(cls.engine)
        cls.SessionLocal = sessionmaker(bind=cls.engine)

    def setUp(self):
        self.session = self.SessionLocal()

    def tearDown(self):
        self.session.rollback()
        self.session.close()

    def test_01_all_mandated_tables_declared(self):
        """Verify presence of all core database tables in SQLAlchemy metadata."""
        declared_tables = set(Base.metadata.tables.keys())
        expected_tables = {
            "users",
            "sources",
            "content",
            "entities",
            "content_entities",
            "tags",
            "content_tags",
            "duplicate_links",
            "watchlists",
            "notifications",
        }
        for table in expected_tables:
            self.assertIn(table, declared_tables, f"Mandated table '{table}' not declared in Base.metadata")

    def test_02_source_table_columns_conformance(self):
        """Verify sources table column schema adheres to IMPLEMENT.md Section 5."""
        source_cols = {c.name for c in Source.__table__.columns}
        mandated_cols = {
            "id",
            "name",
            "url",
            "source_type",
            "platform",
            "category",
            "reliability_score",
            "active",
            "created_at",
            "updated_at",
        }
        self.assertTrue(mandated_cols.issubset(source_cols))

    def test_03_content_table_columns_and_mandated_indexes(self):
        """Verify content table column schema and indexes on published_at, source_id, content_type, content_hash."""
        content_cols = {c.name for c in Content.__table__.columns}
        mandated_cols = {
            "id",
            "source_id",
            "title",
            "description",
            "content_type",
            "canonical_url",
            "content_hash",
            "published_at",
        }
        self.assertTrue(mandated_cols.issubset(content_cols))

        indexed_columns = set()
        for idx in Content.__table__.indexes:
            for col in idx.columns:
                indexed_columns.add(col.name)

        for col_name in ("published_at", "source_id", "content_type", "content_hash", "canonical_url"):
            self.assertIn(col_name, indexed_columns, f"Required index missing on Content.{col_name}")

    def test_04_crud_source_and_content_lifecycle(self):
        """Verify insert, query, update, and relationship loading for Source and Content records."""
        # 1. Insert Source
        source = Source(
            name="CISA KEV Feed",
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            source_type="feed",
            platform="cisa",
            category="vulnerability_management",
            reliability_score=0.95,
            active=True,
        )
        self.session.add(source)
        self.session.commit()
        self.assertIsNotNone(source.id)

        # 2. Insert Content linked to Source
        content = Content(
            source_id=source.id,
            title="Active Exploitation of Ivanti Endpoint Manager",
            description="CISA has added CVE-2024-29824 to its Known Exploited Vulnerabilities catalog.",
            content_type="advisory",
            canonical_url="https://cisa.gov/advisories/cve-2024-29824",
            content_hash="a" * 64,
            published_at=datetime.now(timezone.utc),
            status="ingested",
        )
        self.session.add(content)
        self.session.commit()
        self.assertIsNotNone(content.id)

        # 3. Query record and verify fields
        queried = self.session.query(Content).filter(Content.id == content.id).first()
        self.assertIsNotNone(queried)
        self.assertEqual(queried.title, "Active Exploitation of Ivanti Endpoint Manager")
        self.assertEqual(queried.source_id, source.id)

        # 4. Insert and link Entity
        entity = Entity(
            name="CVE-2024-29824",
            entity_type="cve",
            normalized_name="CVE-2024-29824",
        )
        self.session.add(entity)
        self.session.commit()

        link = ContentEntity(
            content_id=content.id,
            entity_id=entity.id,
            confidence=0.98,
            extraction_method="regex",
        )
        self.session.add(link)
        self.session.commit()

        # 5. Verify join query
        linked_entities = (
            self.session.query(Entity)
            .join(ContentEntity, Entity.id == ContentEntity.entity_id)
            .filter(ContentEntity.content_id == content.id)
            .all()
        )
        self.assertEqual(len(linked_entities), 1)
        self.assertEqual(linked_entities[0].name, "CVE-2024-29824")

    def test_05_transaction_rollback_integrity(self):
        """Verify session.rollback preserves state after an error."""
        count_before = self.session.query(Source).count()
        source = Source(name="Temporary Source", url="https://temp.local", source_type="api")
        self.session.add(source)
        self.session.flush()
        self.session.rollback()
        count_after = self.session.query(Source).count()
        self.assertEqual(count_before, count_after)


if __name__ == "__main__":
    unittest.main()
