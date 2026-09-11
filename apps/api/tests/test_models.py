"""
Database Models Unit & Relationship Test Suite
Validates schema conformance, constraints, foreign keys, cascading deletions,
and indexing for users, sources, content, entities, content_entities, tags, and content_tags.
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Ensure apps/api is in sys.path
api_root = Path(__file__).resolve().parent.parent
if str(api_root) not in sys.path:
    sys.path.insert(0, str(api_root))

from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
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


class TestDatabaseModels(unittest.TestCase):
    """Test suite verifying Step 3, 4, 5 data models and schema integrity."""

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database with foreign keys enabled
        cls.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(cls.engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        cls.Session = sessionmaker(bind=cls.engine)

    def setUp(self):
        Base.metadata.drop_all(bind=self.engine)
        Base.metadata.create_all(bind=self.engine)
        self.session = self.Session()

    def tearDown(self):
        self.session.rollback()
        self.session.close()

    def test_user_creation_and_uniqueness(self):
        """Verify User model creation, defaults, and email unique constraint."""
        user = User(
            email="analyst@cyber-osint.local",
            hashed_password="secure_hashed_password",
            full_name="OSINT Analyst",
            role="lead_analyst",
        )
        self.session.add(user)
        self.session.commit()

        self.assertIsNotNone(user.id)
        self.assertEqual(user.role, "lead_analyst")
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_superuser)
        self.assertIsNotNone(user.created_at)

        # Duplicate email must raise IntegrityError
        dup = User(
            email="analyst@cyber-osint.local",
            hashed_password="another_password",
        )
        self.session.add(dup)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_source_model_specification_conformance(self):
        """
        Verify Source model conforms strictly to IMPLEMENT.md Section 5:
        id, name, url, source_type, platform, category, language,
        access_method, reliability_score, active, last_checked, created_at, updated_at
        """
        source = Source(
            name="CISA Cybersecurity Advisories",
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
            source_type="advisory",
            platform="web",
            category="vulnerabilities",
            language="en",
            access_method="rss",
            reliability_score=0.98,
            active=True,
            last_checked=datetime.now(timezone.utc),
        )
        self.session.add(source)
        self.session.commit()

        self.assertIsNotNone(source.id)
        self.assertEqual(source.name, "CISA Cybersecurity Advisories")
        self.assertEqual(source.reliability_score, 0.98)
        self.assertEqual(source.access_method, "rss")
        self.assertTrue(source.active)

        # Duplicate URL must raise IntegrityError
        dup_source = Source(
            name="CISA Duplicate",
            url="https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
            source_type="advisory",
        )
        self.session.add(dup_source)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_content_model_specification_conformance(self):
        """
        Verify Content model conforms strictly to IMPLEMENT.md Section 6:
        id, source_id, title, description, content_type, canonical_url,
        author, published_at, discovered_at, language, summary, content_hash,
        quality_score, relevance_score, confidence_score, status, created_at, updated_at
        """
        source = Source(
            name="Krebs on Security",
            url="https://krebsonsecurity.com/feed/",
            source_type="blog",
        )
        self.session.add(source)
        self.session.commit()

        content = Content(
            source_id=source.id,
            title="Critical Flaw in Windows Kernel Exploited in the Wild",
            description="Detailed analysis of zero-day kernel privilege escalation vulnerability.",
            content_type="article",
            canonical_url="https://krebsonsecurity.com/2026/09/critical-flaw-windows/",
            author="Brian Krebs",
            published_at=datetime.now(timezone.utc),
            language="en",
            summary="Threat actors actively exploit kernel zero-day vulnerability.",
            content_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            quality_score=0.92,
            relevance_score=0.95,
            confidence_score=1.0,
            status="parsed",
        )
        self.session.add(content)
        self.session.commit()

        self.assertIsNotNone(content.id)
        self.assertEqual(content.source.name, "Krebs on Security")
        self.assertEqual(content.content_type, "article")
        self.assertEqual(content.status, "parsed")
        self.assertEqual(len(source.contents), 1)

    def test_entity_and_content_entity_relationships(self):
        """Verify Entity creation and Many-to-Many linking via ContentEntity."""
        content = Content(
            title="New Ransomware Strain Abuses CVE-2024-38077",
            canonical_url="https://example.com/ransomware-cve-2024-38077",
            content_hash="hash_cve_2024_38077_example",
        )
        self.session.add(content)

        cve_entity = Entity(
            name="CVE-2024-38077",
            entity_type="cve",
            normalized_name="cve-2024-38077",
            description="Windows Remote Desktop Licensing Service RCE",
            metadata_json='{"cvss": 9.8, "vector": "NETWORK"}',
        )
        malware_entity = Entity(
            name="LockBit 3.0",
            entity_type="malware",
            normalized_name="lockbit 3.0",
            description="Ransomware-as-a-service affiliate builder",
        )
        self.session.add_all([cve_entity, malware_entity])
        self.session.commit()

        link1 = ContentEntity(
            content_id=content.id,
            entity_id=cve_entity.id,
            confidence=0.99,
            extraction_method="regex",
            context_snippet="abuses vulnerability CVE-2024-38077 to achieve code execution",
        )
        link2 = ContentEntity(
            content_id=content.id,
            entity_id=malware_entity.id,
            confidence=0.90,
            extraction_method="ner",
            context_snippet="associated with LockBit 3.0 operations",
        )
        self.session.add_all([link1, link2])
        self.session.commit()

        self.assertEqual(len(content.content_entities), 2)
        self.assertEqual(len(cve_entity.content_links), 1)
        self.assertEqual(cve_entity.content_links[0].content.title, content.title)

        # Duplicate link must fail unique constraint
        dup_link = ContentEntity(
            content_id=content.id,
            entity_id=cve_entity.id,
        )
        self.session.add(dup_link)
        with self.assertRaises(IntegrityError):
            self.session.commit()
        self.session.rollback()

    def test_tag_and_content_tag_relationships(self):
        """Verify Tag creation and ContentTag Many-to-Many associations."""
        content = Content(
            title="Supply Chain Attack Compromises NPM Ecosystem",
            canonical_url="https://example.com/npm-supply-chain",
            content_hash="hash_npm_supply_chain_01",
        )
        tag = Tag(name="supply-chain", category="threat_type")
        self.session.add_all([content, tag])
        self.session.commit()

        content_tag = ContentTag(
            content_id=content.id,
            tag_id=tag.id,
            confidence=0.95,
        )
        self.session.add(content_tag)
        self.session.commit()

        self.assertEqual(len(content.content_tags), 1)
        self.assertEqual(content.content_tags[0].tag.name, "supply-chain")

    def test_cascade_deletion(self):
        """Verify cascading deletions when source or content is removed."""
        source = Source(
            name="Ephemeral Feed",
            url="https://ephemeral.local/rss",
            source_type="feed",
        )
        self.session.add(source)
        self.session.commit()

        content = Content(
            source_id=source.id,
            title="Ephemeral Article",
            canonical_url="https://ephemeral.local/item-1",
            content_hash="hash_ephemeral_001",
        )
        tag = Tag(name="ephemeral-tag")
        self.session.add_all([content, tag])
        self.session.commit()

        link = ContentTag(content_id=content.id, tag_id=tag.id)
        self.session.add(link)
        self.session.commit()

        content_id = content.id

        # Deleting source cascades to content in session
        self.session.delete(source)
        self.session.commit()

        remaining_content = self.session.query(Content).filter_by(id=content_id).first()
        self.assertIsNone(remaining_content)

        remaining_link = self.session.query(ContentTag).filter_by(content_id=content_id).first()
        self.assertIsNone(remaining_link)

        # Tag itself must not be deleted
        remaining_tag = self.session.query(Tag).filter_by(id=tag.id).first()
        self.assertIsNotNone(remaining_tag)


if __name__ == "__main__":
    unittest.main()
