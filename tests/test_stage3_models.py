"""
Stage 3: PostgreSQL Models & Initial Schema Verification Tests
Ensures all 7 mandated core tables (users, sources, content, entities,
content_entities, tags, content_tags), indexes, and constraints conform to IMPLEMENT.md Sections 4, 5, and 6.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for path in (repo_root, api_root):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from sqlalchemy import inspect
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


class TestStage3ModelsBaseline(unittest.TestCase):
    """Test suite validating complete implementation of Stage 3 (Database Models & Schema)."""

    def test_all_seven_tables_declared(self):
        """Confirm all 7 mandated tables exist in Base.metadata."""
        declared_tables = Base.metadata.tables.keys()
        mandated_tables = [
            "users",
            "sources",
            "content",
            "entities",
            "content_entities",
            "tags",
            "content_tags",
        ]

        for table in mandated_tables:
            self.assertIn(
                table,
                declared_tables,
                f"Mandated table '{table}' is missing from SQLAlchemy metadata",
            )

    def test_source_table_fields_conformance(self):
        """Validate sources table column set against Section 5 specification."""
        cols = {c.name for c in Source.__table__.columns}
        mandated_cols = {
            "id",
            "name",
            "url",
            "source_type",
            "platform",
            "category",
            "language",
            "access_method",
            "reliability_score",
            "active",
            "last_checked",
            "created_at",
            "updated_at",
        }
        self.assertTrue(
            mandated_cols.issubset(cols),
            f"Source table missing mandated columns: {mandated_cols - cols}",
        )

    def test_content_table_fields_and_indexes_conformance(self):
        """Validate content table column set and required indexes against Section 6 specification."""
        cols = {c.name for c in Content.__table__.columns}
        mandated_cols = {
            "id",
            "source_id",
            "title",
            "description",
            "content_type",
            "canonical_url",
            "author",
            "published_at",
            "discovered_at",
            "language",
            "summary",
            "content_hash",
            "quality_score",
            "relevance_score",
            "confidence_score",
            "status",
            "created_at",
            "updated_at",
        }
        self.assertTrue(
            mandated_cols.issubset(cols),
            f"Content table missing mandated columns: {mandated_cols - cols}",
        )

        # Check required indexes: published_at, source_id, content_type, content_hash, canonical_url
        indexed_cols = set()
        for idx in Content.__table__.indexes:
            for col in idx.columns:
                indexed_cols.add(col.name)

        mandated_indexed_cols = {
            "published_at",
            "source_id",
            "content_type",
            "content_hash",
            "canonical_url",
        }
        self.assertTrue(
            mandated_indexed_cols.issubset(indexed_cols),
            f"Content table missing indexes on: {mandated_indexed_cols - indexed_cols}",
        )

    def test_alembic_migration_file_exists(self):
        """Confirm Alembic migration script 001_initial_schema.py is present."""
        migration_file = api_root / "alembic" / "versions" / "001_initial_schema.py"
        self.assertTrue(migration_file.exists(), "Alembic migration 001_initial_schema.py not found")
        content = migration_file.read_text(encoding="utf-8")
        self.assertIn("users", content)
        self.assertIn("sources", content)
        self.assertIn("content", content)
        self.assertIn("entities", content)
        self.assertIn("content_entities", content)
        self.assertIn("tags", content)
        self.assertIn("content_tags", content)


if __name__ == "__main__":
    unittest.main()
