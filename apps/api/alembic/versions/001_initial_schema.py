"""Initial schema creating users, sources, content, entities, content_entities, tags, and content_tags.

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-09-11 21:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. users table
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("role", sa.String(length=50), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_users_id", "users", ["id"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # 2. sources table
    op.create_table(
        "sources",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=False),
        sa.Column("source_type", sa.String(length=100), nullable=False),
        sa.Column("platform", sa.String(length=100), nullable=False, server_default="web"),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("language", sa.String(length=10), nullable=False, server_default="en"),
        sa.Column("access_method", sa.String(length=50), nullable=False, server_default="rss"),
        sa.Column("reliability_score", sa.Float(), nullable=False, server_default="0.8"),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_checked", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_sources_id", "sources", ["id"], unique=False)
    op.create_index("ix_sources_name", "sources", ["name"], unique=False)
    op.create_index("ix_sources_url", "sources", ["url"], unique=True)
    op.create_index("ix_sources_source_type", "sources", ["source_type"], unique=False)
    op.create_index("ix_sources_category", "sources", ["category"], unique=False)
    op.create_index("ix_sources_active", "sources", ["active"], unique=False)

    # 3. content table
    op.create_table(
        "content",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=True),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("content_type", sa.String(length=50), nullable=False, server_default="article"),
        sa.Column("canonical_url", sa.String(length=2048), nullable=False),
        sa.Column("author", sa.String(length=255), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("language", sa.String(length=10), nullable=False, server_default="en"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("raw_content", sa.Text(), nullable=True),
        sa.Column("content_hash", sa.String(length=64), nullable=False),
        sa.Column("quality_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("relevance_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("confidence_score", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="discovered"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_content_id", "content", ["id"], unique=False)
    op.create_index("ix_content_source_id", "content", ["source_id"], unique=False)
    op.create_index("ix_content_content_type", "content", ["content_type"], unique=False)
    op.create_index("ix_content_canonical_url", "content", ["canonical_url"], unique=False)
    op.create_index("ix_content_published_at", "content", ["published_at"], unique=False)
    op.create_index("ix_content_content_hash", "content", ["content_hash"], unique=False)
    op.create_index("ix_content_status", "content", ["status"], unique=False)
    op.create_index("ix_content_hash_canonical", "content", ["content_hash", "canonical_url"], unique=False)

    # 4. entities table
    op.create_table(
        "entities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("entity_type", sa.String(length=50), nullable=False),
        sa.Column("normalized_name", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("entity_type", "normalized_name", name="uq_entity_type_normalized_name"),
    )
    op.create_index("ix_entities_id", "entities", ["id"], unique=False)
    op.create_index("ix_entities_name", "entities", ["name"], unique=False)
    op.create_index("ix_entities_entity_type", "entities", ["entity_type"], unique=False)
    op.create_index("ix_entities_normalized_name", "entities", ["normalized_name"], unique=False)

    # 5. content_entities table
    op.create_table(
        "content_entities",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("content_id", sa.Integer(), nullable=False),
        sa.Column("entity_id", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("extraction_method", sa.String(length=50), nullable=False, server_default="regex"),
        sa.Column("context_snippet", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_id"], ["content.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["entity_id"], ["entities.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("content_id", "entity_id", name="uq_content_entity"),
    )
    op.create_index("ix_content_entities_id", "content_entities", ["id"], unique=False)
    op.create_index("ix_content_entities_content_id", "content_entities", ["content_id"], unique=False)
    op.create_index("ix_content_entities_entity_id", "content_entities", ["entity_id"], unique=False)

    # 6. tags table
    op.create_table(
        "tags",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("category", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tags_id", "tags", ["id"], unique=False)
    op.create_index("ix_tags_name", "tags", ["name"], unique=True)
    op.create_index("ix_tags_category", "tags", ["category"], unique=False)

    # 7. content_tags table
    op.create_table(
        "content_tags",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("content_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["content_id"], ["content.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["tags.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("content_id", "tag_id", name="uq_content_tag"),
    )
    op.create_index("ix_content_tags_id", "content_tags", ["id"], unique=False)
    op.create_index("ix_content_tags_content_id", "content_tags", ["content_id"], unique=False)
    op.create_index("ix_content_tags_tag_id", "content_tags", ["tag_id"], unique=False)


def downgrade() -> None:
    op.drop_table("content_tags")
    op.drop_table("tags")
    op.drop_table("content_entities")
    op.drop_table("entities")
    op.drop_table("content")
    op.drop_table("sources")
    op.drop_table("users")
