"""
Content Chunk & Vector Embedding Model
Stores document chunks and high-dimensional semantic embeddings for vector similarity
and hybrid search operations.
Conforms to IMPLEMENT.md Section 19.
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    Text,
)
from sqlalchemy.orm import relationship
from app.models.base import Base


class ContentChunk(Base):
    """
    Individual text chunk of an ingested Content record with its associated
    384-dimensional dense semantic embedding vector.
    """

    __tablename__ = "content_chunks"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    content_id = Column(
        Integer,
        ForeignKey("content.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    chunk_index = Column(Integer, nullable=False, default=0)
    chunk_text = Column(Text, nullable=False)
    chunk_tokens = Column(Integer, nullable=True)
    embedding = Column(JSON, nullable=True)  # 384-dimensional float vector
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    content = relationship("Content", back_populates="chunks")

    def __repr__(self) -> str:
        tokens = self.chunk_tokens or len(self.chunk_text.split())
        return f"<ContentChunk(id={self.id}, content_id={self.content_id}, index={self.chunk_index}, tokens={tokens})>"
