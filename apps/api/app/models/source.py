"""
Source Model
Represents registered intelligence sources (blogs, RSS feeds, security advisories, CVE feeds, GitHub repos).
Conforms strictly to IMPLEMENT.md Section 5 specification.
"""

from sqlalchemy import Boolean, Column, DateTime, Float, String
from sqlalchemy.orm import relationship
from app.models.base import BaseModel


class Source(BaseModel):
    """Source registry model tracking external content providers and reliability."""

    __tablename__ = "sources"

    name = Column(String(255), nullable=False, index=True)
    url = Column(String(2048), nullable=False, unique=True, index=True)
    source_type = Column(String(100), nullable=False, index=True)  # blog, advisory, cert, cve, vendor
    platform = Column(String(100), nullable=False, default="web")   # web, github, rss, api
    category = Column(String(100), nullable=True, index=True)      # application_security, malware, vulnerabilities
    language = Column(String(10), default="en", nullable=False)
    access_method = Column(String(50), default="rss", nullable=False)  # rss, api, scrape, search
    reliability_score = Column(Float, default=0.8, nullable=False)
    active = Column(Boolean, default=True, nullable=False, index=True)
    last_checked = Column(DateTime(timezone=True), nullable=True)

    # Relationship to harvested content items
    contents = relationship(
        "Content",
        back_populates="source",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Source(id={self.id}, name='{self.name}', type='{self.source_type}', active={self.active})>"
