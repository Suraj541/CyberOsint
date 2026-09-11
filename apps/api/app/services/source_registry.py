"""
Source Registry Service
Provides source management, connector resolution, connectivity probing,
and source catalog synchronization for the OSINT platform.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.source import Source
from app.schemas.source import SourceCreate, SourceUpdate
from connectors.base import BaseConnector, ConnectorHealth
from connectors.registry import connector_registry

logger = logging.getLogger("cyber_osint.source_registry")


class SourceRegistryService:
    """Service managing OSINT intelligence sources and coordinating their connector adapters."""

    def __init__(self, registry=connector_registry):
        self.registry = registry

    def create_source(self, db: Session, source_in: SourceCreate) -> Source:
        """Register a new source in the platform catalog."""
        db_source = Source(
            name=source_in.name,
            url=source_in.url,
            source_type=source_in.source_type,
            platform=source_in.platform,
            category=source_in.category,
            language=source_in.language,
            access_method=source_in.access_method,
            reliability_score=source_in.reliability_score,
            active=source_in.active,
        )
        db.add(db_source)
        db.commit()
        db.refresh(db_source)
        logger.info("Registered source id=%d name='%s' url='%s'", db_source.id, db_source.name, db_source.url)
        return db_source

    def get_source(self, db: Session, source_id: int) -> Optional[Source]:
        """Retrieve a source by its primary key ID."""
        return db.query(Source).filter(Source.id == source_id).first()

    def get_source_by_url(self, db: Session, url: str) -> Optional[Source]:
        """Look up a source by its unique endpoint URL."""
        return db.query(Source).filter(Source.url == url).first()

    def list_sources(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 100,
        active_only: bool = False,
        source_type: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Source]:
        """List registered sources with optional filtering."""
        query = db.query(Source)
        if active_only:
            query = query.filter(Source.active.is_(True))
        if source_type:
            query = query.filter(Source.source_type == source_type)
        if category:
            query = query.filter(Source.category == category)
        return query.order_by(Source.id.asc()).offset(skip).limit(limit).all()

    def update_source(self, db: Session, source: Source, update_data: SourceUpdate) -> Source:
        """Update source properties."""
        data_dict = update_data.model_dump(exclude_unset=True)
        for field, val in data_dict.items():
            setattr(source, field, val)
        db.commit()
        db.refresh(source)
        logger.info("Updated source id=%d name='%s'", source.id, source.name)
        return source

    def delete_source(self, db: Session, source: Source) -> None:
        """Remove a source and cascade deletions to associated harvested content."""
        source_id = source.id
        db.delete(source)
        db.commit()
        logger.info("Deleted source id=%d", source_id)

    def record_check_result(
        self,
        db: Session,
        source_id: int,
        success: bool,
        error_message: Optional[str] = None,
    ) -> Optional[Source]:
        """Update last_checked timestamp and reliability score adjustment."""
        source = self.get_source(db, source_id)
        if not source:
            return None
        source.last_checked = datetime.now(timezone.utc)
        if success:
            # Gradually reward consistent successful availability (up to 1.0)
            source.reliability_score = min(1.0, round(source.reliability_score + 0.01, 2))
        else:
            # Slightly decrease reliability on consecutive failures (down to 0.1)
            source.reliability_score = max(0.1, round(source.reliability_score - 0.05, 2))
        db.commit()
        db.refresh(source)
        return source

    def get_connector_for_source(self, source: Source) -> Optional[BaseConnector]:
        """
        Instantiate the appropriate BaseConnector for a given Source.
        Looks up by access_method first, then source_type.
        """
        source_config = {
            "id": source.id,
            "name": source.name,
            "url": source.url,
            "source_type": source.source_type,
            "access_method": source.access_method,
            "category": source.category,
        }
        # Try access_method (e.g. 'rss', 'api')
        if self.registry.has(source.access_method):
            return self.registry.create(source.access_method, source_config)
        # Fall back to source_type (e.g. 'blog', 'advisory')
        if self.registry.has(source.source_type):
            return self.registry.create(source.source_type, source_config)
        return None

    def check_source_health(self, db: Session, source_id: int) -> ConnectorHealth:
        """Run health check on a specific registered source using its connector."""
        source = self.get_source(db, source_id)
        if not source:
            return ConnectorHealth(
                status="failing",
                source_url="",
                error_message=f"Source with id {source_id} not found in database",
            )

        connector = self.get_connector_for_source(source)
        if not connector:
            health = ConnectorHealth(
                status="degraded",
                source_url=source.url,
                error_message=f"No connector registered for source_type='{source.source_type}' or access_method='{source.access_method}'",
                details={"active": source.active, "reliability_score": source.reliability_score},
            )
            self.record_check_result(db, source_id, success=False, error_message=health.error_message)
            return health

        try:
            health = connector.health_check()
            success = health.status == "ok"
            self.record_check_result(db, source_id, success=success, error_message=health.error_message)
            return health
        except Exception as exc:
            health = ConnectorHealth(
                status="failing",
                source_url=source.url,
                error_message=str(exc),
            )
            self.record_check_result(db, source_id, success=False, error_message=str(exc))
            return health

    def seed_default_sources(self, db: Session) -> List[Source]:
        """Seed default baseline security sources into the platform catalog."""
        default_sources = [
            SourceCreate(
                name="CISA Cybersecurity Advisories",
                url="https://www.cisa.gov/news-events/cybersecurity-advisories/all.xml",
                source_type="advisory",
                platform="web",
                category="vulnerabilities",
                access_method="rss",
                reliability_score=0.98,
                active=True,
            ),
            SourceCreate(
                name="National Vulnerability Database (NIST)",
                url="https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
                source_type="cve",
                platform="web",
                category="vulnerabilities",
                access_method="rss",
                reliability_score=0.99,
                active=True,
            ),
            SourceCreate(
                name="Krebs on Security",
                url="https://krebsonsecurity.com/feed/",
                source_type="blog",
                platform="web",
                category="threat_intel",
                access_method="rss",
                reliability_score=0.90,
                active=True,
            ),
            SourceCreate(
                name="The Hacker News",
                url="https://feeds.feedburner.com/TheHackersNews",
                source_type="news",
                platform="web",
                category="general_security",
                access_method="rss",
                reliability_score=0.85,
                active=True,
            ),
            SourceCreate(
                name="BleepingComputer",
                url="https://www.bleepingcomputer.com/feed/",
                source_type="news",
                platform="web",
                category="ransomware",
                access_method="rss",
                reliability_score=0.88,
                active=True,
            ),
        ]

        created: List[Source] = []
        for src_in in default_sources:
            existing = self.get_source_by_url(db, src_in.url)
            if not existing:
                created.append(self.create_source(db, src_in))
            else:
                created.append(existing)
        return created


# Singleton instance for services
source_registry_service = SourceRegistryService()
