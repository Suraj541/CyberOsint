"""
Ingestion Pipeline Core Orchestrator
Executes the standardized cybersecurity OSINT ingestion pipeline:
Connector -> Discovery -> Validation -> Normalization -> Deduplication -> Database Storage.
Tracks complete execution telemetry: ingested items, duplicates skipped, and errors.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from app.models.tag import ContentTag, Tag
from connectors.base import BaseConnector, NormalizedItem
from connectors.registry import connector_registry
from packages.classifier import rule_classifier
from services.ingestion.deduplication import Deduplicator, compute_content_hash
from services.ingestion.metrics import IngestionMetrics
from services.ingestion.validation import ItemValidator

logger = logging.getLogger("cyber_osint.services.ingestion.pipeline")


def _parse_published_datetime(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO or RFC date strings safely into timezone-aware datetime objects."""
    if not date_str:
        return None
    try:
        # Standard ISO 8601 (feedparser parsed dates usually formatted as ISO in RSSConnector)
        cleaned = date_str.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


class IngestionPipeline:
    """
    Standardized ingestion orchestrator executing:
    Connector -> Discovery -> Validation -> Normalization -> Deduplication -> Database Storage.
    """

    def __init__(self):
        self.validator = ItemValidator()
        self.deduplicator = Deduplicator()

    def run(
        self,
        db: Session,
        connector: BaseConnector,
        source_id: Optional[int] = None,
        source_name: Optional[str] = None,
    ) -> IngestionMetrics:
        """
        Execute the complete ingestion pipeline for a connector.
        Tracks all metrics: discovered, validated, normalized, ingested, duplicates, and errors.
        """
        effective_source_name = source_name or connector.source_name or "Unknown Source"
        metrics = IngestionMetrics(
            source_id=source_id,
            source_name=effective_source_name,
        )
        in_memory_seen: Set[str] = set()

        logger.info(
            "Starting ingestion pipeline for source '%s' (id=%s)",
            effective_source_name,
            source_id,
        )

        # -------------------------------------------------------------
        # STEP 1: Discovery
        # -------------------------------------------------------------
        try:
            raw_items = connector.discover()
        except Exception as exc:
            err_msg = f"Discovery error on '{effective_source_name}': {exc}"
            logger.error(err_msg, exc_info=True)
            metrics.record_error(err_msg)
            return metrics.finish(status_override="failed")

        metrics.discovered_count = len(raw_items)
        if metrics.discovered_count == 0:
            logger.info("Discovery returned 0 items for '%s'", effective_source_name)
            return metrics.finish(status_override="empty")

        # -------------------------------------------------------------
        # STEPS 2 to 5: Iterate, Validate, Normalize, Deduplicate, Store
        # -------------------------------------------------------------
        for raw_item in raw_items:
            # Step 2: Raw Validation
            is_valid_raw, raw_err = self.validator.validate_raw_item(raw_item)
            if not is_valid_raw:
                metrics.record_error(f"Malformed item skipped: {raw_err}")
                continue
            metrics.validated_count += 1

            # Step 3: Normalization (fetch -> parse -> normalize)
            try:
                fetched = connector.fetch(raw_item)
                parsed = connector.parse(fetched)
                normalized: NormalizedItem = connector.normalize(parsed)
            except Exception as exc:
                err_msg = f"Normalization failed on item: {exc}"
                logger.warning(err_msg)
                metrics.record_error(err_msg)
                continue

            # Validate NormalizedItem contract
            is_valid_norm, norm_err = self.validator.validate_normalized_item(normalized)
            if not is_valid_norm:
                metrics.record_error(f"Item failed contract validation: {norm_err}")
                continue
            metrics.normalized_count += 1

            # Step 4: Deduplication (SHA-256 Content Hash)
            content_hash = compute_content_hash(
                url=normalized.url,
                title=normalized.title,
                raw_content=normalized.raw_content,
            )

            if self.deduplicator.is_duplicate(db, content_hash, in_memory_seen):
                metrics.record_duplicate(content_hash, normalized.title)
                continue

            # Register hash in batch cache immediately
            self.deduplicator.register_seen(content_hash, in_memory_seen)

            # Step 5: Database Storage
            try:
                published_dt = _parse_published_datetime(normalized.published_at)

                content = Content(
                    source_id=source_id,
                    title=normalized.title[:512],
                    description=normalized.description,
                    content_type=normalized.content_type or "article",
                    canonical_url=normalized.url[:2048],
                    author=(normalized.author or effective_source_name)[:255],
                    published_at=published_dt,
                    discovered_at=datetime.now(timezone.utc),
                    language=normalized.language or "en",
                    summary=None,
                    raw_content=normalized.raw_content,
                    content_hash=content_hash,
                    quality_score=0.0,
                    relevance_score=0.0,
                    confidence_score=1.0,
                    status="discovered",
                )
                db.add(content)
                db.flush()  # Generate content.id

                # Link taxonomy tags if provided in metadata
                tags_list = normalized.metadata.get("tags") or []
                if isinstance(tags_list, list):
                    for tag_name in tags_list:
                        if not tag_name or not isinstance(tag_name, str):
                            continue
                        clean_tag = tag_name.strip()[:100]
                        if not clean_tag:
                            continue
                        tag_obj = db.query(Tag).filter(Tag.name == clean_tag).first()
                        if not tag_obj:
                            tag_obj = Tag(name=clean_tag, category="topic")
                            db.add(tag_obj)
                            db.flush()

                        # Associate ContentTag
                        content_tag = ContentTag(
                            content_id=content.id,
                            tag_id=tag_obj.id,
                            confidence=1.0,
                        )
                        db.add(content_tag)

                # Link structured and regex-extracted entities
                self._link_entities(db, content, normalized)

                # Automatic Cybersecurity Taxonomy Classification
                classification = rule_classifier.classify(
                    title=normalized.title,
                    description=normalized.description,
                    content_text=normalized.raw_content,
                    metadata=normalized.metadata,
                )
                normalized.metadata["classification"] = classification.to_dict()

                # Link predicted primary domain tag
                domain_tag = db.query(Tag).filter(Tag.name == classification.category).first()
                if not domain_tag:
                    domain_tag = Tag(name=classification.category, category="domain")
                    db.add(domain_tag)
                    db.flush()

                ct_domain = ContentTag(
                    content_id=content.id,
                    tag_id=domain_tag.id,
                    confidence=classification.confidence,
                )
                db.add(ct_domain)

                # Link predicted subcategory tag if present
                if classification.subcategory:
                    subdomain_tag = db.query(Tag).filter(Tag.name == classification.subcategory).first()
                    if not subdomain_tag:
                        subdomain_tag = Tag(name=classification.subcategory, category="subdomain")
                        db.add(subdomain_tag)
                        db.flush()

                    ct_subdomain = ContentTag(
                        content_id=content.id,
                        tag_id=subdomain_tag.id,
                        confidence=classification.confidence,
                    )
                    db.add(ct_subdomain)

                db.commit()
                metrics.record_ingested(
                    content_id=content.id,
                    title=content.title,
                    url=content.canonical_url,
                    content_hash=content.content_hash,
                )

            except Exception as exc:
                db.rollback()
                err_msg = f"Database storage failed for item '{normalized.title[:40]}': {exc}"
                logger.error(err_msg, exc_info=True)
                metrics.record_error(err_msg)

        # -------------------------------------------------------------
        # STEP 6: Update Source Telemetry
        # -------------------------------------------------------------
        if source_id:
            try:
                source = db.query(Source).filter(Source.id == source_id).first()
                if source:
                    source.last_checked = datetime.now(timezone.utc)
                    db.commit()
            except Exception as exc:
                logger.warning("Failed to update source %s last_checked: %s", source_id, exc)

        metrics.finish()
        logger.info(
            "Ingestion completed for '%s': %d ingested, %d duplicates skipped, %d errors in %.2fms (status: %s)",
            effective_source_name,
            metrics.ingested_count,
            metrics.duplicates_skipped,
            metrics.errors_count,
            metrics.duration_ms,
            metrics.status,
        )
        return metrics

    def _link_entities(
        self,
        db: Session,
        content: Content,
        normalized: NormalizedItem,
    ) -> None:
        """
        Extract and link cybersecurity entities (CVEs, products, CWEs, advisories)
        into Entity and ContentEntity tables.
        Supports both structured entities from connector metadata and automated regex extraction.
        """
        seen_entity_ids: Set[int] = set()

        # 1. Structured entities from connector metadata
        structured_entities = normalized.metadata.get("entities") or []
        if isinstance(structured_entities, list):
            for ent_dict in structured_entities:
                if not isinstance(ent_dict, dict):
                    continue
                raw_name = ent_dict.get("name")
                raw_type = str(ent_dict.get("type", "generic")).lower().strip()
                if not raw_name or not isinstance(raw_name, str):
                    continue

                clean_name = raw_name.strip()[:255]
                normalized_name = clean_name.upper() if raw_type == "cve" else clean_name.lower()
                description = ent_dict.get("description")
                metadata_dict = ent_dict.get("metadata") or {}
                meta_json = json.dumps(metadata_dict, default=str) if metadata_dict else None

                # Find or create Entity
                entity_obj = (
                    db.query(Entity)
                    .filter(
                        Entity.entity_type == raw_type,
                        Entity.normalized_name == normalized_name,
                    )
                    .first()
                )
                if not entity_obj:
                    entity_obj = Entity(
                        name=clean_name,
                        entity_type=raw_type,
                        normalized_name=normalized_name,
                        description=description,
                        metadata_json=meta_json,
                    )
                    db.add(entity_obj)
                    db.flush()
                else:
                    if meta_json and not entity_obj.metadata_json:
                        entity_obj.metadata_json = meta_json
                        db.flush()

                if entity_obj.id not in seen_entity_ids:
                    seen_entity_ids.add(entity_obj.id)
                    content_entity = ContentEntity(
                        content_id=content.id,
                        entity_id=entity_obj.id,
                        confidence=1.0,
                        extraction_method="structured",
                        context_snippet=clean_name,
                    )
                    db.add(content_entity)

        # 2. Automated Regex Extraction for CVEs in free text (title + description)
        search_corpus = f"{content.title} {content.description or ''}"
        cve_matches = re.findall(r"\b(CVE-\d{4}-\d{4,7})\b", search_corpus, re.IGNORECASE)
        for cve_str in cve_matches:
            cve_id = cve_str.upper().strip()
            entity_obj = (
                db.query(Entity)
                .filter(
                    Entity.entity_type == "cve",
                    Entity.normalized_name == cve_id,
                )
                .first()
            )
            if not entity_obj:
                entity_obj = Entity(
                    name=cve_id,
                    entity_type="cve",
                    normalized_name=cve_id,
                    description=f"Automated extraction for {cve_id}",
                    metadata_json=json.dumps({"extracted_via": "regex"}, default=str),
                )
                db.add(entity_obj)
                db.flush()

            if entity_obj.id not in seen_entity_ids:
                seen_entity_ids.add(entity_obj.id)
                content_entity = ContentEntity(
                    content_id=content.id,
                    entity_id=entity_obj.id,
                    confidence=0.9,
                    extraction_method="regex",
                    context_snippet=f"Mentioned in '{content.title[:100]}'",
                )
                db.add(content_entity)

    def ingest_source(
        self,
        db: Session,
        source: Source,
        connector_override: Optional[BaseConnector] = None,
    ) -> IngestionMetrics:
        """
        Execute ingestion for a registered Source entity.
        Resolves the appropriate connector from connector_registry.
        """
        if connector_override is not None:
            return self.run(
                db=db,
                connector=connector_override,
                source_id=source.id,
                source_name=source.name,
            )

        # Determine connector type key
        conn_key = (source.access_method or source.source_type or "rss").lower()
        if not connector_registry.has(conn_key):
            # Fallback to source_type or rss
            if connector_registry.has(source.source_type.lower()):
                conn_key = source.source_type.lower()
            elif connector_registry.has("rss"):
                conn_key = "rss"
            else:
                metrics = IngestionMetrics(source_id=source.id, source_name=source.name)
                metrics.record_error(f"No connector registered for access method '{conn_key}'")
                return metrics.finish(status_override="failed")

        connector_config = {
            "source_id": source.id,
            "name": source.name,
            "url": source.url,
            "category": source.category,
            "language": source.language,
        }

        try:
            connector = connector_registry.create(conn_key, connector_config)
        except Exception as exc:
            metrics = IngestionMetrics(source_id=source.id, source_name=source.name)
            metrics.record_error(f"Failed to instantiate connector '{conn_key}': {exc}")
            return metrics.finish(status_override="failed")

        return self.run(
            db=db,
            connector=connector,
            source_id=source.id,
            source_name=source.name,
        )

    def ingest_source_by_id(self, db: Session, source_id: int) -> IngestionMetrics:
        """Fetch source by ID and execute ingestion pipeline."""
        source = db.query(Source).filter(Source.id == source_id).first()
        if not source:
            raise ValueError(f"Source with id {source_id} does not exist")
        return self.ingest_source(db, source)


# Global singleton instance
ingestion_pipeline = IngestionPipeline()
