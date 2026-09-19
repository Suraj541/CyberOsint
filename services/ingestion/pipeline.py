"""
Ingestion Pipeline Core Orchestrator
Executes the standardized cybersecurity OSINT ingestion pipeline:
Connector -> Discovery -> Validation -> Normalization -> Deduplication -> Database Storage.
Tracks complete execution telemetry: ingested items, duplicates skipped, and errors.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.source import Source
from app.models.tag import ContentTag, Tag
from connectors.base import BaseConnector, NormalizedItem
from connectors.registry import connector_registry
from packages.classifier import rule_classifier
from packages.extractor import entity_extractor
from packages.mitre import mitre_service
from services.deduplication import deduplication_engine, normalize_url
from services.ingestion.deduplication import Deduplicator, compute_content_hash
from services.ingestion.metrics import IngestionMetrics
from services.ingestion.validation import ItemValidator
from services.graph import knowledge_graph_service
from services.notification import notification_pipeline
from services.reliability import source_reliability_service
from services.search import search_service
from services.semantic import semantic_service
from services.observability.collector import metrics_collector

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

            # Step 4 & 5: Deduplication, Upsert, and Storage (CVE & Record Synchronization)
            self._upsert_or_store_item(
                db=db,
                normalized=normalized,
                source_id=source_id,
                effective_source_name=effective_source_name,
                metrics=metrics,
                in_memory_seen=in_memory_seen,
            )

        # -------------------------------------------------------------
        # STEP 6: Update Source Telemetry & Reliability Quality (Section 28)
        # -------------------------------------------------------------
        if source_id:
            try:
                source = db.query(Source).filter(Source.id == source_id).first()
                if source:
                    source.last_checked = datetime.now(timezone.utc)
                    db.commit()
                    # Trigger source reliability quality update (Section 28)
                    try:
                        source_reliability_service.update_or_create_source_quality(db, source_id)
                    except Exception as q_exc:
                        logger.debug("Source quality update skipped for source %s: %s", source_id, q_exc)
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

        # Section 41 Step 40: push run metrics into the global observability collector
        try:
            metrics_collector.record_ingestion_run(metrics, connector_name=effective_source_name)
        except Exception as _obs_err:
            logger.debug("Observability metrics update skipped: %s", _obs_err)

        return metrics

    def ingest_items(
        self,
        db: Session,
        items: List[NormalizedItem],
        source_id: Optional[int] = None,
        source_name: Optional[str] = None,
    ) -> IngestionMetrics:
        """
        Ingests pre-normalized items directly through validation, deduplication,
        storage, entity linking, taxonomy classification, chunking, and commits.
        """
        effective_source_name = source_name or "Direct Normalized Ingestion"
        metrics = IngestionMetrics(
            source_id=source_id,
            source_name=effective_source_name,
        )
        in_memory_seen: Set[str] = set()

        metrics.discovered_count = len(items)
        if metrics.discovered_count == 0:
            return metrics.finish(status_override="empty")

        for normalized in items:
            is_valid_norm, norm_err = self.validator.validate_normalized_item(normalized)
            if not is_valid_norm:
                metrics.record_error(f"Item failed contract validation: {norm_err}")
                continue
            metrics.validated_count += 1
            metrics.normalized_count += 1

            # Step 4 & 5: Deduplication, Upsert, and Storage (CVE & Record Synchronization)
            self._upsert_or_store_item(
                db=db,
                normalized=normalized,
                source_id=source_id,
                effective_source_name=effective_source_name,
                metrics=metrics,
                in_memory_seen=in_memory_seen,
            )

        if source_id:
            try:
                source = db.query(Source).filter(Source.id == source_id).first()
                if source:
                    source.last_checked = datetime.now(timezone.utc)
                    db.commit()
            except Exception as exc:
                logger.warning("Failed to update source %s last_checked: %s", source_id, exc)

        metrics.finish()
        try:
            metrics_collector.record_ingestion_run(metrics, connector_name=effective_source_name)
        except Exception as _obs_err:
            logger.debug("Observability metrics update skipped: %s", _obs_err)

        return metrics

    def _upsert_or_store_item(
        self,
        db: Session,
        normalized: NormalizedItem,
        source_id: Optional[int],
        effective_source_name: str,
        metrics: IngestionMetrics,
        in_memory_seen: Set[str],
    ) -> None:
        """
        Unified deduplication, upsert, and storage orchestrator.
        Guarantees:
        - Deterministic CVE identification via CVE-ID (e.g. CVE-2024-3400).
        - If modified upstream (CVSS, CWE, affected products, description, references, or hash):
          Updates existing Content and Entity records in-place without duplicate rows.
        - If exact duplicate: records audit link in DuplicateLink and skips.
        - If genuine new item: stores Content, extracts and links entities, classifies taxonomy, and commits.
        """
        content_hash = compute_content_hash(
            url=normalized.url,
            title=normalized.title,
            raw_content=normalized.raw_content,
        )

        clean_url = normalize_url(normalized.url) if normalized.url else ""

        # -------------------------------------------------------------
        # 1. Deterministic Identifier Resolution (CVE-ID or Canonical URL)
        # -------------------------------------------------------------
        cve_id: Optional[str] = normalized.metadata.get("cve_id")
        if not cve_id and (normalized.title or normalized.url):
            cve_match = re.search(r"\bCVE-\d{4}-\d{4,7}\b", f"{normalized.title} {normalized.url}", re.IGNORECASE)
            if cve_match:
                cve_id = cve_match.group(0).upper()

        # Concurrency: under PostgreSQL, serialize concurrent workers processing the exact same item
        try:
            if db.bind and "postgresql" in getattr(db.bind.dialect, "name", ""):
                lock_source = cve_id or clean_url or content_hash
                if lock_source:
                    lock_id = (
                        int(hashlib.md5(lock_source.encode("utf-8")).hexdigest()[:8], 16) - 0x80000000
                    )
                    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_id})
        except Exception as lock_err:
            logger.debug("Advisory transaction lock skipped: %s", lock_err)

        existing_content: Optional[Content] = None
        cve_entity: Optional[Entity] = None

        if cve_id:
            cve_id_clean = cve_id.strip().upper()
            cve_entity = (
                db.query(Entity)
                .filter(
                    Entity.entity_type == "cve",
                    (Entity.name == cve_id_clean)
                    | (Entity.normalized_name == cve_id_clean)
                    | (Entity.normalized_name == cve_id_clean.lower()),
                )
                .first()
            )
            if cve_entity:
                link = db.query(ContentEntity).filter(ContentEntity.entity_id == cve_entity.id).first()
                if link:
                    existing_content = db.query(Content).filter(Content.id == link.content_id).first()

            if not existing_content:
                existing_content = (
                    db.query(Content)
                    .filter(
                        (Content.canonical_url == normalized.url)
                        | (Content.canonical_url == clean_url)
                        | (Content.canonical_url.ilike(f"%{cve_id_clean}%"))
                        | (Content.title.ilike(f"%{cve_id_clean}%"))
                    )
                    .first()
                )
                if existing_content and not cve_entity:
                    c_link = db.query(ContentEntity).filter(ContentEntity.content_id == existing_content.id).first()
                    if c_link:
                        cve_entity = db.query(Entity).filter(Entity.id == c_link.entity_id, Entity.entity_type == "cve").first()

        # Non-CVE or unresolved: check exact canonical URL match
        if not existing_content and clean_url and not clean_url.startswith("urn:"):
            existing_content = (
                db.query(Content)
                .filter((Content.canonical_url == normalized.url) | (Content.canonical_url == clean_url))
                .order_by(Content.id.asc())
                .first()
            )

        # Content Hash Lookup (exact payload fingerprint)
        if not existing_content and content_hash:
            existing_content = (
                db.query(Content)
                .filter(Content.content_hash == content_hash)
                .order_by(Content.id.asc())
                .first()
            )

        # -------------------------------------------------------------
        # 2. Existing Item Found: Check for Modifications (Upsert Semantics)
        # -------------------------------------------------------------
        if existing_content:
            old_meta = {}
            if cve_entity and cve_entity.metadata_json:
                try:
                    old_meta = json.loads(cve_entity.metadata_json)
                except Exception:
                    old_meta = {}

            # Check if any mutable field has changed
            hash_diff = (content_hash != existing_content.content_hash)
            title_diff = ((normalized.title or "").strip() != (existing_content.title or "").strip())
            desc_diff = ((normalized.description or "").strip() != (existing_content.description or "").strip())

            new_cvss = normalized.metadata.get("cvss_score")
            new_sev = normalized.metadata.get("severity")
            new_cwe = normalized.metadata.get("weakness")
            new_prods = normalized.metadata.get("affected_products")
            new_refs = normalized.metadata.get("references")
            new_mod_at = normalized.metadata.get("modified_at")

            cve_meta_diff = False
            if cve_entity:
                if new_cvss is not None and old_meta.get("cvss_score") != new_cvss:
                    cve_meta_diff = True
                if new_sev is not None and old_meta.get("severity") != new_sev:
                    cve_meta_diff = True
                if new_cwe is not None and old_meta.get("weakness") != new_cwe:
                    cve_meta_diff = True
                if new_prods is not None and old_meta.get("affected_products") != new_prods:
                    cve_meta_diff = True
                if new_refs is not None and old_meta.get("references") != new_refs:
                    cve_meta_diff = True
                if new_mod_at is not None and old_meta.get("modified_at") != new_mod_at:
                    cve_meta_diff = True

            is_modified = hash_diff or title_diff or desc_diff or cve_meta_diff

            if is_modified:
                # UPDATE the existing record
                try:
                    existing_content.title = normalized.title[:512]
                    existing_content.description = normalized.description
                    existing_content.raw_content = normalized.raw_content
                    existing_content.content_hash = content_hash
                    existing_content.status = "updated"
                    existing_content.updated_at = datetime.now(timezone.utc)
                    pub_dt = _parse_published_datetime(normalized.published_at)
                    if pub_dt and not existing_content.published_at:
                        existing_content.published_at = pub_dt

                    # Update CVE Entity mutable fields
                    if cve_entity:
                        cve_entity.description = (normalized.description or cve_entity.description)[:500]
                        cve_entity.updated_at = datetime.now(timezone.utc)
                        for k, v in [
                            ("cvss_score", new_cvss),
                            ("severity", new_sev),
                            ("weakness", new_cwe),
                            ("affected_products", new_prods),
                            ("references", new_refs),
                            ("modified_at", new_mod_at),
                        ]:
                            if v is not None:
                                old_meta[k] = v
                        cve_entity.metadata_json = json.dumps(old_meta, default=str)

                    # Link any newly discovered entities (e.g. new CWE or product)
                    self._link_entities(db, existing_content, normalized)

                    db.commit()

                    metrics.record_updated(
                        content_id=existing_content.id,
                        title=existing_content.title,
                        url=existing_content.canonical_url,
                        content_hash=content_hash,
                    )

                    # Re-index in search & semantic vector store
                    try:
                        search_service.index_content(
                            db=db,
                            content_id=existing_content.id,
                            category=normalized.metadata.get("category", "vulnerability"),
                            tags=normalized.metadata.get("tags", []),
                        )
                    except Exception as s_exc:
                        logger.debug("Search index update skipped on item %s: %s", existing_content.id, s_exc)

                    try:
                        semantic_service.index_content(
                            db=db,
                            content_id=existing_content.id,
                        )
                    except Exception as sem_exc:
                        logger.debug("Semantic index update skipped on item %s: %s", existing_content.id, sem_exc)



                    # Register in batch cache
                    self.deduplicator.register_seen(content_hash, in_memory_seen)
                    if clean_url:
                        in_memory_seen.add(clean_url)
                    return
                except Exception as exc:
                    db.rollback()
                    err_msg = f"Update failed for item '{normalized.title[:40]}': {exc}"
                    logger.error(err_msg, exc_info=True)
                    metrics.record_error(err_msg)
                    return
            else:
                # Exact duplicate unchanged record: Record duplicate link and skip
                try:
                    dup_match_type = "exact_url" if (existing_content.canonical_url in (normalized.url, clean_url)) else "exact_hash"
                    deduplication_engine.record_duplicate_link(
                        db=db,
                        canonical_id=existing_content.id,
                        duplicate_id=None,
                        match_type=dup_match_type,
                        similarity_score=1.0,
                    )
                    db.commit()
                except Exception as dup_err:
                    db.rollback()
                    logger.debug("Failed to record duplicate link: %s", dup_err)

                metrics.record_duplicate(content_hash, normalized.title)
                self.deduplicator.register_seen(content_hash, in_memory_seen)
                if clean_url:
                    in_memory_seen.add(clean_url)
                return

        # -------------------------------------------------------------
        # 3. New Item: Deduplication Engine Check (Fuzzy / Cluster)
        # -------------------------------------------------------------
        dup_result = deduplication_engine.evaluate(
            db=db,
            item=normalized,
            in_memory_seen=in_memory_seen,
        )

        if dup_result.is_duplicate:
            if dup_result.canonical_id:
                try:
                    deduplication_engine.record_duplicate_link(
                        db=db,
                        canonical_id=dup_result.canonical_id,
                        duplicate_id=None,
                        match_type=dup_result.match_type or "exact_hash",
                        similarity_score=dup_result.similarity_score,
                        cluster_id=dup_result.cluster_id,
                        metrics=dup_result.metrics,
                    )
                    db.commit()
                except Exception as dup_err:
                    db.rollback()
                    logger.debug("Failed to record duplicate link: %s", dup_err)

            metrics.record_duplicate(content_hash, normalized.title)
            self.deduplicator.register_seen(content_hash, in_memory_seen)
            if clean_url:
                in_memory_seen.add(clean_url)
            return

        # Register in batch seen cache
        self.deduplicator.register_seen(content_hash, in_memory_seen)
        if clean_url:
            in_memory_seen.add(clean_url)

        # -------------------------------------------------------------
        # 4. Database Storage for Genuine New Item
        # -------------------------------------------------------------
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
            try:
                with db.begin_nested():
                    db.add(content)
                    db.flush()
            except IntegrityError:
                existing = (
                    db.query(Content)
                    .filter((Content.canonical_url == normalized.url) | (Content.content_hash == content_hash))
                    .first()
                )
                if existing:
                    metrics.duplicates_skipped += 1
                    return
                raise

            # Associate Taxonomy & Discovery Tags
            seen_tag_ids: Set[int] = set()
            tags_list = normalized.metadata.get("tags") or []
            if isinstance(tags_list, list):
                for tag_name in tags_list:
                    if not tag_name or not isinstance(tag_name, str):
                        continue
                    clean_tag = tag_name.strip()[:100]
                    if not clean_tag:
                        continue
                    tag_obj = self._get_or_create_tag(db, clean_tag, "topic")
                    if tag_obj and tag_obj.id not in seen_tag_ids:
                        seen_tag_ids.add(tag_obj.id)
                        try:
                            with db.begin_nested():
                                content_tag = ContentTag(
                                    content_id=content.id,
                                    tag_id=tag_obj.id,
                                    confidence=1.0,
                                )
                                db.add(content_tag)
                                db.flush()
                        except IntegrityError:
                            pass

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

            domain_tag = self._get_or_create_tag(db, classification.category, "domain")
            if domain_tag and domain_tag.id not in seen_tag_ids:
                seen_tag_ids.add(domain_tag.id)
                try:
                    with db.begin_nested():
                        ct_domain = ContentTag(
                            content_id=content.id,
                            tag_id=domain_tag.id,
                            confidence=classification.confidence,
                        )
                        db.add(ct_domain)
                        db.flush()
                except IntegrityError:
                    pass

            if classification.subcategory:
                subdomain_tag = self._get_or_create_tag(db, classification.subcategory, "subdomain")
                if subdomain_tag and subdomain_tag.id not in seen_tag_ids:
                    seen_tag_ids.add(subdomain_tag.id)
                    try:
                        with db.begin_nested():
                            ct_subdomain = ContentTag(
                                content_id=content.id,
                                tag_id=subdomain_tag.id,
                                confidence=classification.confidence,
                            )
                            db.add(ct_subdomain)
                            db.flush()
                    except IntegrityError:
                        pass

            db.commit()
            metrics.record_ingested(
                content_id=content.id,
                title=content.title,
                url=content.canonical_url,
                content_hash=content.content_hash,
            )

            try:
                search_service.index_content(
                    db=db,
                    content_id=content.id,
                    category=classification.category,
                    tags=tags_list,
                )
            except Exception as index_exc:
                logger.warning("Failed to index content id=%s into search engine: %s", content.id, index_exc)

            try:
                semantic_service.index_content(
                    db=db,
                    content_id=content.id,
                )
            except Exception as sem_exc:
                logger.warning("Failed to generate semantic embeddings for content id=%s: %s", content.id, sem_exc)

            try:
                notification_pipeline.process_content(
                    db=db,
                    content_or_dict=content,
                )
            except Exception as notif_exc:
                logger.warning("Failed to run notification pipeline for content id=%s: %s", content.id, notif_exc)

        except IntegrityError as ie:
            db.rollback()
            existing = (
                db.query(Content)
                .filter((Content.canonical_url == normalized.url) | (Content.content_hash == content_hash))
                .first()
            )
            if existing:
                metrics.duplicates_skipped += 1
            else:
                err_msg = f"Database integrity error for item '{normalized.title[:40]}': {ie}"
                logger.error(err_msg)
                metrics.record_error(err_msg)
        except Exception as exc:
            db.rollback()
            err_msg = f"Database storage failed for item '{normalized.title[:40]}': {exc}"
            logger.error(err_msg, exc_info=True)
            metrics.record_error(err_msg)

    @staticmethod
    def _get_or_create_tag(db: Session, name: str, category: str = "topic") -> Tag:
        """Find or create Tag atomically with savepoint to survive concurrent inserts."""
        tag_obj = db.query(Tag).filter(Tag.name == name).first()
        if tag_obj:
            return tag_obj
        try:
            with db.begin_nested():
                tag_obj = Tag(name=name, category=category)
                db.add(tag_obj)
                db.flush()
                return tag_obj
        except IntegrityError:
            return db.query(Tag).filter(Tag.name == name).first()

    def _link_entities(
        self,
        db: Session,
        content: Content,
        normalized: NormalizedItem,
    ) -> None:
        """
        Extract and link cybersecurity entities (CVE, CWE, Vendor, Product, Malware,
        Threat Actor, Technology, Domain, IP, Hash, ATT&CK Technique)
        into Entity and ContentEntity tables using the Deterministic Entity Extraction Engine.
        """
        existing_links = (
            db.query(ContentEntity.entity_id)
            .filter(ContentEntity.content_id == content.id)
            .all()
        )
        seen_entity_ids: Set[int] = {r[0] for r in existing_links}
        linked_entities: List[Entity] = []

        extracted_entities = entity_extractor.extract_from_content(
            title=content.title,
            description=content.description,
            body=content.raw_content,
            metadata=normalized.metadata,
        )

        for ent in extracted_entities:
            clean_name = ent.name.strip()[:255]
            if not clean_name:
                continue

            # Find or create Entity
            entity_obj = (
                db.query(Entity)
                .filter(
                    Entity.entity_type == ent.entity_type,
                    Entity.normalized_name == ent.normalized_name,
                )
                .first()
            )
            # Automatic MITRE ATT&CK correlation enrichment (Section 26)
            try:
                mitre_corr = mitre_service.correlate_entity(ent.entity_type, clean_name)
                if mitre_corr:
                    if not ent.metadata:
                        ent.metadata = {}
                    ent.metadata["mitre_attack"] = mitre_corr
            except Exception as mitre_exc:
                logger.debug("MITRE correlation skipped for entity '%s': %s", clean_name, mitre_exc)

            meta_json = json.dumps(ent.metadata, default=str) if ent.metadata else None

            if not entity_obj:
                description = (
                    ent.metadata.get("description")
                    if (ent.metadata and ent.metadata.get("description"))
                    else f"Extracted {ent.entity_type}: {clean_name}"
                )
                try:
                    with db.begin_nested():
                        entity_obj = Entity(
                            name=clean_name,
                            entity_type=ent.entity_type,
                            normalized_name=ent.normalized_name,
                            description=description,
                            metadata_json=meta_json,
                        )
                        db.add(entity_obj)
                        db.flush()
                except IntegrityError:
                    entity_obj = (
                        db.query(Entity)
                        .filter(
                            Entity.entity_type == ent.entity_type,
                            Entity.normalized_name == ent.normalized_name,
                        )
                        .first()
                    )
            else:
                if meta_json and not entity_obj.metadata_json:
                    entity_obj.metadata_json = meta_json
                    try:
                        with db.begin_nested():
                            db.flush()
                    except IntegrityError:
                        pass
                elif meta_json and "mitre_attack" in ent.metadata and "mitre_attack" not in (entity_obj.metadata_json or ""):
                    entity_obj.metadata_json = meta_json
                    try:
                        with db.begin_nested():
                            db.flush()
                    except IntegrityError:
                        pass

            if entity_obj and entity_obj.id not in seen_entity_ids:
                seen_entity_ids.add(entity_obj.id)
                linked_entities.append(entity_obj)
                try:
                    with db.begin_nested():
                        content_entity = ContentEntity(
                            content_id=content.id,
                            entity_id=entity_obj.id,
                            confidence=ent.confidence,
                            extraction_method=ent.extraction_method,
                            context_snippet=ent.context_snippet or clean_name,
                        )
                        db.add(content_entity)
                        db.flush()
                except IntegrityError:
                    pass

        # Automatic Knowledge Graph edge synthesis (Section 27)
        if len(linked_entities) >= 2:
            try:
                knowledge_graph_service.synthesize_content_edges(
                    db=db,
                    content_id=content.id,
                    entities=linked_entities,
                )
            except Exception as graph_exc:
                logger.debug("Knowledge graph synthesis skipped for content id=%s: %s", content.id, graph_exc)

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
