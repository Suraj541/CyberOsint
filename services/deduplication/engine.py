"""
Advanced Deduplication Engine
Implements the 5-stage deduplication pipeline:
Exact URL -> Content Hash -> Similar Title -> Semantic & Multi-Signal Similarity -> Duplicate Cluster.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

import json
import logging
from pathlib import Path
import sys
import uuid
from typing import Any, Dict, List, Optional, Set

# Ensure apps/api is in sys.path if not present
api_root = Path(__file__).resolve().parent.parent.parent / "apps" / "api"
if str(api_root) not in sys.path and api_root.exists():
    sys.path.insert(0, str(api_root))

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.duplicate import DuplicateLink
from services.deduplication.hashing import compute_content_hash, normalize_title_text
from services.deduplication.models import DeduplicationResult, DuplicateCluster
from services.deduplication.similarity import (
    calculate_multi_signal_similarity,
    calculate_title_similarity,
)
from services.deduplication.url import normalize_url

logger = logging.getLogger("cyber_osint.services.deduplication.engine")


class DeduplicationEngine:
    """
    Multi-stage intelligence deduplication engine:
    1. Exact URL match (after query param strip and canonical resolution)
    2. Content Hash match (SHA-256 fingerprint against DB and batch)
    3. Similar Title match (Levenshtein, token sort, and n-gram overlap)
    4. Multi-Signal Similarity (title, description, extracted entities, and TF-IDF semantics)
    5. Cluster Management (records duplicate relationships instead of silent deletion)
    """

    def __init__(
        self,
        title_threshold: float = 0.85,
        composite_threshold: float = 0.75,
        candidate_window_limit: int = 100,
    ):
        self.title_threshold = title_threshold
        self.composite_threshold = composite_threshold
        self.candidate_window_limit = candidate_window_limit

    def evaluate(
        self,
        db: Session,
        item: Any,
        in_memory_seen: Optional[Set[str]] = None,
    ) -> DeduplicationResult:
        """
        Evaluate an incoming intelligence item through the complete deduplication pipeline.
        Item can be a NormalizedItem, Content instance, or dict.
        """
        # Extract item attributes
        if isinstance(item, dict):
            url = item.get("canonical_url") or item.get("url") or ""
            title = item.get("title") or ""
            description = item.get("description") or ""
            raw_content = item.get("raw_content") or ""
            metadata = item.get("metadata") or {}
            entities = item.get("entities") or (metadata.get("entities") if isinstance(metadata, dict) else None)
            content_hash = item.get("content_hash")
        else:
            url = getattr(item, "canonical_url", None) or getattr(item, "url", None) or ""
            title = getattr(item, "title", "") or ""
            description = getattr(item, "description", "") or ""
            raw_content = getattr(item, "raw_content", "") or ""
            metadata = getattr(item, "metadata", None) or {}
            entities = getattr(item, "entities", None) or (metadata.get("entities") if isinstance(metadata, dict) else None)
            content_hash = getattr(item, "content_hash", None)

        clean_url = normalize_url(url)
        if not content_hash:
            content_hash = compute_content_hash(clean_url, title, raw_content)

        # -------------------------------------------------------------
        # 1. In-Memory Batch Check (Fast-path)
        # -------------------------------------------------------------
        if in_memory_seen is not None:
            if content_hash in in_memory_seen or (clean_url and clean_url in in_memory_seen):
                match_type = "exact_url" if (clean_url and clean_url in in_memory_seen) else "exact_hash"
                canonical_item = None
                if clean_url and not clean_url.startswith("urn:"):
                    canonical_item = (
                        db.query(Content)
                        .filter(Content.canonical_url == clean_url)
                        .order_by(Content.id.asc())
                        .first()
                    )
                if not canonical_item and content_hash:
                    canonical_item = (
                        db.query(Content)
                        .filter(Content.content_hash == content_hash)
                        .order_by(Content.id.asc())
                        .first()
                    )

                cid = canonical_item.id if canonical_item else None
                curl = canonical_item.canonical_url if canonical_item else clean_url
                ctitle = canonical_item.title if canonical_item else title
                cluster_id = self._get_or_create_cluster_id(db, cid) if cid else None

                return DeduplicationResult(
                    is_duplicate=True,
                    match_type=match_type,
                    similarity_score=1.0,
                    canonical_id=cid,
                    canonical_url=curl,
                    canonical_title=ctitle,
                    cluster_id=cluster_id,
                    metrics={"in_memory_match": 1.0},
                    reason="Matched in-flight batch deduplication cache",
                )

        # -------------------------------------------------------------
        # 2. Stage 1: Exact Canonical URL Match
        # -------------------------------------------------------------
        if clean_url and not clean_url.startswith("urn:"):
            url_match = (
                db.query(Content)
                .filter(Content.canonical_url == clean_url)
                .order_by(Content.id.asc())
                .first()
            )
            if url_match:
                cluster_id = self._get_or_create_cluster_id(db, url_match.id)
                return DeduplicationResult(
                    is_duplicate=True,
                    match_type="exact_url",
                    similarity_score=1.0,
                    canonical_id=url_match.id,
                    canonical_url=url_match.canonical_url,
                    canonical_title=url_match.title,
                    cluster_id=cluster_id,
                    metrics={"title_similarity": 1.0},
                    reason=f"Exact canonical URL match with content id={url_match.id}",
                )

        # -------------------------------------------------------------
        # 3. Stage 2: Exact Content Hash Match (SHA-256)
        # -------------------------------------------------------------
        if content_hash:
            hash_match = (
                db.query(Content)
                .filter(Content.content_hash == content_hash)
                .order_by(Content.id.asc())
                .first()
            )
            if hash_match:
                cluster_id = self._get_or_create_cluster_id(db, hash_match.id)
                return DeduplicationResult(
                    is_duplicate=True,
                    match_type="exact_hash",
                    similarity_score=1.0,
                    canonical_id=hash_match.id,
                    canonical_url=hash_match.canonical_url,
                    canonical_title=hash_match.title,
                    cluster_id=cluster_id,
                    metrics={"hash_similarity": 1.0},
                    reason=f"Exact cryptographic SHA-256 hash match with content id={hash_match.id}",
                )

        # -------------------------------------------------------------
        # 4. Stage 3 & 4: Title & Multi-Signal Similarity Check
        # -------------------------------------------------------------
        candidates = (
            db.query(Content)
            .order_by(Content.id.desc())
            .limit(self.candidate_window_limit)
            .all()
        )

        best_candidate: Optional[Content] = None
        best_metrics: Dict[str, float] = {}
        highest_score = 0.0
        match_type = ""

        clean_title = normalize_title_text(title)

        for candidate in candidates:
            # First check title similarity
            title_sim = calculate_title_similarity(clean_title, candidate.title)

            if title_sim >= self.title_threshold and title_sim > highest_score:
                highest_score = title_sim
                best_candidate = candidate
                match_type = "similar_title"
                best_metrics = {"title_similarity": title_sim, "composite_score": title_sim}

            # If title is moderately similar (>= 0.60), evaluate full multi-signal composite
            elif title_sim >= 0.55:
                # Extract candidate entities if available in metadata
                cand_entities = None
                if candidate.content_entities:
                    cand_entities = [(ce.entity.entity_type, ce.entity.normalized_name) for ce in candidate.content_entities if ce.entity]

                multi_scores = calculate_multi_signal_similarity(
                    title1=title,
                    title2=candidate.title,
                    desc1=description,
                    desc2=candidate.description,
                    entities1=entities,
                    entities2=cand_entities,
                    body1=raw_content,
                    body2=candidate.raw_content,
                )

                if multi_scores["composite_score"] >= self.composite_threshold and multi_scores["composite_score"] > highest_score:
                    highest_score = multi_scores["composite_score"]
                    best_candidate = candidate
                    match_type = "near_duplicate"
                    best_metrics = multi_scores

        if best_candidate and highest_score > 0.0:
            cluster_id = self._get_or_create_cluster_id(db, best_candidate.id)
            return DeduplicationResult(
                is_duplicate=True,
                match_type=match_type,
                similarity_score=highest_score,
                canonical_id=best_candidate.id,
                canonical_url=best_candidate.canonical_url,
                canonical_title=best_candidate.title,
                cluster_id=cluster_id,
                metrics=best_metrics,
                reason=f"Detected {match_type} (score: {highest_score:.2f}) with canonical content id={best_candidate.id}",
            )

        # -------------------------------------------------------------
        # 5. Stage 5: Unique Content Record
        # -------------------------------------------------------------
        return DeduplicationResult(
            is_duplicate=False,
            match_type="unique",
            similarity_score=0.0,
            reason="Item is novel across all deduplication pipeline checks",
        )

    def record_duplicate_link(
        self,
        db: Session,
        canonical_id: int,
        duplicate_id: Optional[int] = None,
        match_type: str = "exact_hash",
        similarity_score: float = 1.0,
        cluster_id: Optional[str] = None,
        metrics: Optional[Dict[str, float]] = None,
    ) -> DuplicateLink:
        """
        Persist a duplicate relationship linking a duplicate record to its canonical entity.
        Conforms to Section 17 mandate: Store duplicate relationships instead of silently deleting records.
        """
        if not cluster_id:
            cluster_id = self._get_or_create_cluster_id(db, canonical_id)

        meta_json = json.dumps(metrics, default=str) if metrics else None

        link = DuplicateLink(
            canonical_id=canonical_id,
            duplicate_id=duplicate_id,
            cluster_id=cluster_id,
            match_type=match_type,
            similarity_score=similarity_score,
            metadata_json=meta_json,
        )
        db.add(link)
        db.flush()
        return link

    def _get_or_create_cluster_id(self, db: Session, canonical_id: int) -> str:
        """Find existing cluster ID for a canonical record or generate a new deterministic ID."""
        existing = (
            db.query(DuplicateLink.cluster_id)
            .filter(DuplicateLink.canonical_id == canonical_id)
            .first()
        )
        if existing and existing[0]:
            return existing[0]
        return f"cluster_{canonical_id}_{uuid.uuid4().hex[:8]}"

    def list_clusters(
        self,
        db: Session,
        limit: int = 50,
        offset: int = 0,
    ) -> List[DuplicateCluster]:
        """Retrieve aggregated duplicate clusters."""
        # Query distinct clusters
        cluster_rows = (
            db.query(
                DuplicateLink.cluster_id,
                DuplicateLink.canonical_id,
                func.count(DuplicateLink.id).label("dup_count"),
            )
            .group_by(DuplicateLink.cluster_id, DuplicateLink.canonical_id)
            .order_by(func.count(DuplicateLink.id).desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        clusters: List[DuplicateCluster] = []
        for cluster_id, canonical_id, dup_count in cluster_rows:
            canonical = db.query(Content).filter(Content.id == canonical_id).first()
            if not canonical:
                continue

            links = (
                db.query(DuplicateLink)
                .filter(DuplicateLink.cluster_id == cluster_id)
                .all()
            )

            duplicate_entries = [
                {
                    "link_id": link.id,
                    "duplicate_content_id": link.duplicate_id,
                    "match_type": link.match_type,
                    "similarity_score": link.similarity_score,
                    "created_at": link.created_at.isoformat() if link.created_at else None,
                }
                for link in links
            ]

            clusters.append(
                DuplicateCluster(
                    cluster_id=cluster_id,
                    canonical_id=canonical.id,
                    canonical_title=canonical.title,
                    canonical_url=canonical.canonical_url,
                    duplicates=duplicate_entries,
                    total_members=1 + len(duplicate_entries),
                )
            )

        return clusters

    def get_cluster(self, db: Session, cluster_id: str) -> Optional[DuplicateCluster]:
        """Retrieve a specific duplicate cluster by cluster ID."""
        first_link = (
            db.query(DuplicateLink)
            .filter(DuplicateLink.cluster_id == cluster_id)
            .first()
        )
        if not first_link:
            return None

        canonical = db.query(Content).filter(Content.id == first_link.canonical_id).first()
        if not canonical:
            return None

        links = (
            db.query(DuplicateLink)
            .filter(DuplicateLink.cluster_id == cluster_id)
            .all()
        )

        duplicate_entries = [
            {
                "link_id": link.id,
                "duplicate_content_id": link.duplicate_id,
                "match_type": link.match_type,
                "similarity_score": link.similarity_score,
                "created_at": link.created_at.isoformat() if link.created_at else None,
            }
            for link in links
        ]

        return DuplicateCluster(
            cluster_id=cluster_id,
            canonical_id=canonical.id,
            canonical_title=canonical.title,
            canonical_url=canonical.canonical_url,
            duplicates=duplicate_entries,
            total_members=1 + len(duplicate_entries),
        )


# Global singleton instance
deduplication_engine = DeduplicationEngine()
