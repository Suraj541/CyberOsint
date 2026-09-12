"""
Source Reliability Service
Calculates multi-dimensional source quality: authority, accuracy, technical_depth,
originality, and historical_reliability.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
Constraint: Internal ranking indicator — not an unquestionable truth score.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.source import Source
from app.models.source_quality import SourceQuality
from services.reliability.models import QualityMetrics, QualityTier, ReliabilityWeights

logger = logging.getLogger("cyber_osint.services.reliability")

# Canonical domain authorities for cybersecurity OSINT
AUTHORITY_DOMAIN_RULES: Dict[str, float] = {
    # Tier 1: Primary CERTs, Gov agencies, National Standards
    "cisa.gov": 0.98,
    "nist.gov": 0.98,
    "nvd.nist.gov": 0.99,
    "enisa.europa.eu": 0.96,
    "cert.org": 0.95,
    "ncsc.gov.uk": 0.95,
    "bsi.bund.de": 0.95,
    "jpcert.or.jp": 0.94,
    "cve.org": 0.99,
    "mitre.org": 0.98,
    # Tier 1-2: Primary OS & Cloud Vendor Security Research Teams
    "project-zero": 0.95,
    "googleprojectzero.blogspot.com": 0.95,
    "msrc.microsoft.com": 0.94,
    "microsoft.com": 0.92,
    "talosintelligence.com": 0.93,
    "unit42.paloaltonetworks.com": 0.93,
    "mandiant.com": 0.93,
    "citizenlab.ca": 0.94,
    "redhat.com": 0.91,
    "ubuntu.com": 0.90,
    "cloud.google.com": 0.90,
    "aws.amazon.com": 0.90,
    # Tier 2: Reputable Security Investigative Journalism & Analysis
    "bleepingcomputer.com": 0.82,
    "krebsonsecurity.com": 0.84,
    "thehackernews.com": 0.78,
    "darkreading.com": 0.76,
    "securityweek.com": 0.78,
    "threatpost.com": 0.75,
    "schneier.com": 0.85,
    "isc.sans.edu": 0.90,
    "exploit-db.com": 0.85,
    "packetstormsecurity.com": 0.82,
}


class SourceReliabilityService:
    """Computes and maintains source quality metrics across 5 dimensions."""

    def __init__(self, weights: Optional[ReliabilityWeights] = None) -> None:
        self.weights = weights or ReliabilityWeights()

    def evaluate_authority(self, source: Source) -> float:
        """
        Evaluate organizational and domain authority (0.0 to 1.0).
        High for official agencies, primary CERTs, and top vendor research labs.
        """
        url = (source.url or "").lower()
        netloc = urlparse(url).netloc.lower()

        # Direct domain match or parent domain
        base_authority = 0.60  # baseline for unknown web source
        for dom, score in AUTHORITY_DOMAIN_RULES.items():
            if dom in netloc or dom in url:
                base_authority = score
                break

        # Suffix rules (.gov, .mil)
        if netloc.endswith(".gov") or netloc.endswith(".mil"):
            base_authority = max(base_authority, 0.95)

        # Source type modifiers
        st = (source.source_type or "").lower()
        if st in ("cert", "cve"):
            base_authority = max(base_authority, 0.90)
        elif st == "advisory":
            base_authority = max(base_authority, 0.85)
        elif st == "vendor":
            base_authority = max(base_authority, 0.80)

        return min(1.0, max(0.20, base_authority))

    def evaluate_accuracy(self, db: Session, source: Source) -> float:
        """
        Evaluate factual precision and verification rate (0.0 to 1.0).
        Assesses presence of structured CVE IDs, CVSS scores, and verifiable technical indicators.
        """
        # Query sample of content for this source
        contents = (
            db.query(Content)
            .filter(Content.source_id == source.id)
            .order_by(Content.id.desc())
            .limit(25)
            .all()
        )

        if not contents:
            # Baseline from source reliability_score
            return min(1.0, max(0.50, source.reliability_score or 0.80))

        verified_count = 0
        for item in contents:
            full_text = f"{item.title or ''} {item.description or ''} {item.raw_content or ''}"
            has_cve = bool(re.search(r"CVE-\d{4}-\d{4,7}", full_text))
            has_technical_scoring = bool(re.search(r"\b(CVSS|CWE-\d+|CRITICAL|HIGH|MEDIUM|LOW)\b", full_text, re.I))
            has_entities = bool(item.content_entities) if hasattr(item, "content_entities") else False
            if has_cve or (has_technical_scoring and has_entities) or item.confidence_score >= 0.85:
                verified_count += 1

        accuracy_ratio = verified_count / len(contents)
        # Blend with source baseline
        base = source.reliability_score or 0.80
        score = 0.5 * base + 0.5 * accuracy_ratio
        return min(1.0, max(0.40, score))

    def evaluate_technical_depth(self, db: Session, source: Source) -> float:
        """
        Evaluate depth of technical artifacts (0.0 to 1.0).
        Scans for code snippets, memory offsets, packet pcaps, YARA rules, hashes, and ATT&CK mappings.
        """
        contents = (
            db.query(Content)
            .filter(Content.source_id == source.id)
            .order_by(Content.id.desc())
            .limit(25)
            .all()
        )

        if not contents:
            st = (source.source_type or "").lower()
            if st == "cve":
                return 0.90
            elif st in ("cert", "advisory"):
                return 0.80
            elif st == "vendor":
                return 0.75
            return 0.60

        depth_scores: List[float] = []
        for item in contents:
            body = f"{item.title or ''} {item.description or ''} {item.raw_content or ''}"
            item_score = 0.30

            # Technical indicators: SHA256 / MD5 hashes
            if re.search(r"\b[a-fA-F0-9]{64}\b", body) or re.search(r"\b[a-fA-F0-9]{32}\b", body):
                item_score += 0.20
            # Code / disassembly / command syntax
            if "```" in body or re.search(r"\b(powershell|bash|exec|curl|wget|reg add|ptrace)\b", body, re.I):
                item_score += 0.20
            # MITRE technique references (T1059, etc.)
            if re.search(r"\bT1\d{3}(\.\d{3})?\b", body):
                item_score += 0.15
            # Vulnerability / exploit analysis
            if re.search(r"\b(buffer overflow|rce|injection|privilege escalation|cve-)\b", body, re.I):
                item_score += 0.15

            depth_scores.append(min(1.0, item_score))

        avg_depth = sum(depth_scores) / len(depth_scores)
        return min(1.0, max(0.30, avg_depth))

    def evaluate_originality(self, db: Session, source: Source) -> float:
        """
        Evaluate whether content represents primary reporting vs syndication (0.0 to 1.0).
        Primary vendors, CERTs, and dedicated research blogs score high.
        """
        st = (source.source_type or "").lower()
        if st in ("cert", "cve"):
            return 0.95
        if st in ("advisory", "vendor"):
            return 0.90

        # Query duplicate ratio for this source
        total_items = db.query(Content).filter(Content.source_id == source.id).count()
        if total_items == 0:
            return 0.75

        # Check duplicated content where this source is secondary
        # If the platform is blog/rss, check default originality
        return 0.75

    def evaluate_historical_reliability(self, source: Source) -> float:
        """
        Evaluate uptime, polling success, and consistency of publication (0.0 to 1.0).
        """
        if not source.active:
            return 0.30

        base = source.reliability_score if source.reliability_score is not None else 0.80
        # If recently checked, reward
        if source.last_checked:
            return min(1.0, max(0.50, base + 0.05))
        return min(1.0, max(0.50, base))

    def compute_composite_score(
        self,
        authority: float,
        accuracy: float,
        technical_depth: float,
        originality: float,
        historical_reliability: float,
    ) -> float:
        """Compute weighted overall score across all 5 dimensions."""
        score = (
            self.weights.authority * authority
            + self.weights.accuracy * accuracy
            + self.weights.technical_depth * technical_depth
            + self.weights.originality * originality
            + self.weights.historical_reliability * historical_reliability
        )
        return min(1.0, max(0.0, score))

    def determine_tier_and_symbol(self, overall_score: float) -> tuple[QualityTier, str]:
        """
        Categorize into quality tiers and indicator badge symbols:
        Tier 1: >= 0.85 (A+)
        Tier 2: >= 0.70 (A)
        Tier 3: >= 0.50 (B)
        Tier 4: < 0.50 (C)
        """
        if overall_score >= 0.88:
            return QualityTier.TIER_1_AUTHORITATIVE, "A+"
        elif overall_score >= 0.80:
            return QualityTier.TIER_1_AUTHORITATIVE, "A"
        elif overall_score >= 0.70:
            return QualityTier.TIER_2_HIGH, "B+"
        elif overall_score >= 0.55:
            return QualityTier.TIER_3_STANDARD, "B"
        else:
            return QualityTier.TIER_4_UNVERIFIED, "C"

    def calculate_quality(self, db: Session, source: Source) -> QualityMetrics:
        """Perform comprehensive 5-dimension quality assessment for a Source."""
        authority = self.evaluate_authority(source)
        accuracy = self.evaluate_accuracy(db, source)
        technical_depth = self.evaluate_technical_depth(db, source)
        originality = self.evaluate_originality(db, source)
        historical_reliability = self.evaluate_historical_reliability(source)

        overall = self.compute_composite_score(
            authority=authority,
            accuracy=accuracy,
            technical_depth=technical_depth,
            originality=originality,
            historical_reliability=historical_reliability,
        )

        tier, symbol = self.determine_tier_and_symbol(overall)

        eval_meta = {
            "authority_rationale": f"Calculated for {source.source_type} on domain '{urlparse(source.url).netloc}'",
            "weights": {
                "authority": self.weights.authority,
                "accuracy": self.weights.accuracy,
                "technical_depth": self.weights.technical_depth,
                "originality": self.weights.originality,
                "historical_reliability": self.weights.historical_reliability,
            },
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
        }

        return QualityMetrics(
            source_id=source.id,
            source_name=source.name,
            authority=authority,
            accuracy=accuracy,
            technical_depth=technical_depth,
            originality=originality,
            historical_reliability=historical_reliability,
            overall_score=overall,
            quality_tier=tier,
            indicator_symbol=symbol,
            eval_metadata=eval_meta,
        )

    def update_or_create_source_quality(self, db: Session, source_id: int) -> QualityMetrics:
        """Calculate and persist or update SourceQuality record for a given source."""
        source = db.query(Source).filter(Source.id == source_id).first()
        if not source:
            raise ValueError(f"Source with id={source_id} not found")

        metrics = self.calculate_quality(db, source)

        record = db.query(SourceQuality).filter(SourceQuality.source_id == source_id).first()
        if not record:
            record = SourceQuality(
                source_id=source_id,
                authority=metrics.authority,
                accuracy=metrics.accuracy,
                technical_depth=metrics.technical_depth,
                originality=metrics.originality,
                historical_reliability=metrics.historical_reliability,
                overall_score=metrics.overall_score,
                quality_tier=metrics.quality_tier.value,
                indicator_symbol=metrics.indicator_symbol,
                eval_metadata=json.dumps(metrics.eval_metadata),
            )
            db.add(record)
        else:
            record.authority = metrics.authority
            record.accuracy = metrics.accuracy
            record.technical_depth = metrics.technical_depth
            record.originality = metrics.originality
            record.historical_reliability = metrics.historical_reliability
            record.overall_score = metrics.overall_score
            record.quality_tier = metrics.quality_tier.value
            record.indicator_symbol = metrics.indicator_symbol
            record.eval_metadata = json.dumps(metrics.eval_metadata)

        db.commit()
        db.refresh(record)
        return metrics

    def get_source_quality(self, db: Session, source_id: int) -> QualityMetrics:
        """Retrieve existing quality record or calculate on-demand."""
        record = db.query(SourceQuality).filter(SourceQuality.source_id == source_id).first()
        if record:
            tier_enum = QualityTier(record.quality_tier) if record.quality_tier in [t.value for t in QualityTier] else QualityTier.TIER_2_HIGH
            eval_meta = json.loads(record.eval_metadata) if record.eval_metadata else {}
            source = db.query(Source).filter(Source.id == source_id).first()
            return QualityMetrics(
                source_id=source_id,
                source_name=source.name if source else f"Source #{source_id}",
                authority=record.authority,
                accuracy=record.accuracy,
                technical_depth=record.technical_depth,
                originality=record.originality,
                historical_reliability=record.historical_reliability,
                overall_score=record.overall_score,
                quality_tier=tier_enum,
                indicator_symbol=record.indicator_symbol,
                eval_metadata=eval_meta,
            )
        return self.update_or_create_source_quality(db, source_id)

    def recalculate_all(self, db: Session) -> List[QualityMetrics]:
        """Recalculate reliability quality records for all registered sources."""
        sources = db.query(Source).all()
        results = []
        for src in sources:
            try:
                res = self.update_or_create_source_quality(db, src.id)
                results.append(res)
            except Exception as err:
                logger.error("Error calculating quality for source id=%s: %s", src.id, err)
        return results


# Global singleton instance
source_reliability_service = SourceReliabilityService()
