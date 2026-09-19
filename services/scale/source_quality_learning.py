"""Section 49 (Step 48): Source Quality Learning & Bayesian Reputation Engine.

Features:
  - Dynamic Bayesian credibility updating based on corroboration and false positive feedback
  - Automated tier classification (Gold, Silver, Community, Quarantine)
  - Pre-seeded reputation scores for primary OSINT feeds
"""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.orm import Session

from app.models.scale import SourceReputationModel
from app.schemas.scale import ReputationUpdateRequest, SourceReputationOut

INITIAL_SOURCE_REPUTATIONS = [
    {
        "source_name": "CISA Cybersecurity Advisories & KEV",
        "reputation_score": 98.5,
        "tier": "gold",
        "corroboration_rate": 0.99,
        "false_positive_rate": 0.005,
        "latency_rating_ms": 120.0,
        "total_items_evaluated": 850,
    },
    {
        "source_name": "National Vulnerability Database (NVD)",
        "reputation_score": 96.0,
        "tier": "gold",
        "corroboration_rate": 0.98,
        "false_positive_rate": 0.010,
        "latency_rating_ms": 180.0,
        "total_items_evaluated": 1240,
    },
    {
        "source_name": "CERT-EU Security Bulletins",
        "reputation_score": 94.2,
        "tier": "gold",
        "corroboration_rate": 0.95,
        "false_positive_rate": 0.015,
        "latency_rating_ms": 160.0,
        "total_items_evaluated": 620,
    },
    {
        "source_name": "BleepingComputer Security News",
        "reputation_score": 86.5,
        "tier": "silver",
        "corroboration_rate": 0.88,
        "false_positive_rate": 0.035,
        "latency_rating_ms": 95.0,
        "total_items_evaluated": 1820,
    },
    {
        "source_name": "GitHub Security Advisory Database",
        "reputation_score": 89.0,
        "tier": "silver",
        "corroboration_rate": 0.91,
        "false_positive_rate": 0.025,
        "latency_rating_ms": 140.0,
        "total_items_evaluated": 910,
    },
    {
        "source_name": "Exploit-DB Vulnerability Database",
        "reputation_score": 82.0,
        "tier": "silver",
        "corroboration_rate": 0.84,
        "false_positive_rate": 0.045,
        "latency_rating_ms": 220.0,
        "total_items_evaluated": 450,
    },
]


def seed_source_reputations(db: Session) -> None:
    """Seeds baseline source reputation states if none exist."""
    count = db.query(SourceReputationModel).count()
    if count > 0:
        return

    for s in INITIAL_SOURCE_REPUTATIONS:
        model = SourceReputationModel(
            source_name=s["source_name"],
            reputation_score=s["reputation_score"],
            tier=s["tier"],
            corroboration_rate=s["corroboration_rate"],
            false_positive_rate=s["false_positive_rate"],
            latency_rating_ms=s["latency_rating_ms"],
            total_items_evaluated=s["total_items_evaluated"],
        )
        db.add(model)
    db.commit()


def list_source_reputations(db: Session) -> List[SourceReputationOut]:
    """Lists sources ranked by Bayesian credibility score."""
    seed_source_reputations(db)
    items = db.query(SourceReputationModel).order_by(SourceReputationModel.reputation_score.desc()).all()
    return [_to_out(i) for i in items]


def update_source_reputation(db: Session, req: ReputationUpdateRequest) -> SourceReputationOut:
    """Updates Bayesian reputation metrics for a source following corroboration verification."""
    seed_source_reputations(db)
    source = db.query(SourceReputationModel).filter(SourceReputationModel.source_name == req.source_name).first()

    if not source:
        source = SourceReputationModel(
            source_name=req.source_name,
            reputation_score=75.0,
            tier="silver",
            corroboration_rate=0.75,
            false_positive_rate=0.05,
            latency_rating_ms=req.latency_ms,
            total_items_evaluated=1,
        )
        db.add(source)

    # Bayesian continuous update rule
    alpha = 0.05  # Learning rate / exponential smoothing
    reward = 1.0 if req.is_corroborated else -0.5
    penalty = -3.0 if req.had_false_positive else 0.0

    new_score = source.reputation_score + (reward + penalty) * alpha * 10
    source.reputation_score = max(10.0, min(99.9, round(new_score, 2)))

    # Update rates
    source.total_items_evaluated += 1
    if req.is_corroborated:
        source.corroboration_rate = round(min(1.0, source.corroboration_rate + 0.005), 3)
    if req.had_false_positive:
        source.false_positive_rate = round(min(1.0, source.false_positive_rate + 0.01), 3)

    source.latency_rating_ms = round(source.latency_rating_ms * 0.9 + req.latency_ms * 0.1, 1)

    # Assign tier
    if source.reputation_score >= 90.0:
        source.tier = "gold"
    elif source.reputation_score >= 75.0:
        source.tier = "silver"
    elif source.reputation_score >= 50.0:
        source.tier = "community"
    else:
        source.tier = "quarantine"

    db.commit()
    db.refresh(source)
    return _to_out(source)


def _to_out(item: SourceReputationModel) -> SourceReputationOut:
    return SourceReputationOut(
        id=item.id,
        source_name=item.source_name,
        reputation_score=item.reputation_score,
        tier=item.tier,
        corroboration_rate=item.corroboration_rate,
        false_positive_rate=item.false_positive_rate,
        latency_rating_ms=item.latency_rating_ms,
        total_items_evaluated=item.total_items_evaluated,
    )
