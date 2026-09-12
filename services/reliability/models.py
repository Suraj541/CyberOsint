"""
Source Reliability Data Models
Defines metric schemas, tier classifications, and scoring weights for Source Reliability.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class QualityTier(str, Enum):
    TIER_1_AUTHORITATIVE = "Tier 1 (Authoritative)"
    TIER_2_HIGH = "Tier 2 (High)"
    TIER_3_STANDARD = "Tier 3 (Standard)"
    TIER_4_UNVERIFIED = "Tier 4 (Unverified)"


@dataclass
class ReliabilityWeights:
    """Weighting for 5 mandated dimensions (sum = 1.0)."""

    authority: float = 0.25
    accuracy: float = 0.25
    technical_depth: float = 0.20
    originality: float = 0.15
    historical_reliability: float = 0.15


@dataclass
class QualityMetrics:
    """Calculated 5-dimension quality assessment for a source."""

    source_id: int
    source_name: str
    authority: float
    accuracy: float
    technical_depth: float
    originality: float
    historical_reliability: float
    overall_score: float
    quality_tier: QualityTier
    indicator_symbol: str
    eval_metadata: Dict[str, Any] = field(default_factory=dict)
    disclaimer: str = "Internal analytical ranking indicator — not an absolute truth score"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "authority": round(self.authority, 3),
            "accuracy": round(self.accuracy, 3),
            "technical_depth": round(self.technical_depth, 3),
            "originality": round(self.originality, 3),
            "historical_reliability": round(self.historical_reliability, 3),
            "overall_score": round(self.overall_score, 3),
            "quality_tier": self.quality_tier.value,
            "indicator_symbol": self.indicator_symbol,
            "eval_metadata": self.eval_metadata,
            "disclaimer": self.disclaimer,
        }
