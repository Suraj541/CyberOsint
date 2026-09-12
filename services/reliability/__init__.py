"""
Source Reliability Services Package
Exposes SourceReliabilityService and singleton for computing source quality.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
"""

from services.reliability.models import QualityMetrics, QualityTier, ReliabilityWeights
from services.reliability.service import SourceReliabilityService, source_reliability_service

__all__ = [
    "QualityMetrics",
    "QualityTier",
    "ReliabilityWeights",
    "SourceReliabilityService",
    "source_reliability_service",
]
