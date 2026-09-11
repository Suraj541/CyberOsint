"""
Deduplication Service Domain Models
Defines structured evaluation results, cluster wrappers, and match telemetry.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DeduplicationResult:
    """Evaluation result for an incoming content item through the deduplication pipeline."""

    is_duplicate: bool
    match_type: Optional[str] = None  # exact_url, exact_hash, similar_title, near_duplicate, unique
    similarity_score: float = 0.0
    canonical_id: Optional[int] = None
    canonical_url: Optional[str] = None
    canonical_title: Optional[str] = None
    cluster_id: Optional[str] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_duplicate": self.is_duplicate,
            "match_type": self.match_type,
            "similarity_score": round(self.similarity_score, 4),
            "canonical_id": self.canonical_id,
            "canonical_url": self.canonical_url,
            "canonical_title": self.canonical_title,
            "cluster_id": self.cluster_id,
            "metrics": {k: round(v, 4) for k, v in self.metrics.items()},
            "reason": self.reason,
        }


@dataclass
class DuplicateCluster:
    """Group of near-duplicate or identical intelligence reports linked to a canonical item."""

    cluster_id: str
    canonical_id: int
    canonical_title: str
    canonical_url: str
    duplicates: List[Dict[str, Any]] = field(default_factory=list)
    total_members: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "canonical_id": self.canonical_id,
            "canonical_title": self.canonical_title,
            "canonical_url": self.canonical_url,
            "duplicates": self.duplicates,
            "total_members": self.total_members,
        }
