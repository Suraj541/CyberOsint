"""
services/backup/retention.py
Section 43 (Step 42): RetentionPolicy

Configurable retention settings for automated backup pruning.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RetentionPolicy:
    """
    Defines how long backups are kept and the minimum set that must be preserved.

    Attributes:
        max_age_days       — backups older than this are eligible for deletion
        min_backups        — always keep at least this many most-recent backups,
                             regardless of age
        min_verified       — at least this many VERIFIED backups must be kept
                             (raises ValueError if retention would drop below this)
        keep_pitr          — if True, PITR WAL segments are never pruned by age
        description        — human-readable name for this policy
    """
    max_age_days: int = 30
    min_backups: int = 3
    min_verified: int = 1
    keep_pitr: bool = True
    description: str = "default"

    def __post_init__(self):
        if self.max_age_days < 1:
            raise ValueError("max_age_days must be >= 1")
        if self.min_backups < 1:
            raise ValueError("min_backups must be >= 1")
        if self.min_verified < 1:
            raise ValueError("min_verified must be >= 1")

    def to_dict(self) -> dict:
        return {
            "max_age_days": self.max_age_days,
            "min_backups": self.min_backups,
            "min_verified": self.min_verified,
            "keep_pitr": self.keep_pitr,
            "description": self.description,
        }


# ── Common presets ─────────────────────────────────────────────────────────────

#: Development: 7-day retention, keep at least 2
DEVELOPMENT_POLICY = RetentionPolicy(
    max_age_days=7,
    min_backups=2,
    min_verified=1,
    keep_pitr=True,
    description="development",
)

#: Staging: 14-day retention, keep at least 5
STAGING_POLICY = RetentionPolicy(
    max_age_days=14,
    min_backups=5,
    min_verified=2,
    keep_pitr=True,
    description="staging",
)

#: Production: 90-day retention, keep at least 10 (regulatory compliance)
PRODUCTION_POLICY = RetentionPolicy(
    max_age_days=90,
    min_backups=10,
    min_verified=3,
    keep_pitr=True,
    description="production",
)

POLICY_PRESETS = {
    "development": DEVELOPMENT_POLICY,
    "staging": STAGING_POLICY,
    "production": PRODUCTION_POLICY,
}
