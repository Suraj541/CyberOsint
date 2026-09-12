"""
MITRE ATT&CK Framework Package
Provides domain models, canonical enterprise matrix data, and intelligence service
conforming strictly to IMPLEMENT.md Section 26.
"""

from packages.mitre.canonical_data import (
    CANONICAL_DATA_SOURCES,
    CANONICAL_GROUPS,
    CANONICAL_MITIGATIONS,
    CANONICAL_RELATIONSHIPS,
    CANONICAL_SOFTWARE,
    CANONICAL_TACTICS,
    CANONICAL_TECHNIQUES,
)
from packages.mitre.models import (
    AttackDataSource,
    AttackGroup,
    AttackMitigation,
    AttackRelationship,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)
from packages.mitre.service import MitreAttackService, mitre_service

__all__ = [
    "AttackTactic",
    "AttackTechnique",
    "AttackGroup",
    "AttackSoftware",
    "AttackMitigation",
    "AttackDataSource",
    "AttackRelationship",
    "CANONICAL_TACTICS",
    "CANONICAL_TECHNIQUES",
    "CANONICAL_GROUPS",
    "CANONICAL_SOFTWARE",
    "CANONICAL_MITIGATIONS",
    "CANONICAL_DATA_SOURCES",
    "CANONICAL_RELATIONSHIPS",
    "MitreAttackService",
    "mitre_service",
]
