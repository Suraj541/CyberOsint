"""
Cybersecurity Entity Extraction Package
Provides deterministic extraction of 11 cybersecurity entity types
(CVE, CWE, Vendor, Product, Malware, Threat Actor, Technology, Domain, IP, Hash, ATT&CK Technique)
from unstructured threat intelligence text.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from packages.extractor.engine import (
    DeterministicEntityExtractor,
    entity_extractor,
)
from packages.extractor.models import ExtractedEntity

extract_entities = entity_extractor.extract
extract_from_content = entity_extractor.extract_from_content

__all__ = [
    "ExtractedEntity",
    "DeterministicEntityExtractor",
    "entity_extractor",
    "extract_entities",
    "extract_from_content",
]
