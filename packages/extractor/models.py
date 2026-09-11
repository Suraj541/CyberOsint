"""
Entity Extraction Data Models
Defines the output structure for deterministically extracted cybersecurity entities.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class ExtractedEntity:
    """
    Standardized entity extracted deterministically from cybersecurity text.
    """

    name: str
    entity_type: str  # cve, cwe, vendor, product, malware, threat_actor, technology, domain, ip, hash, mitre_technique
    normalized_name: str
    confidence: float = 1.0
    extraction_method: str = "regex"  # regex, dictionary, defanged, structured
    context_snippet: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "entity_type": self.entity_type,
            "normalized_name": self.normalized_name,
            "confidence": round(self.confidence, 2),
            "extraction_method": self.extraction_method,
            "context_snippet": self.context_snippet,
            "metadata": self.metadata,
        }
