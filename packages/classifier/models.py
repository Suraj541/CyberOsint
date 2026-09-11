"""
Classification Data Models
Defines the output structure for the cybersecurity classification engine.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ClassificationResult:
    """
    Standardized classification prediction for cybersecurity intelligence items.
    """

    category: str
    subcategory: Optional[str] = None
    confidence: float = 0.5
    rule_matched: Optional[str] = None
    matched_keywords: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "subcategory": self.subcategory,
            "confidence": round(self.confidence, 2),
            "rule_matched": self.rule_matched,
            "matched_keywords": self.matched_keywords,
        }
