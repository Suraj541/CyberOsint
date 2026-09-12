"""
Summarization Data Models
Pydantic schemas and dataclasses for structured AI summary generation and validation.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


@dataclass
class ValidationResult:
    """Telemetry produced by the Grounding & Hallucination Validator."""

    status: str = "passed"  # passed, flagged, rejected
    score: float = 1.0
    grounded_facts_count: int = 0
    unsupported_claims: List[str] = field(default_factory=list)
    entity_overlap_ratio: float = 1.0
    notes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "score": round(self.score, 3),
            "grounded_facts_count": self.grounded_facts_count,
            "unsupported_claims": self.unsupported_claims,
            "entity_overlap_ratio": round(self.entity_overlap_ratio, 3),
            "notes": self.notes,
        }


@dataclass
class SummaryOutput:
    """Structured AI summary adhering to the 5 strict prompt rules."""

    executive_summary: str
    reported_facts: List[str]
    inferences: List[str]
    uncertainties: List[str]
    key_takeaways: List[str]
    source_attribution: str
    model: str = "cyber-grounded-summarizer"
    model_version: str = "v1.2.0"
    prompt_version: str = "v1.0.0-grounded"
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    confidence: float = 0.92
    validation: ValidationResult = field(default_factory=ValidationResult)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "reported_facts": self.reported_facts,
            "inferences": self.inferences,
            "uncertainties": self.uncertainties,
            "key_takeaways": self.key_takeaways,
            "source_attribution": self.source_attribution,
            "model": self.model,
            "model_version": self.model_version,
            "prompt_version": self.prompt_version,
            "generated_at": self.generated_at,
            "confidence": round(self.confidence, 3),
            "validation_status": self.validation.status,
            "validation_score": round(self.validation.score, 3),
            "validation_notes": self.validation.to_dict(),
        }
