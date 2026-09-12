"""
Source Quality Pydantic Schemas
Defines request and response models for Source Reliability endpoints.
Conforms strictly to IMPLEMENT.md Section 28 (Step 27).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SourceQualityOut(BaseModel):
    source_id: int = Field(..., description="ID of the evaluated source")
    source_name: str = Field(..., description="Name of the evaluated source")
    authority: float = Field(..., description="Authority score (0.0 to 1.0)")
    accuracy: float = Field(..., description="Accuracy score (0.0 to 1.0)")
    technical_depth: float = Field(..., description="Technical depth score (0.0 to 1.0)")
    originality: float = Field(..., description="Originality score (0.0 to 1.0)")
    historical_reliability: float = Field(..., description="Historical reliability score (0.0 to 1.0)")
    overall_score: float = Field(..., description="Composite weighted quality score (0.0 to 1.0)")
    quality_tier: str = Field(..., description="Tier classification e.g. Tier 1 (Authoritative)")
    indicator_symbol: str = Field(..., description="Symbolic badge code e.g. A+, A, B+, B, C")
    eval_metadata: Optional[Dict[str, Any]] = Field(default=None, description="Evaluation rationale and weights")
    disclaimer: str = Field(
        default="Internal analytical ranking indicator — not an absolute truth score",
        description="Non-authoritative internal ranking constraint",
    )

    class Config:
        from_attributes = True


class SourceQualityRecalculateResponse(BaseModel):
    status: str
    recalculated_count: int
    qualities: List[SourceQualityOut]
