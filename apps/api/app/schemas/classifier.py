"""
Classifier Pydantic Schemas
Defines request and response schemas for on-demand cybersecurity content classification.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ClassifyRequest(BaseModel):
    """Payload for on-demand content classification."""

    title: str = Field(..., min_length=2, description="Content title or headline")
    description: Optional[str] = Field(default=None, description="Short summary or article lead")
    content_text: Optional[str] = Field(default=None, description="Available body or raw content text")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional item metadata (CVE ID, source type, tags)")


class ClassifyResponse(BaseModel):
    """Structured classification prediction."""

    category: str = Field(..., description="Canonical snake_case category identifier")
    subcategory: Optional[str] = Field(default=None, description="Canonical subcategory identifier if resolved")
    confidence: float = Field(..., description="Confidence score from 0.0 to 1.0")
    rule_matched: Optional[str] = Field(default=None, description="Internal rule or heuristic that triggered the classification")
    matched_keywords: List[str] = Field(default_factory=list, description="Keywords or phrases that informed the decision")
