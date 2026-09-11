"""
Deterministic Entity Extraction Pydantic Schemas
Defines request and response schemas for on-demand cybersecurity entity extraction.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExtractRequest(BaseModel):
    """Payload for on-demand deterministic entity extraction."""

    text: str = Field(..., min_length=1, description="Threat intelligence text or document body to analyze")
    title: Optional[str] = Field(default=None, description="Optional article or advisory title")
    metadata: Optional[Dict[str, Any]] = Field(default=None, description="Optional structured metadata or existing entities")


class ExtractedEntityResponse(BaseModel):
    """Extracted cybersecurity intelligence entity."""

    name: str = Field(..., description="Raw or display name of the entity")
    entity_type: str = Field(..., description="Type of entity (cve, cwe, malware, threat_actor, vendor, product, technology, domain, ip, hash, mitre_technique)")
    normalized_name: str = Field(..., description="Canonical uppercase/lowercase normalized representation")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")
    extraction_method: str = Field(default="regex", description="Method used for extraction (regex, dictionary, defanged, structured)")
    context_snippet: Optional[str] = Field(default=None, description="Surrounding contextual text snippet")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional entity attributes or telemetry")


class ExtractResponse(BaseModel):
    """Response envelope containing all extracted entities and statistical distribution."""

    entities: List[ExtractedEntityResponse] = Field(default_factory=list, description="List of extracted entities")
    total_entities: int = Field(..., description="Total count of unique entities extracted")
    entity_counts: Dict[str, int] = Field(default_factory=dict, description="Count breakdown by entity type")
