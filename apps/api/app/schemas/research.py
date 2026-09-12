"""
AI Research Pydantic Schemas
Defines request and response schemas for AI Research endpoints.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ResearchRequest(BaseModel):
    """Request payload for executing an AI research inquiry."""
    question: str = Field(
        ...,
        min_length=3,
        description="Cybersecurity research inquiry (e.g. 'What are the latest security developments involving Kubernetes?')",
    )
    max_evidence: int = Field(
        default=8,
        ge=1,
        le=20,
        description="Maximum number of evidence items to collect and cite",
    )
    min_reliability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Optional minimum source reliability score threshold",
    )


class QueryExpansionOut(BaseModel):
    original_query: str
    expanded_terms: List[str] = Field(default_factory=list)
    detected_entities: List[str] = Field(default_factory=list)
    search_keywords: str


class EvidenceOut(BaseModel):
    citation_id: int
    content_id: int
    title: str
    source_name: str
    canonical_url: str
    published_at: Optional[str] = None
    quality_tier: str
    quality_score: float
    relevance_score: float
    snippet: str
    matched_entities: List[str] = Field(default_factory=list)


class SynthesisOut(BaseModel):
    executive_answer: str
    key_findings: List[str] = Field(default_factory=list)
    threat_activity: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    mitigations: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    confidence: float


class PipelineStageOut(BaseModel):
    stage_number: int
    stage_name: str
    status: str
    details: Optional[str] = None
    item_count: int


class ResearchResponseOut(BaseModel):
    question: str
    expansion: QueryExpansionOut
    pipeline_stages: List[PipelineStageOut] = Field(default_factory=list)
    evidence: List[EvidenceOut] = Field(default_factory=list)
    synthesis: SynthesisOut
    execution_time_ms: float


class SuggestedQueryItem(BaseModel):
    id: str
    title: str
    question: str
    category: str
    suggested_entities: List[str] = Field(default_factory=list)
