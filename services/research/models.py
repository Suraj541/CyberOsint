"""
AI Research Data Models
Defines data structures for the 9-stage research pipeline:
Question -> Query Expansion -> Search -> Entity Search -> Vector Search ->
Source Ranking -> Evidence Collection -> AI Synthesis -> Citations.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class QueryExpansionResult(BaseModel):
    """Result of Stage 2: Query Expansion."""
    original_query: str = Field(..., description="User's original research question")
    expanded_terms: List[str] = Field(default_factory=list, description="Synonyms, acronyms, and related concepts")
    detected_entities: List[str] = Field(default_factory=list, description="Specific CVEs, tools, actors identified in query")
    search_keywords: str = Field(..., description="Combined search term query string")


class EvidenceItem(BaseModel):
    """Result of Stage 7: Evidence Collection."""
    citation_id: int = Field(..., description="Numbered citation reference ID [1], [2], ...")
    content_id: int = Field(..., description="Database content ID")
    title: str = Field(..., description="Source article/advisory title")
    source_name: str = Field(..., description="Name of reporting organization/source")
    canonical_url: str = Field(..., description="Direct URL to original source material")
    published_at: Optional[str] = Field(None, description="ISO timestamp of publication")
    quality_tier: str = Field(default="Tier 2 (High)", description="Source reliability quality tier")
    quality_score: float = Field(default=0.8, description="Source quality composite score (0.0 to 1.0)")
    relevance_score: float = Field(default=1.0, description="Query matching relevance score")
    snippet: str = Field(..., description="Verbatim factual excerpt from retrieved evidence")
    matched_entities: List[str] = Field(default_factory=list, description="Associated CVEs, techniques, or indicators")


class SynthesisOutput(BaseModel):
    """Result of Stage 8: AI Synthesis strictly bounded to retrieved evidence."""
    executive_answer: str = Field(..., description="Cohesive synthesis answering the question using [citation] markers")
    key_findings: List[str] = Field(default_factory=list, description="Primary factual findings extracted from evidence")
    threat_activity: List[str] = Field(default_factory=list, description="Adversary behaviors, threat actors, and campaigns cited")
    vulnerabilities: List[str] = Field(default_factory=list, description="Vulnerabilities, CVEs, and affected components")
    mitigations: List[str] = Field(default_factory=list, description="Actionable security controls supported by evidence")
    evidence_gaps: List[str] = Field(default_factory=list, description="Preserved uncertainties and topics unaddressed by retrieved data")
    confidence: float = Field(default=0.9, description="Confidence in synthesis alignment with evidence")


class PipelineStageTelemetry(BaseModel):
    """Status telemetry for each of the 9 pipeline stages."""
    stage_number: int
    stage_name: str
    status: str = "completed"
    details: Optional[str] = None
    item_count: int = 0


class ResearchResponse(BaseModel):
    """Final output of Stage 9: Complete Research Intelligence Report."""
    question: str = Field(..., description="Original user query")
    expansion: QueryExpansionResult
    pipeline_stages: List[PipelineStageTelemetry] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list, description="Numbered evidence records")
    synthesis: SynthesisOutput = Field(..., description="Grounded synthesized intelligence brief")
    execution_time_ms: float = Field(default=0.0, description="Total pipeline execution latency in milliseconds")
