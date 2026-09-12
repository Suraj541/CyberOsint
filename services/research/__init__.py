"""
AI Research Engine Package
Implements the 9-stage research pipeline:
Question -> Query Expansion -> Search -> Entity Search -> Vector Search ->
Source Ranking -> Evidence Collection -> AI Synthesis -> Citations.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

from services.research.evidence import EvidenceCollector, evidence_collector
from services.research.expansion import QueryExpander, query_expander
from services.research.models import (
    EvidenceItem,
    PipelineStageTelemetry,
    QueryExpansionResult,
    ResearchResponse,
    SynthesisOutput,
)
from services.research.retriever import HybridRetriever, hybrid_retriever
from services.research.service import ResearchService, research_service
from services.research.synthesizer import EvidenceSynthesizer, evidence_synthesizer

__all__ = [
    "ResearchService",
    "research_service",
    "QueryExpander",
    "query_expander",
    "HybridRetriever",
    "hybrid_retriever",
    "EvidenceCollector",
    "evidence_collector",
    "EvidenceSynthesizer",
    "evidence_synthesizer",
    "EvidenceItem",
    "PipelineStageTelemetry",
    "QueryExpansionResult",
    "ResearchResponse",
    "SynthesisOutput",
]
