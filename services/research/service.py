"""
AI Research Service Orchestrator
Coordinates the complete 9-stage research pipeline:
Question -> Query Expansion -> Search -> Entity Search -> Vector Search ->
Source Ranking -> Evidence Collection -> AI Synthesis -> Citations.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

import logging
import time
from typing import List, Optional
from sqlalchemy.orm import Session

from services.research.evidence import EvidenceCollector, evidence_collector
from services.research.expansion import QueryExpander, query_expander
from services.research.models import (
    PipelineStageTelemetry,
    QueryExpansionResult,
    ResearchResponse,
)
from services.research.retriever import HybridRetriever, hybrid_retriever
from services.research.synthesizer import EvidenceSynthesizer, evidence_synthesizer

logger = logging.getLogger("cyber_osint.services.research")


class ResearchService:
    """Orchestrates the 9-stage AI Research Pipeline."""

    def __init__(
        self,
        expander: Optional[QueryExpander] = None,
        retriever: Optional[HybridRetriever] = None,
        collector: Optional[EvidenceCollector] = None,
        synthesizer: Optional[EvidenceSynthesizer] = None,
    ):
        self.expander = expander or query_expander
        self.retriever = retriever or hybrid_retriever
        self.collector = collector or evidence_collector
        self.synthesizer = synthesizer or evidence_synthesizer

    def conduct_research(
        self,
        db: Session,
        question: str,
        max_evidence: int = 8,
        min_reliability: float = 0.0,
    ) -> ResearchResponse:
        """
        Execute all 9 stages of the AI Research Pipeline.
        """
        start_time = time.time()
        pipeline_stages: List[PipelineStageTelemetry] = []

        # Stage 1: Question
        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=1,
                stage_name="Question Ingestion",
                status="completed",
                details=f"Received query: '{question}'",
                item_count=1,
            )
        )

        # Stage 2: Query Expansion
        expansion: QueryExpansionResult = self.expander.expand_query(question)
        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=2,
                stage_name="Query Expansion",
                status="completed",
                details=f"Extracted {len(expansion.expanded_terms)} expanded terms and {len(expansion.detected_entities)} entities",
                item_count=len(expansion.expanded_terms),
            )
        )

        # Stage 3, 4, 5, 6: Search, Entity Search, Vector Search, Source Ranking
        ranked_candidates = self.retriever.retrieve_and_rank(
            db=db,
            expansion=expansion,
            top_k=max_evidence,
            min_reliability=min_reliability,
        )

        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=3,
                stage_name="Lexical Search",
                status="completed",
                details="Executed full-text search across indexed content",
                item_count=len(ranked_candidates),
            )
        )

        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=4,
                stage_name="Entity Search",
                status="completed",
                details="Queried entities and content entity links",
                item_count=sum(len(c.matched_entities) for c in ranked_candidates),
            )
        )

        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=5,
                stage_name="Vector Search",
                status="completed",
                details="Computed cosine similarity on dense embeddings",
                item_count=sum(len(c.matched_chunks) for c in ranked_candidates),
            )
        )

        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=6,
                stage_name="Source Ranking",
                status="completed",
                details="Prioritized results using multi-dimensional source quality scores",
                item_count=len(ranked_candidates),
            )
        )

        # Stage 7: Evidence Collection
        evidence_items = self.collector.collect_evidence(
            ranked_candidates=ranked_candidates,
            query_terms=expansion.expanded_terms,
            max_evidence=max_evidence,
        )
        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=7,
                stage_name="Evidence Collection",
                status="completed",
                details=f"Extracted {len(evidence_items)} discrete factual snippets",
                item_count=len(evidence_items),
            )
        )

        # Stage 8: AI Synthesis
        synthesis = self.synthesizer.synthesize(
            question=question,
            evidence=evidence_items,
        )
        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=8,
                stage_name="AI Synthesis",
                status="completed",
                details="Formulated evidence-bounded brief enforcing strict factual grounding",
                item_count=len(synthesis.key_findings),
            )
        )

        # Stage 9: Citations
        pipeline_stages.append(
            PipelineStageTelemetry(
                stage_number=9,
                stage_name="Citations Generation",
                status="completed",
                details=f"Linked {len(evidence_items)} numbered citations to source telemetry",
                item_count=len(evidence_items),
            )
        )

        latency_ms = round((time.time() - start_time) * 1000, 2)
        logger.info(
            "AI Research completed in %.2fms for query '%s' with %d evidence items",
            latency_ms,
            question[:50],
            len(evidence_items),
        )

        return ResearchResponse(
            question=question,
            expansion=expansion,
            pipeline_stages=pipeline_stages,
            evidence=evidence_items,
            synthesis=synthesis,
            execution_time_ms=latency_ms,
        )


# Global research service singleton
research_service = ResearchService()
