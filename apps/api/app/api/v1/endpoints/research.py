"""
AI Research API Endpoints
Provides endpoints for query expansion, multi-modal evidence retrieval,
and grounded research intelligence synthesis.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.research import (
    QueryExpansionOut,
    ResearchRequest,
    ResearchResponseOut,
    SuggestedQueryItem,
)
from services.research import query_expander, research_service

router = APIRouter(prefix="/research", tags=["AI Research"])

CURATED_SUGGESTED_QUERIES: List[SuggestedQueryItem] = [
    SuggestedQueryItem(
        id="k8s-security",
        title="Kubernetes Security Developments",
        question="What are the latest security developments involving Kubernetes?",
        category="cloud_security",
        suggested_entities=["Kubernetes", "k8s", "kubelet", "containers"],
    ),
    SuggestedQueryItem(
        id="akira-ransomware",
        title="Akira Ransomware Threat Profile",
        question="Analyze recent Akira ransomware campaigns, targets, and initial access techniques",
        category="malware",
        suggested_entities=["Akira", "ransomware", "Cisco VPN", "double extortion"],
    ),
    SuggestedQueryItem(
        id="edge-zeroday",
        title="Edge Gateway Zero-Days",
        question="What active zero-day vulnerabilities in enterprise perimeter gateways are being exploited in the wild?",
        category="vulnerability_management",
        suggested_entities=["CVE-2024-3400", "PAN-OS", "FortiOS", "zero-day"],
    ),
    SuggestedQueryItem(
        id="ad-kerberos",
        title="Active Directory Kerberos Attacks",
        question="Explain observed Active Directory Kerberos attack vectors and credential delegation risks",
        category="identity_security",
        suggested_entities=["Active Directory", "Kerberos", "Golden Ticket", "T1558"],
    ),
    SuggestedQueryItem(
        id="supply-chain",
        title="Open-Source Supply Chain Compromises",
        question="What are the primary attack patterns in recent open-source software supply chain backdoors?",
        category="application_security",
        suggested_entities=["XZ Utils", "CVE-2024-3094", "backdoor", "supply chain"],
    ),
]


@router.post(
    "/ask",
    response_model=ResearchResponseOut,
    status_code=status.HTTP_200_OK,
    summary="Execute 9-Stage AI Research Pipeline",
)
def ask_research_question(
    payload: ResearchRequest,
    db: Session = Depends(get_db),
) -> ResearchResponseOut:
    """
    Execute complete 9-stage research pipeline:
    Question -> Query Expansion -> Search -> Entity Search -> Vector Search ->
    Source Ranking -> Evidence Collection -> AI Synthesis -> Citations.
    Guarantees answers are strictly bounded to retrieved evidence.
    """
    try:
        result = research_service.conduct_research(
            db=db,
            question=payload.question,
            max_evidence=payload.max_evidence,
            min_reliability=payload.min_reliability,
        )
        return ResearchResponseOut.model_validate(result.model_dump())
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI Research execution failed: {str(exc)}",
        )


@router.post(
    "/expand",
    response_model=QueryExpansionOut,
    status_code=status.HTTP_200_OK,
    summary="Query Expansion Diagnostic",
)
def expand_query(payload: ResearchRequest) -> QueryExpansionOut:
    """Diagnostic endpoint to inspect Stage 2 Query Expansion terms."""
    expansion = query_expander.expand_query(payload.question)
    return QueryExpansionOut.model_validate(expansion.model_dump())


@router.get(
    "/suggested",
    response_model=List[SuggestedQueryItem],
    status_code=status.HTTP_200_OK,
    summary="List Curated Research Questions",
)
def get_suggested_queries() -> List[SuggestedQueryItem]:
    """Retrieve curated research prompts adhering to IMPLEMENT.md Section 30."""
    return CURATED_SUGGESTED_QUERIES
