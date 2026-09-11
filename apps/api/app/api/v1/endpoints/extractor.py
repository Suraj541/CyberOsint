"""
Deterministic Entity Extractor API Endpoints
Provides on-demand deterministic extraction of 11 cybersecurity entity types
(CVE, CWE, Vendor, Product, Malware, Threat Actor, Technology, Domain, IP, Hash, ATT&CK Technique)
from unstructured text, titles, and metadata.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

from collections import Counter
from fastapi import APIRouter, status

from app.schemas.extractor import (
    ExtractRequest,
    ExtractedEntityResponse,
    ExtractResponse,
)
from packages.extractor import entity_extractor

router = APIRouter(prefix="/extractor", tags=["Entity Extractor"])


@router.post(
    "/extract",
    response_model=ExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract Cybersecurity Entities",
    description=(
        "Deterministically extracts 11 entity types (CVE, CWE, Vendor, Product, Malware, "
        "Threat Actor, Technology, Domain, IP, Hash, ATT&CK Technique) from threat intelligence text."
    ),
)
def extract_endpoint(request: ExtractRequest) -> ExtractResponse:
    """Extract deterministic entities from raw text, title, and metadata."""
    if request.title or request.metadata:
        entities = entity_extractor.extract_from_content(
            title=request.title or "",
            body=request.text,
            metadata=request.metadata,
        )
    else:
        entities = entity_extractor.extract(request.text)

    entity_responses = [
        ExtractedEntityResponse(
            name=e.name,
            entity_type=e.entity_type,
            normalized_name=e.normalized_name,
            confidence=round(e.confidence, 2),
            extraction_method=e.extraction_method,
            context_snippet=e.context_snippet,
            metadata=e.metadata,
        )
        for e in entities
    ]

    # Calculate type counts
    counts = dict(Counter(e.entity_type for e in entities))

    return ExtractResponse(
        entities=entity_responses,
        total_entities=len(entities),
        entity_counts=counts,
    )
