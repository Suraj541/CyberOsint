"""
Classifier API Endpoints
Provides on-demand classification of arbitrary cybersecurity intelligence content
into the 16 canonical taxonomy categories.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

from fastapi import APIRouter, status

from app.schemas.classifier import ClassifyRequest, ClassifyResponse
from packages.classifier import rule_classifier

router = APIRouter(prefix="/classifier", tags=["Classification Engine"])


@router.post(
    "/classify",
    response_model=ClassifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Classify Cybersecurity Content",
    description=(
        "Analyzes title, description, content body, and metadata to return a structured "
        "prediction with canonical category, subcategory, and confidence score."
    ),
)
def classify_endpoint(request: ClassifyRequest) -> ClassifyResponse:
    """Classify arbitrary text and metadata against the standardized taxonomy."""
    result = rule_classifier.classify(
        title=request.title,
        description=request.description,
        content_text=request.content_text,
        metadata=request.metadata,
    )
    return ClassifyResponse(
        category=result.category,
        subcategory=result.subcategory,
        confidence=round(result.confidence, 2),
        rule_matched=result.rule_matched,
        matched_keywords=result.matched_keywords,
    )
