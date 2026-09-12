"""
AI Summarization API Endpoints
Provides endpoints for retrieving, generating, and batch-processing AI-generated executive summaries.
Enforces strict provenance tracking, validation telemetry, and separation of reported facts from inferences.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.content import Content
from app.schemas.summary import (
    BatchSummaryRequest,
    BatchSummaryResponse,
    ContentSummaryOut,
    SummaryGenerateRequest,
    SummaryGenerateResponse,
)
from services.summarization.service import summarization_service

router = APIRouter(prefix="/summaries", tags=["AI Summarization"])


@router.get(
    "/{content_id}",
    response_model=ContentSummaryOut,
    status_code=status.HTTP_200_OK,
    summary="Get AI Summary by Content ID",
)
def get_summary(
    content_id: int,
    db: Session = Depends(get_db),
) -> ContentSummaryOut:
    """Retrieve the validated AI summary for the specified content ID."""
    summary = summarization_service.get_content_summary(db, content_id)
    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AI summary not found for content ID {content_id}",
        )
    return ContentSummaryOut.model_validate(summary)


@router.post(
    "/{content_id}/generate",
    response_model=SummaryGenerateResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate or Regenerate AI Summary",
)
def generate_summary(
    content_id: int,
    payload: Optional[SummaryGenerateRequest] = None,
    db: Session = Depends(get_db),
) -> SummaryGenerateResponse:
    """
    Run 5-stage pipeline to generate a grounded executive summary for content ID.
    Stage: Clean Text -> AI Model -> Extract Summary -> Grounding Validation -> Persist.
    """
    force = payload.force if payload else False
    content = db.query(Content).filter(Content.id == content_id).first()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Content ID {content_id} not found",
        )

    try:
        summary_record = summarization_service.summarize_content(db, content_id, force=force)
        return SummaryGenerateResponse(
            status="success",
            content_id=content_id,
            summary=ContentSummaryOut.model_validate(summary_record),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate AI summary: {str(exc)}",
        )


@router.post(
    "/batch-generate",
    response_model=BatchSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch Generate AI Summaries",
)
def batch_generate_summaries(
    payload: Optional[BatchSummaryRequest] = None,
    db: Session = Depends(get_db),
) -> BatchSummaryResponse:
    """
    Trigger batch processing of pending content items missing an AI summary.
    """
    limit = payload.limit if payload else 10
    results = summarization_service.batch_summarize(db, limit=limit)
    out_items = [ContentSummaryOut.model_validate(r) for r in results]
    return BatchSummaryResponse(
        status="success",
        processed_count=len(out_items),
        summaries=out_items,
    )
