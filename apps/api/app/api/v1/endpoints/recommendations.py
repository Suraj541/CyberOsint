"""
Recommendations REST Endpoints
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.recommendation import (
    InteractionCreateRequest,
    RecommendationItemSchema,
    RecommendationsListResponse,
    TopicRecommendationSchema,
    UserProfileResponse,
    UserProfileUpdateRequest,
)
from services.recommendation import (
    DifficultyLevel,
    recommendation_service,
)

router = APIRouter(prefix="/recommendations", tags=["Recommendations"])


@router.get("", response_model=RecommendationsListResponse)
def get_recommendations(
    session_id: str = Query("guest_analyst_session", description="Session identifier"),
    content_type: Optional[str] = Query(None, description="Content type filter (all, article, video, research, tool, course, document)"),
    difficulty: Optional[str] = Query(None, description="Technical depth (beginner, intermediate, advanced, expert)"),
    limit: int = Query(10, ge=1, le=50, description="Number of items to recommend"),
    current_content_id: Optional[int] = Query(None, description="Current item ID to exclude / contextualize"),
    db: Session = Depends(get_db),
):
    """
    Retrieves personalized recommendations computed across user interests,
    saved content, search history, reading history, taxonomy categories, entities, and difficulty level.
    """
    try:
        res = recommendation_service.get_recommendations(
            session_id=session_id,
            content_type=content_type,
            difficulty=difficulty,
            limit=limit,
            current_content_id=current_content_id,
            db=db,
        )
        return res
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compute recommendations: {str(e)}",
        )


@router.post("/interactions", status_code=status.HTTP_201_CREATED)
def record_interaction(
    payload: InteractionCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Records a user interaction event: view, save, unsave, search, click.
    Feeds real-time telemetry to the recommendation engine.
    """
    try:
        result = recommendation_service.record_interaction(
            session_id=payload.session_id,
            interaction_type=payload.interaction_type,
            content_id=payload.content_id,
            search_query=payload.search_query,
            metadata=payload.metadata,
            db=db,
        )
        return {"status": "success", "interaction": result}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to record interaction: {str(e)}",
        )


@router.get("/profile", response_model=UserProfileResponse)
def get_user_profile(
    session_id: str = Query("guest_analyst_session", description="Session identifier"),
    db: Session = Depends(get_db),
):
    """
    Retrieves current user recommendation preferences and activity counts.
    """
    try:
        profile = recommendation_service.get_or_create_profile(session_id=session_id, db=db)
        return profile
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve user profile: {str(e)}",
        )


@router.put("/profile", response_model=UserProfileResponse)
def update_user_profile(
    payload: UserProfileUpdateRequest,
    db: Session = Depends(get_db),
):
    """
    Updates user declared interests, technical difficulty level, and preferred delivery types.
    """
    try:
        profile = recommendation_service.update_profile(
            session_id=payload.session_id,
            interests=payload.interests,
            difficulty_level=payload.difficulty_level,
            preferred_types=payload.preferred_types,
            db=db,
        )
        return profile
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update user profile: {str(e)}",
        )


@router.get("/topics", response_model=List[TopicRecommendationSchema])
def get_topic_recommendations(
    topic: str = Query("Kubernetes Security", description="Seed cybersecurity topic"),
    limit: int = Query(5, ge=1, le=20, description="Number of related topics to discover"),
):
    """
    Returns semantic topic recommendations via the Topic Correlation Graph.
    Canonical example:
    Input: 'Kubernetes Security' ->
    Output: 'Container Security', 'Docker Security', 'Cloud Security', 'Kubernetes Threat Detection', 'Runtime Security'
    """
    try:
        return recommendation_service.get_related_topics(topic=topic, limit=limit)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve related topics: {str(e)}",
        )


@router.get("/saved", response_model=List[RecommendationItemSchema])
def get_saved_content(
    session_id: str = Query("guest_analyst_session", description="Session identifier"),
    limit: int = Query(20, ge=1, le=50, description="Maximum items to return"),
    db: Session = Depends(get_db),
):
    """
    Retrieves all bookmarked / saved intelligence artifacts for the current session.
    """
    try:
        return recommendation_service.get_saved_content(session_id=session_id, limit=limit, db=db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve saved content: {str(e)}",
        )
