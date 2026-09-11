"""
Sources API Endpoints
Provides CRUD operations, seed triggers, and active connectivity checks for the Source Registry.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.source import SourceCreate, SourceResponse, SourceUpdate
from app.services.source_registry import source_registry_service
from connectors.base import ConnectorHealth

router = APIRouter(prefix="/sources", tags=["Sources"])


@router.get(
    "",
    response_model=List[SourceResponse],
    status_code=status.HTTP_200_OK,
    summary="List Registered Sources",
)
def list_sources(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    active_only: bool = Query(default=False),
    source_type: Optional[str] = Query(default=None),
    category: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
) -> List[SourceResponse]:
    """List all registered intelligence sources with pagination and category filters."""
    return source_registry_service.list_sources(
        db,
        skip=skip,
        limit=limit,
        active_only=active_only,
        source_type=source_type,
        category=category,
    )


@router.post(
    "",
    response_model=SourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register New Source",
)
def create_source(
    source_in: SourceCreate,
    db: Session = Depends(get_db),
) -> SourceResponse:
    """Register a new source in the catalog. Fails if URL already exists."""
    existing = source_registry_service.get_source_by_url(db, source_in.url)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Source with URL '{source_in.url}' is already registered (id={existing.id})",
        )
    return source_registry_service.create_source(db, source_in)


@router.post(
    "/seed",
    response_model=List[SourceResponse],
    status_code=status.HTTP_200_OK,
    summary="Seed Default OSINT Sources",
)
def seed_sources(db: Session = Depends(get_db)) -> List[SourceResponse]:
    """Seed standard baseline cybersecurity intelligence sources (CISA, NVD, Krebs, etc.)."""
    return source_registry_service.seed_default_sources(db)


@router.get(
    "/{source_id}",
    response_model=SourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Source Details",
)
def get_source(
    source_id: int,
    db: Session = Depends(get_db),
) -> SourceResponse:
    """Retrieve details for a specific registered source."""
    source = source_registry_service.get_source(db, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with id {source_id} not found",
        )
    return source


@router.put(
    "/{source_id}",
    response_model=SourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Update Source",
)
def update_source(
    source_id: int,
    source_update: SourceUpdate,
    db: Session = Depends(get_db),
) -> SourceResponse:
    """Update settings or state for a registered source."""
    source = source_registry_service.get_source(db, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with id {source_id} not found",
        )
    return source_registry_service.update_source(db, source, source_update)


@router.delete(
    "/{source_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Source",
)
def delete_source(
    source_id: int,
    db: Session = Depends(get_db),
) -> None:
    """Remove a source from the catalog."""
    source = source_registry_service.get_source(db, source_id)
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source with id {source_id} not found",
        )
    source_registry_service.delete_source(db, source)


@router.get(
    "/{source_id}/health-check",
    response_model=ConnectorHealth,
    status_code=status.HTTP_200_OK,
    summary="Test Source Connectivity",
)
def check_source_connectivity(
    source_id: int,
    db: Session = Depends(get_db),
) -> ConnectorHealth:
    """Execute live health check on the external source endpoint."""
    return source_registry_service.check_source_health(db, source_id)
