"""
Watchlists REST API Endpoints
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.watchlist import (
    MatchedWatchlistItemResponse,
    WatchlistCreateRequest,
    WatchlistFeedResponse,
    WatchlistItemCreateRequest,
    WatchlistItemResponse,
    WatchlistMatchTestRequest,
    WatchlistResponse,
    WatchlistUpdateRequest,
)
from services.watchlist import (
    WatchlistItemCreateDTO,
    WatchlistItemType,
    watchlist_matcher,
    watchlist_service,
)

router = APIRouter(prefix="/watchlists", tags=["Watchlists"])


@router.get("", response_model=List[WatchlistResponse])
def list_watchlists(
    session_id: str = Query("guest_analyst_session", description="Session identifier"),
    db: Session = Depends(get_db),
):
    """
    Retrieves all watchlists belonging to the current analyst session.
    Automatically seeds default curated watchlists if empty.
    """
    try:
        return watchlist_service.list_watchlists(session_id=session_id, db=db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list watchlists: {str(e)}",
        )


@router.post("", response_model=WatchlistResponse, status_code=status.HTTP_201_CREATED)
def create_watchlist(
    payload: WatchlistCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Creates a new surveillance watchlist with optional initial targets.
    """
    try:
        dto_items = [
            WatchlistItemCreateDTO(
                item_type=WatchlistItemType(it.item_type.lower()),
                item_value=it.item_value,
                severity_threshold=it.severity_threshold,
                notify_on_match=it.notify_on_match,
            )
            for it in payload.items
        ]
        created = watchlist_service.create_watchlist(
            session_id=payload.session_id,
            name=payload.name,
            description=payload.description,
            notification_channel=payload.notification_channel,
            items=dto_items,
            db=db,
        )
        return created
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid item type: {str(val_err)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create watchlist: {str(e)}",
        )


@router.get("/{watchlist_id}", response_model=WatchlistResponse)
def get_watchlist(
    watchlist_id: int,
    db: Session = Depends(get_db),
):
    """
    Retrieves a single watchlist by ID along with its monitored items.
    """
    wl = watchlist_service.get_watchlist(watchlist_id=watchlist_id, db=db)
    if not wl:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watchlist #{watchlist_id} not found",
        )
    return wl


@router.put("/{watchlist_id}", response_model=WatchlistResponse)
def update_watchlist(
    watchlist_id: int,
    payload: WatchlistUpdateRequest,
    db: Session = Depends(get_db),
):
    """
    Updates watchlist metadata (name, description, active status, notification channel).
    """
    updated = watchlist_service.update_watchlist(
        watchlist_id=watchlist_id,
        name=payload.name,
        description=payload.description,
        is_active=payload.is_active,
        notification_channel=payload.notification_channel,
        db=db,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watchlist #{watchlist_id} not found",
        )
    return updated


@router.delete("/{watchlist_id}", status_code=status.HTTP_200_OK)
def delete_watchlist(
    watchlist_id: int,
    db: Session = Depends(get_db),
):
    """
    Deletes a watchlist and all its associated monitored items.
    """
    success = watchlist_service.delete_watchlist(watchlist_id=watchlist_id, db=db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watchlist #{watchlist_id} not found",
        )
    return {"status": "deleted", "watchlist_id": watchlist_id}


@router.post("/{watchlist_id}/items", response_model=WatchlistItemResponse, status_code=status.HTTP_201_CREATED)
def add_watchlist_item(
    watchlist_id: int,
    payload: WatchlistItemCreateRequest,
    db: Session = Depends(get_db),
):
    """
    Adds a new monitored target item to an existing watchlist.
    Supported types: CVE, Product, Vendor, Threat Actor, Malware, Technology, Topic, Researcher, Tool, Keyword.
    """
    try:
        itype_clean = payload.item_type.lower()
        # Validate against the 10 mandated types
        valid_types = [t.value for t in WatchlistItemType]
        if itype_clean not in valid_types:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid item_type '{payload.item_type}'. Must be one of: {', '.join(valid_types)}",
            )

        item = watchlist_service.add_item(
            watchlist_id=watchlist_id,
            item_type=itype_clean,
            item_value=payload.item_value,
            severity_threshold=payload.severity_threshold,
            notify_on_match=payload.notify_on_match,
            db=db,
        )
        if not item:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Watchlist #{watchlist_id} not found",
            )
        return item
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to add watchlist item: {str(e)}",
        )


@router.delete("/{watchlist_id}/items/{item_id}", status_code=status.HTTP_200_OK)
def remove_watchlist_item(
    watchlist_id: int,
    item_id: int,
    db: Session = Depends(get_db),
):
    """
    Removes a monitored item from a watchlist.
    """
    success = watchlist_service.remove_item(item_id=item_id, db=db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Watchlist item #{item_id} not found",
        )
    return {"status": "removed", "item_id": item_id, "watchlist_id": watchlist_id}


@router.get("/{watchlist_id}/feed", response_model=WatchlistFeedResponse)
def get_watchlist_feed(
    watchlist_id: int,
    limit: int = Query(20, ge=1, le=100, description="Max items to retrieve"),
    db: Session = Depends(get_db),
):
    """
    Retrieves intelligence content matching any active monitored target in this watchlist.
    """
    try:
        return watchlist_service.get_watchlist_feed(watchlist_id=watchlist_id, limit=limit, db=db)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve watchlist feed: {str(e)}",
        )


@router.post("/match-test", response_model=List[MatchedWatchlistItemResponse])
def test_match_content(
    payload: WatchlistMatchTestRequest,
    watchlist_id: Optional[int] = Query(None, description="Optional specific watchlist ID to test"),
    db: Session = Depends(get_db),
):
    """
    Diagnostic endpoint testing whether a candidate content record triggers any watchlist rules.
    """
    try:
        content_dict = {
            "title": payload.title,
            "description": payload.description,
            "summary": payload.summary,
            "content_type": payload.content_type,
            "source": payload.source,
            "severity": payload.severity,
            "tags": payload.tags,
            "entities": payload.entities,
        }
        hits = watchlist_service.match_content_dict(content_dict, watchlist_id=watchlist_id, db=db)
        return hits
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Matching test failed: {str(e)}",
        )
