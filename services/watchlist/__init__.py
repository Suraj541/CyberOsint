"""
Watchlist Service Package
Exposes WatchlistService, WatchlistMatcher, and DTOs.
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from services.watchlist.matcher import WatchlistMatcher, watchlist_matcher
from services.watchlist.models import (
    MatchedContentItem,
    MatchedWatchlistItem,
    WatchlistCreateDTO,
    WatchlistDTO,
    WatchlistFeedResponse,
    WatchlistItemCreateDTO,
    WatchlistItemDTO,
    WatchlistItemType,
    WatchlistUpdateDTO,
)
from services.watchlist.service import WatchlistService, watchlist_service

__all__ = [
    "WatchlistItemType",
    "WatchlistItemCreateDTO",
    "WatchlistItemDTO",
    "WatchlistCreateDTO",
    "WatchlistUpdateDTO",
    "WatchlistDTO",
    "MatchedWatchlistItem",
    "MatchedContentItem",
    "WatchlistFeedResponse",
    "WatchlistMatcher",
    "watchlist_matcher",
    "WatchlistService",
    "watchlist_service",
]
