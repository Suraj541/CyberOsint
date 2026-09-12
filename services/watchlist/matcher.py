"""
Watchlist Matcher Engine
Evaluates intelligence content against the 10 mandated watchlist target types:
CVE, Product, Vendor, Threat Actor, Malware, Technology, Topic, Researcher, Tool, Keyword.
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from services.watchlist.models import (
    MatchedWatchlistItem,
    WatchlistItemDTO,
    WatchlistItemType,
)

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


class WatchlistMatcher:
    """
    Evaluates incoming or catalogued content against active watchlist items.
    """

    def __init__(self) -> None:
        pass

    def _normalize(self, val: str) -> str:
        return val.strip().lower()

    def _check_severity(self, content_severity: Optional[str], threshold: Optional[str]) -> bool:
        """Verifies if content severity satisfies or exceeds the threshold."""
        if not threshold:
            return True
        c_sev = (content_severity or "LOW").upper()
        t_sev = threshold.upper()
        c_rank = SEVERITY_ORDER.get(c_sev, 1)
        t_rank = SEVERITY_ORDER.get(t_sev, 1)
        return c_rank >= t_rank

    def match_item(
        self,
        item: WatchlistItemDTO,
        content_dict: Dict[str, Any],
        watchlist_name: str = "Watchlist",
    ) -> Optional[MatchedWatchlistItem]:
        """
        Evaluates a single WatchlistItemDTO against content_dict.
        Returns MatchedWatchlistItem if matched, else None.
        """
        itype = item.item_type.lower()
        ivalue = self._normalize(item.item_value)

        # Check severity threshold first
        content_sev = content_dict.get("severity")
        if item.severity_threshold and not self._check_severity(content_sev, item.severity_threshold):
            return None

        title = content_dict.get("title", "") or ""
        title_lower = title.lower()
        description = content_dict.get("description", "") or ""
        desc_lower = description.lower()
        summary = content_dict.get("summary", "") or ""
        summary_lower = summary.lower()
        author = content_dict.get("author", "") or ""
        author_lower = author.lower()
        source = content_dict.get("source", "") or ""
        source_lower = source.lower()
        category = content_dict.get("category", "") or ""
        cat_lower = category.lower()

        tags = [self._normalize(t) for t in content_dict.get("tags", [])]

        # Extract entities list (either string list or dict list)
        entities_data = content_dict.get("entities", [])
        entity_names = []
        entity_by_type: Dict[str, List[str]] = {}
        for e in entities_data:
            if isinstance(e, dict):
                ename = self._normalize(e.get("name", ""))
                etype = self._normalize(e.get("entity_type", "entity"))
                entity_names.append(ename)
                entity_by_type.setdefault(etype, []).append(ename)
            elif isinstance(e, str):
                ename = self._normalize(e)
                entity_names.append(ename)

        full_text = f"{title_lower} {desc_lower} {summary_lower}"

        # 1. CVE Type Matching
        if itype == WatchlistItemType.CVE.value:
            # Check CVE entity
            if any(ivalue == cve for cve in entity_by_type.get("cve", [])):
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="entities.cve",
                    matched_text=item.item_value,
                )
            if ivalue in title_lower:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="title",
                    matched_text=title,
                )
            if ivalue in full_text:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="summary",
                    matched_text=summary or description,
                )

        # 2. Product Matching
        elif itype == WatchlistItemType.PRODUCT.value:
            if any(ivalue in p for p in entity_by_type.get("product", [])):
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="entities.product",
                    matched_text=item.item_value,
                )
            if ivalue in title_lower or any(ivalue in t for t in tags):
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="title_or_tags",
                    matched_text=title,
                )

        # 3. Vendor Matching
        elif itype == WatchlistItemType.VENDOR.value:
            if any(ivalue in v for v in entity_by_type.get("vendor", [])):
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="entities.vendor",
                    matched_text=item.item_value,
                )
            if ivalue in source_lower or ivalue in title_lower:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="source_or_title",
                    matched_text=source or title,
                )

        # 4. Threat Actor Matching
        elif itype == WatchlistItemType.THREAT_ACTOR.value:
            actor_candidates = entity_by_type.get("threat_actor", []) + entity_by_type.get("actor", [])
            if any(ivalue in a for a in actor_candidates) or ivalue in title_lower or ivalue in full_text:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="threat_actor",
                    matched_text=item.item_value,
                )

        # 5. Malware Matching
        elif itype == WatchlistItemType.MALWARE.value:
            malware_candidates = entity_by_type.get("malware", [])
            if any(ivalue in m for m in malware_candidates) or ivalue in title_lower or ivalue in full_text:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="malware",
                    matched_text=item.item_value,
                )

        # 6. Technology Matching
        elif itype == WatchlistItemType.TECHNOLOGY.value:
            if any(ivalue in t for t in tags) or any(ivalue in e for e in entity_names) or ivalue in title_lower:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="technology",
                    matched_text=item.item_value,
                )

        # 7. Topic Matching
        elif itype == WatchlistItemType.TOPIC.value:
            if ivalue in cat_lower or any(ivalue in t for t in tags) or ivalue in title_lower:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="topic",
                    matched_text=item.item_value,
                )

        # 8. Researcher Matching
        elif itype == WatchlistItemType.RESEARCHER.value:
            if ivalue in author_lower or ivalue in title_lower or ivalue in full_text:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="researcher_author",
                    matched_text=author or item.item_value,
                )

        # 9. Tool Matching
        elif itype == WatchlistItemType.TOOL.value:
            tool_candidates = entity_by_type.get("tool", [])
            if any(ivalue in t for t in tool_candidates) or any(ivalue in t for t in tags) or ivalue in title_lower:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="tool",
                    matched_text=item.item_value,
                )

        # 10. Keyword Matching (fallback generic term)
        else:
            pattern = re.escape(ivalue)
            if re.search(r"\b" + pattern + r"\b", full_text, re.IGNORECASE) or ivalue in full_text:
                return MatchedWatchlistItem(
                    watchlist_id=item.watchlist_id,
                    watchlist_name=watchlist_name,
                    item_id=item.id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    matched_field="keyword_text",
                    matched_text=item.item_value,
                )

        return None

    def match_all(
        self,
        items: List[WatchlistItemDTO],
        content_dict: Dict[str, Any],
        watchlist_name: str = "Watchlist",
    ) -> List[MatchedWatchlistItem]:
        """Evaluates multiple items and returns all matching hits."""
        hits: List[MatchedWatchlistItem] = []
        for item in items:
            hit = self.match_item(item, content_dict, watchlist_name)
            if hit:
                hits.append(hit)
        return hits


watchlist_matcher = WatchlistMatcher()
