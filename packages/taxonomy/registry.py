"""
Taxonomy Registry
Provides unified query, lookup, resolution, and keyword matching services
over the 16 canonical cybersecurity categories.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from packages.taxonomy.categories import (
    CATEGORIES_CATALOGUE,
    Category,
    CategoryId,
    Subcategory,
)
from packages.taxonomy.mappings import CWE_TO_CATEGORY, TAG_TO_CATEGORY

logger = logging.getLogger("cyber_osint.packages.taxonomy")


class TaxonomyRegistry:
    """
    Central registry for cybersecurity taxonomy categories, subcategories,
    tag aliases, and CWE mappings.
    """

    def __init__(self):
        self._categories: Dict[str, Category] = CATEGORIES_CATALOGUE
        self._tag_mappings: Dict[str, Tuple[str, Optional[str]]] = dict(TAG_TO_CATEGORY)
        self._cwe_mappings: Dict[str, Tuple[str, Optional[str]]] = dict(CWE_TO_CATEGORY)

    def get_category(self, category_id: str) -> Optional[Category]:
        """Lookup category definition by stable category ID."""
        return self._categories.get(str(category_id).lower().strip())

    def get_all_categories(self) -> List[Category]:
        """Return list of all 16 canonical categories."""
        return list(self._categories.values())

    def get_category_ids(self) -> List[str]:
        """Return list of all 16 stable category identifiers."""
        return list(self._categories.keys())

    def get_subcategories(self, category_id: str) -> List[Subcategory]:
        """Return list of subcategories for a given category ID."""
        cat = self.get_category(category_id)
        return cat.subcategories if cat else []

    def is_valid_category(self, category_id: str) -> bool:
        """Verify whether a category ID is a valid stable identifier."""
        return str(category_id).lower().strip() in self._categories

    def is_valid_subcategory(self, category_id: str, subcategory_id: str) -> bool:
        """Verify whether a subcategory ID belongs to the specified category ID."""
        cat = self.get_category(category_id)
        if not cat:
            return False
        return subcategory_id.lower().strip() in [s.id for s in cat.subcategories]

    def resolve_tag(self, tag: str) -> Optional[Dict[str, Any]]:
        """
        Resolve an arbitrary tag or alias string into its canonical category and subcategory.
        """
        if not tag:
            return None

        clean_tag = tag.strip().lower().replace(" ", "-").replace("_", "-")

        # 1. Direct tag lookup
        if clean_tag in self._tag_mappings:
            cat_id, sub_id = self._tag_mappings[clean_tag]
            cat = self.get_category(cat_id)
            return {
                "tag": tag,
                "category_id": cat_id,
                "category_name": cat.name if cat else cat_id,
                "subcategory_id": sub_id,
            }

        # 2. Match against category IDs or names directly
        for cat_id, cat in self._categories.items():
            if clean_tag in (cat_id.replace("_", "-"), cat.name.lower().replace(" ", "-")):
                return {
                    "tag": tag,
                    "category_id": cat_id,
                    "category_name": cat.name,
                    "subcategory_id": None,
                }
            # Check subcategories
            for sub in cat.subcategories:
                if clean_tag in (sub.id.replace("_", "-"), sub.name.lower().replace(" ", "-")):
                    return {
                        "tag": tag,
                        "category_id": cat_id,
                        "category_name": cat.name,
                        "subcategory_id": sub.id,
                        "subcategory_name": sub.name,
                    }

        return None

    def resolve_cwe(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Map a CWE identifier (e.g. 'CWE-79', '79', 'cwe-89') to canonical category and subcategory.
        """
        if not cwe_id:
            return None

        cleaned = cwe_id.strip().upper()
        if not cleaned.startswith("CWE-"):
            # If plain number like "79"
            if cleaned.isdigit():
                cleaned = f"CWE-{cleaned}"
            elif cleaned.startswith("CWE"):
                cleaned = f"CWE-{cleaned[3:]}"

        if cleaned in self._cwe_mappings:
            cat_id, sub_id = self._cwe_mappings[cleaned]
            cat = self.get_category(cat_id)
            return {
                "cwe": cleaned,
                "category_id": cat_id,
                "category_name": cat.name if cat else cat_id,
                "subcategory_id": sub_id,
            }

        return None

    def match_keywords(self, text: str, threshold: float = 0.0) -> List[Dict[str, Any]]:
        """
        Scan text against category keywords and subcategories to compute matching scores.
        Returns ranked list of matching categories.
        """
        if not text:
            return []

        text_lower = text.lower()
        results: List[Dict[str, Any]] = []

        for cat_id, cat in self._categories.items():
            matched_keywords = []
            score = 0.0

            # Check primary category keywords
            for kw in cat.keywords:
                pattern = r"\b" + re.escape(kw.lower()) + r"\b"
                matches = len(re.findall(pattern, text_lower))
                if matches > 0:
                    matched_keywords.append(kw)
                    score += matches * 1.0

            # Check subcategory keywords
            matched_subs = []
            for sub in cat.subcategories:
                for sub_kw in sub.keywords:
                    pattern = r"\b" + re.escape(sub_kw.lower()) + r"\b"
                    sub_matches = len(re.findall(pattern, text_lower))
                    if sub_matches > 0:
                        matched_keywords.append(sub_kw)
                        matched_subs.append(sub.id)
                        score += sub_matches * 1.5

            if score > threshold and matched_keywords:
                results.append({
                    "category_id": cat_id,
                    "category_name": cat.name,
                    "score": round(score, 2),
                    "matched_keywords": list(set(matched_keywords)),
                    "matched_subcategories": list(set(matched_subs)),
                })

        # Sort descending by score
        results.sort(key=lambda x: x["score"], reverse=True)
        return results


# Global singleton instance
taxonomy_registry = TaxonomyRegistry()
