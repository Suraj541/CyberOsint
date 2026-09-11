"""
Cybersecurity Taxonomy Package
Provides the 16 canonical cybersecurity categories, stable category IDs,
hierarchical subcategories, and tag-to-category resolution services.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

from packages.taxonomy.categories import (
    CATEGORIES_CATALOGUE,
    Category,
    CategoryId,
    Subcategory,
)
from packages.taxonomy.mappings import CWE_TO_CATEGORY, TAG_TO_CATEGORY
from packages.taxonomy.registry import TaxonomyRegistry, taxonomy_registry

# Shortcut utility functions
get_category = taxonomy_registry.get_category
get_all_categories = taxonomy_registry.get_all_categories
resolve_tag = taxonomy_registry.resolve_tag
resolve_cwe = taxonomy_registry.resolve_cwe
match_keywords = taxonomy_registry.match_keywords

__all__ = [
    "CategoryId",
    "Category",
    "Subcategory",
    "CATEGORIES_CATALOGUE",
    "TaxonomyRegistry",
    "taxonomy_registry",
    "TAG_TO_CATEGORY",
    "CWE_TO_CATEGORY",
    "get_category",
    "get_all_categories",
    "resolve_tag",
    "resolve_cwe",
    "match_keywords",
]
