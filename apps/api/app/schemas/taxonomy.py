"""
Taxonomy Pydantic Schemas
Defines request and response schemas for categories, subcategories,
tag resolution, and keyword matching.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SubcategoryResponse(BaseModel):
    """Subcategory response model."""

    id: str = Field(..., description="Stable snake_case subcategory ID")
    name: str = Field(..., description="Human-readable subcategory name")
    description: str = Field(..., description="Subcategory scope description")
    keywords: List[str] = Field(default_factory=list, description="Associated domain keywords")


class CategoryResponse(BaseModel):
    """Detailed category response model with subcategories."""

    id: str = Field(..., description="Stable snake_case category identifier")
    name: str = Field(..., description="Category display title")
    description: str = Field(..., description="Domain scope and definitions")
    subcategories: List[SubcategoryResponse] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    canonical_tags: List[str] = Field(default_factory=list)


class CategorySummaryResponse(BaseModel):
    """Summary representation of a top-level category."""

    id: str
    name: str
    description: str
    subcategory_count: int = 0


class TagResolutionResponse(BaseModel):
    """Result of mapping a free-form tag or alias to a canonical category ID."""

    tag: str
    category_id: str
    category_name: str
    subcategory_id: Optional[str] = None
    subcategory_name: Optional[str] = None


class CWEResolutionResponse(BaseModel):
    """Result of mapping a CWE identifier to a canonical category ID."""

    cwe: str
    category_id: str
    category_name: str
    subcategory_id: Optional[str] = None


class KeywordMatchResponse(BaseModel):
    """Result of scanning text against category keywords."""

    category_id: str
    category_name: str
    score: float
    matched_keywords: List[str] = Field(default_factory=list)
    matched_subcategories: List[str] = Field(default_factory=list)
