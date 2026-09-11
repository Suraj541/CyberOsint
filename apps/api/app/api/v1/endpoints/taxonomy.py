"""
Taxonomy API Endpoints
Provides search, retrieval, tag resolution, and keyword matching endpoints
for the standardized 16 cybersecurity categories.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from packages.taxonomy import taxonomy_registry
from app.schemas.taxonomy import (
    CategoryResponse,
    CWEResolutionResponse,
    KeywordMatchResponse,
    SubcategoryResponse,
    TagResolutionResponse,
)

router = APIRouter(prefix="/taxonomy", tags=["Cybersecurity Taxonomy"])


class MatchRequest(BaseModel):
    text: str


@router.get(
    "/categories",
    response_model=List[CategoryResponse],
    status_code=status.HTTP_200_OK,
    summary="List All Cybersecurity Categories",
)
def list_categories() -> List[CategoryResponse]:
    """Retrieve all 16 canonical categories with hierarchical subcategories and keywords."""
    categories = taxonomy_registry.get_all_categories()
    result = []
    for cat in categories:
        sub_list = [
            SubcategoryResponse(
                id=sub.id,
                name=sub.name,
                description=sub.description,
                keywords=sub.keywords,
            )
            for sub in cat.subcategories
        ]
        result.append(
            CategoryResponse(
                id=cat.id,
                name=cat.name,
                description=cat.description,
                subcategories=sub_list,
                keywords=cat.keywords,
                canonical_tags=cat.canonical_tags,
            )
        )
    return result


@router.get(
    "/categories/{category_id}",
    response_model=CategoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Category by ID",
)
def get_category(category_id: str) -> CategoryResponse:
    """Retrieve detailed category information by its stable snake_case identifier."""
    cat = taxonomy_registry.get_category(category_id)
    if not cat:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Category '{category_id}' not found in cybersecurity taxonomy",
        )

    sub_list = [
        SubcategoryResponse(
            id=sub.id,
            name=sub.name,
            description=sub.description,
            keywords=sub.keywords,
        )
        for sub in cat.subcategories
    ]
    return CategoryResponse(
        id=cat.id,
        name=cat.name,
        description=cat.description,
        subcategories=sub_list,
        keywords=cat.keywords,
        canonical_tags=cat.canonical_tags,
    )


@router.get(
    "/resolve-tag",
    response_model=TagResolutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve Free-Form Tag to Canonical Category",
)
def resolve_tag(tag: str = Query(..., min_length=1, description="Raw tag or buzzword to resolve")) -> TagResolutionResponse:
    """
    Map an arbitrary keyword or source tag (e.g. 'ransomware', 'k8s', 'zero-day')
    to its canonical category and subcategory ID.
    """
    match = taxonomy_registry.resolve_tag(tag)
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag '{tag}' could not be resolved to any taxonomy category",
        )
    return TagResolutionResponse(
        tag=match["tag"],
        category_id=match["category_id"],
        category_name=match["category_name"],
        subcategory_id=match.get("subcategory_id"),
        subcategory_name=match.get("subcategory_name"),
    )


@router.get(
    "/resolve-cwe/{cwe_id}",
    response_model=CWEResolutionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resolve CWE ID to Canonical Category",
)
def resolve_cwe(cwe_id: str) -> CWEResolutionResponse:
    """Map a Common Weakness Enumeration ID (e.g. 'CWE-89', '79') to its taxonomy category."""
    match = taxonomy_registry.resolve_cwe(cwe_id)
    if not match:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CWE '{cwe_id}' could not be mapped to any taxonomy category",
        )
    return CWEResolutionResponse(
        cwe=match["cwe"],
        category_id=match["category_id"],
        category_name=match["category_name"],
        subcategory_id=match.get("subcategory_id"),
    )


@router.post(
    "/match",
    response_model=List[KeywordMatchResponse],
    status_code=status.HTTP_200_OK,
    summary="Match Text Keywords Against Taxonomy",
)
def match_text(request: MatchRequest) -> List[KeywordMatchResponse]:
    """Scan arbitrary text and score matching taxonomy categories."""
    matches = taxonomy_registry.match_keywords(request.text)
    return [
        KeywordMatchResponse(
            category_id=m["category_id"],
            category_name=m["category_name"],
            score=m["score"],
            matched_keywords=m["matched_keywords"],
            matched_subcategories=m["matched_subcategories"],
        )
        for m in matches
    ]
