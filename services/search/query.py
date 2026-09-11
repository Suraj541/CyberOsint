"""
OpenSearch Query Builder Module
Constructs standard OpenSearch/Elasticsearch DSL queries with multi-match, phrase matching,
boolean filters, aggregations, and highlighting.
Conforms to IMPLEMENT.md Section 18.
"""

from typing import Any, Dict, List
from services.search.models import SearchQuery


class OpenSearchQueryBuilder:
    """Constructs OpenSearch DSL queries from structured SearchQuery criteria."""

    @classmethod
    def build(cls, sq: SearchQuery) -> Dict[str, Any]:
        """Build full OpenSearch DSL request payload."""
        must_clauses: List[Dict[str, Any]] = []
        filter_clauses: List[Dict[str, Any]] = []

        # 1. Full-Text Query / Phrase Match
        if sq.phrase:
            must_clauses.append({
                "multi_match": {
                    "query": sq.phrase,
                    "type": "phrase",
                    "fields": ["title^3", "description^2", "summary^2"],
                }
            })
        elif sq.query:
            must_clauses.append({
                "multi_match": {
                    "query": sq.query,
                    "fields": [
                        "title^3",
                        "summary^2",
                        "description",
                        "tags^2",
                        "entities.name^2",
                        "author",
                    ],
                    "type": "best_fields",
                    "operator": "or",
                }
            })
        else:
            must_clauses.append({"match_all": {}})

        # 2. Strict Boolean Filters
        if sq.category:
            filter_clauses.append({"term": {"category": sq.category.lower().strip()}})

        if sq.source:
            filter_clauses.append({"term": {"source": sq.source.strip()}})

        if sq.content_type:
            filter_clauses.append({"term": {"content_type": sq.content_type.lower().strip()}})

        if sq.tag:
            filter_clauses.append({"term": {"tags": sq.tag.lower().strip()}})

        if sq.entity:
            entity_clean = sq.entity.strip().lower()
            filter_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"entities.normalized_name": entity_clean}},
                        {"term": {"entities.name": entity_clean}},
                    ],
                    "minimum_should_match": 1,
                }
            })

        if sq.entity_type:
            filter_clauses.append({"term": {"entities.entity_type": sq.entity_type.lower().strip()}})

        if sq.date_from or sq.date_to:
            range_clause: Dict[str, Any] = {}
            if sq.date_from:
                range_clause["gte"] = sq.date_from.isoformat()
            if sq.date_to:
                range_clause["lte"] = sq.date_to.isoformat()
            filter_clauses.append({"range": {"published_at": range_clause}})

        # Assemble bool query
        query_dict: Dict[str, Any] = {"bool": {}}
        if must_clauses:
            query_dict["bool"]["must"] = must_clauses
        if filter_clauses:
            query_dict["bool"]["filter"] = filter_clauses

        # 3. Sorting
        sort: List[Any] = []
        if sq.sort_by == "newest":
            sort = [{"published_at": {"order": "desc", "missing": "_last"}}, "_score"]
        elif sq.sort_by == "oldest":
            sort = [{"published_at": {"order": "asc", "missing": "_last"}}, "_score"]
        else:  # relevance
            sort = ["_score", {"published_at": {"order": "desc", "missing": "_last"}}]

        # 4. Pagination & Offsets
        from_offset = (sq.page - 1) * sq.page_size

        # 5. Faceted Aggregations
        aggs = {
            "categories": {"terms": {"field": "category", "size": 25}},
            "sources": {"terms": {"field": "source", "size": 25}},
            "content_types": {"terms": {"field": "content_type", "size": 10}},
            "entities": {"terms": {"field": "entities.normalized_name", "size": 25}},
        }

        # 6. Highlighting
        highlight = {
            "pre_tags": ["<mark>"],
            "post_tags": ["</mark>"],
            "fields": {
                "title": {"number_of_fragments": 0},
                "description": {"fragment_size": 150, "number_of_fragments": 2},
                "summary": {"fragment_size": 150, "number_of_fragments": 2},
            },
        }

        return {
            "from": from_offset,
            "size": sq.page_size,
            "query": query_dict,
            "sort": sort,
            "aggs": aggs,
            "highlight": highlight,
        }
