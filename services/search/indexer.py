"""
OpenSearch Schema & Indexing Module
Defines mapping properties for the cyber_osint_content index and normalizes
SQLAlchemy Content instances into searchable JSON documents.
Conforms to IMPLEMENT.md Section 18.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime


CYBER_OSINT_INDEX_NAME = "cyber_osint_content"

INDEX_MAPPING: Dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "analyzer": {
                "cyber_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "stop"],
                }
            }
        },
    },
    "mappings": {
        "properties": {
            "id": {"type": "integer"},
            "title": {
                "type": "text",
                "analyzer": "cyber_analyzer",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
            },
            "description": {"type": "text", "analyzer": "cyber_analyzer"},
            "summary": {"type": "text", "analyzer": "cyber_analyzer"},
            "canonical_url": {"type": "keyword"},
            "source": {"type": "keyword"},
            "category": {"type": "keyword"},
            "content_type": {"type": "keyword"},
            "author": {"type": "keyword"},
            "published_at": {"type": "date"},
            "discovered_at": {"type": "date"},
            "tags": {"type": "keyword"},
            "entities": {
                "properties": {
                    "entity_type": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "normalized_name": {"type": "keyword"},
                    "confidence": {"type": "float"},
                }
            },
            "quality_score": {"type": "float"},
            "confidence_score": {"type": "float"},
            "relevance_score": {"type": "float"},
        }
    },
}


def serialize_content_document(
    content: Any,
    source_name: Optional[str] = None,
    category: Optional[str] = None,
    tags: Optional[List[str]] = None,
    entities: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Transform a Content instance (or dict) into an OpenSearch document payload
    containing all 10 mandated Section 18 fields.
    """
    if isinstance(content, dict):
        cid = content.get("id") or 0
        title = content.get("title") or ""
        desc = content.get("description") or ""
        summary = content.get("summary") or ""
        url = content.get("canonical_url") or content.get("url") or ""
        src = source_name or content.get("source") or ""
        cat = category or content.get("category") or ""
        ctype = content.get("content_type") or "article"
        author = content.get("author") or ""
        pub_at = content.get("published_at")
        disc_at = content.get("discovered_at")
        doc_tags = tags or content.get("tags") or []
        doc_entities = entities or content.get("entities") or []
    else:
        cid = getattr(content, "id", 0)
        title = getattr(content, "title", "") or ""
        desc = getattr(content, "description", "") or ""
        summary = getattr(content, "summary", "") or ""
        url = getattr(content, "canonical_url", "") or ""
        src = source_name or (content.source.name if getattr(content, "source", None) else "")
        cat = category or getattr(content, "category", "") or ""
        ctype = getattr(content, "content_type", "article") or "article"
        author = getattr(content, "author", "") or ""
        pub_at = getattr(content, "published_at", None)
        disc_at = getattr(content, "discovered_at", None)

        # Extract tags from relationships if available
        if tags is not None:
            doc_tags = tags
        elif hasattr(content, "content_tags") and content.content_tags:
            doc_tags = [
                ct.tag.name.lower()
                for ct in content.content_tags
                if hasattr(ct, "tag") and ct.tag
            ]
        else:
            doc_tags = []

        # Extract entities from relationships if available
        if entities is not None:
            doc_entities = entities
        elif hasattr(content, "content_entities") and content.content_entities:
            doc_entities = [
                {
                    "entity_type": ce.entity.entity_type,
                    "name": ce.entity.name,
                    "normalized_name": ce.entity.normalized_name,
                    "confidence": ce.confidence or 0.8,
                }
                for ce in content.content_entities
                if hasattr(ce, "entity") and ce.entity
            ]
        else:
            doc_entities = []

    # Automatically classify content if category is not explicitly provided
    if not cat:
        try:
            from services.classifier import classify_content
            classified = classify_content(
                title=title,
                description=desc,
                content_text=summary,
            )
            if classified and classified.category:
                cat = classified.category
        except Exception:
            pass

    if not cat:
        # Fallback to tag name if tag is a domain/subdomain
        if not isinstance(content, dict) and hasattr(content, "content_tags") and content.content_tags:
            for ct in content.content_tags:
                if hasattr(ct, "tag") and ct.tag and ct.tag.category in ("domain", "subdomain"):
                    cat = ct.tag.name
                    break

    if not cat:
        if "cve-" in title.lower() or ctype == "cve":
            cat = "vulnerability_management"
        else:
            cat = "threat_intelligence"


    def _format_date(dt: Any) -> Optional[str]:
        if isinstance(dt, datetime):
            return dt.isoformat()
        if isinstance(dt, str):
            return dt
        return None

    return {
        "id": cid,
        "title": title,
        "description": desc,
        "summary": summary,
        "canonical_url": url,
        "source": src,
        "category": cat.lower() if cat else "threat_intelligence",
        "content_type": ctype.lower() if ctype else "article",
        "author": author,
        "published_at": _format_date(pub_at),
        "discovered_at": _format_date(disc_at) or datetime.utcnow().isoformat(),
        "tags": [t.lower().strip() for t in doc_tags if t],
        "entities": doc_entities,
    }
