"""
OpenSearch Client & In-Memory Fallback Engine
Provides HTTP client operations for OpenSearch with an automatic in-memory fallback
for offline testing and development environments without a live cluster.
Conforms to IMPLEMENT.md Section 18.
"""

import json
import logging
import re
import time
import urllib.error
import urllib.request
from datetime import datetime
from typing import Any, Counter, Dict, List, Optional

from services.search.indexer import CYBER_OSINT_INDEX_NAME, INDEX_MAPPING

logger = logging.getLogger("cyber_osint.services.search.client")


class OpenSearchClient:
    """
    OpenSearch HTTP Client with automatic graceful in-memory fallback.
    Standardizes searching, indexing, and health checks across environments.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9200",
        index_name: str = CYBER_OSINT_INDEX_NAME,
        timeout: float = 0.3,
    ):
        self.base_url = base_url.rstrip("/")
        self.index_name = index_name
        self.timeout = timeout

        # In-memory document store for offline / test operation
        self._in_memory_docs: Dict[int, Dict[str, Any]] = {}
        self._is_cluster_available: Optional[bool] = None
        self._last_ping_time: float = 0.0

    def _http_request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Execute JSON HTTP request to OpenSearch cluster."""
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body) if body else {}
        except Exception as exc:
            logger.debug("OpenSearch HTTP request %s %s failed: %s", method, path, exc)
            return None

    def ping(self, force_check: bool = False) -> bool:
        """Check whether the OpenSearch cluster is reachable."""
        now = time.time()
        if not force_check and self._is_cluster_available is not None and (now - self._last_ping_time < 30.0):
            return self._is_cluster_available

        self._last_ping_time = now
        res = self._http_request("GET", "/")
        if res and ("version" in res or "tagline" in res):
            self._is_cluster_available = True
            return True

        self._is_cluster_available = False
        return False

    def ensure_index(self) -> bool:
        """Create the target index with mapping if not already existing."""
        if not self.ping():
            return True  # Fallback handles in-memory schema implicitly

        # Check if index exists
        exists = self._http_request("HEAD", f"/{self.index_name}")
        if exists is not None:
            return True

        # Create index
        res = self._http_request("PUT", f"/{self.index_name}", payload=INDEX_MAPPING)
        return bool(res and (res.get("acknowledged") or "error" not in res))

    def index_document(self, doc_id: int, document: Dict[str, Any]) -> bool:
        """Index a single document by ID."""
        document["id"] = doc_id
        # Always maintain in-memory mirror
        self._in_memory_docs[doc_id] = document

        if not self.ping():
            return True

        res = self._http_request("PUT", f"/{self.index_name}/_doc/{doc_id}", payload=document)
        return bool(res and res.get("result") in ("created", "updated"))

    def bulk_index(self, documents: List[Dict[str, Any]]) -> int:
        """Bulk index documents."""
        count = 0
        for doc in documents:
            doc_id = doc.get("id")
            if doc_id is not None:
                self.index_document(doc_id, doc)
                count += 1
        return count

    def delete_document(self, doc_id: int) -> bool:
        """Delete a document by ID."""
        self._in_memory_docs.pop(doc_id, None)
        if not self.ping():
            return True
        res = self._http_request("DELETE", f"/{self.index_name}/_doc/{doc_id}")
        return bool(res and res.get("result") == "deleted")

    def search(self, query_dsl: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute search query against OpenSearch cluster, or evaluate via
        in-memory fallback search engine when cluster is offline.
        """
        if self.ping():
            res = self._http_request("POST", f"/{self.index_name}/_search", payload=query_dsl)
            if res is not None and "hits" in res:
                return res

        # Cluster offline -> Execute in-memory deterministic fallback search
        return self._search_in_memory(query_dsl)

    def stats(self) -> Dict[str, Any]:
        """Return search engine document statistics and cluster health."""
        is_live = self.ping(force_check=True)
        if is_live:
            count_res = self._http_request("GET", f"/{self.index_name}/_count")
            health_res = self._http_request("GET", "/_cluster/health")
            doc_count = count_res.get("count", 0) if count_res else len(self._in_memory_docs)
            status = health_res.get("status", "green") if health_res else "green"
            return {
                "engine": "opensearch",
                "status": status,
                "cluster_online": True,
                "document_count": doc_count,
                "index_name": self.index_name,
            }

        return {
            "engine": "in_memory_fallback",
            "status": "healthy",
            "cluster_online": False,
            "document_count": len(self._in_memory_docs),
            "index_name": self.index_name,
        }

    def clear_in_memory_index(self) -> None:
        """Clear in-memory document store (primarily for unit tests)."""
        self._in_memory_docs.clear()

    # -----------------------------------------------------------------
    # Deterministic In-Memory Search Engine Implementation
    # -----------------------------------------------------------------
    def _search_in_memory(self, query_dsl: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate OpenSearch DSL query against in-memory documents."""
        start_time = time.time()
        bool_query = query_dsl.get("query", {}).get("bool", {})
        must_clauses = bool_query.get("must", [])
        filter_clauses = bool_query.get("filter", [])

        # Extract search keywords and phrases
        phrase_term: Optional[str] = None
        keywords: List[str] = []

        for must in must_clauses:
            if "multi_match" in must:
                mm = must["multi_match"]
                if mm.get("type") == "phrase":
                    phrase_term = mm.get("query", "").lower()
                else:
                    q_str = mm.get("query", "").lower()
                    keywords = [w for w in re.split(r"\s+", q_str) if w]

        matched_hits: List[Dict[str, Any]] = []

        for doc_id, doc in self.index_memory_items():
            # 1. Evaluate Filters
            if not self._eval_filters(doc, filter_clauses):
                continue

            # 2. Evaluate Full-Text / Phrase Criteria & Score
            score = 1.0
            highlights: Dict[str, List[str]] = {}

            if phrase_term:
                full_text = f"{doc.get('title', '')} {doc.get('description', '')} {doc.get('summary', '')}".lower()
                if phrase_term not in full_text:
                    continue
                score += 5.0
                if phrase_term in doc.get("title", "").lower():
                    highlights["title"] = [doc.get("title", "")]
                if phrase_term in doc.get("description", "").lower():
                    highlights["description"] = [doc.get("description", "")]

            elif keywords:
                keyword_matched = False
                doc_title = doc.get("title", "").lower()
                doc_desc = doc.get("description", "").lower()
                doc_summary = doc.get("summary", "").lower()
                doc_tags = [str(t).lower() for t in doc.get("tags", [])]
                doc_entities = [str(e.get("name", "")).lower() for e in doc.get("entities", [])]

                for kw in keywords:
                    if kw in doc_title:
                        score += 3.0
                        keyword_matched = True
                        highlights.setdefault("title", []).append(doc.get("title", ""))
                    if kw in doc_summary:
                        score += 2.0
                        keyword_matched = True
                        highlights.setdefault("summary", []).append(doc.get("summary", ""))
                    if kw in doc_desc:
                        score += 1.0
                        keyword_matched = True
                        highlights.setdefault("description", []).append(doc.get("description", ""))
                    if any(kw in t for t in doc_tags):
                        score += 2.0
                        keyword_matched = True
                    if any(kw in ent for ent in doc_entities):
                        score += 2.5
                        keyword_matched = True

                if not keyword_matched:
                    continue

            matched_hits.append({
                "_id": str(doc_id),
                "_score": round(score, 2),
                "_source": doc,
                "highlight": highlights,
            })

        # 3. Sort Results
        sort_spec = query_dsl.get("sort", [])
        if any(isinstance(s, dict) and "published_at" in s and s["published_at"].get("order") == "desc" for s in sort_spec):
            matched_hits.sort(key=lambda h: h["_source"].get("published_at") or "", reverse=True)
        elif any(isinstance(s, dict) and "published_at" in s and s["published_at"].get("order") == "asc" for s in sort_spec):
            matched_hits.sort(key=lambda h: h["_source"].get("published_at") or "")
        else:  # Default score sort
            matched_hits.sort(key=lambda h: h["_score"], reverse=True)

        # 4. Facets / Aggregations Calculation
        cat_counts = Counter(h["_source"].get("category") for h in matched_hits if h["_source"].get("category"))
        src_counts = Counter(h["_source"].get("source") for h in matched_hits if h["_source"].get("source"))
        ctype_counts = Counter(h["_source"].get("content_type") for h in matched_hits if h["_source"].get("content_type"))
        
        ent_counts: Counter = Counter()
        for h in matched_hits:
            for ent in h["_source"].get("entities", []):
                ename = ent.get("normalized_name") or ent.get("name")
                if ename:
                    ent_counts[ename] += 1

        # 5. Pagination
        from_offset = query_dsl.get("from", 0)
        size = query_dsl.get("size", 20)
        paginated_hits = matched_hits[from_offset : from_offset + size]

        took = round((time.time() - start_time) * 1000, 2)

        return {
            "took": max(1, int(took)),
            "timed_out": False,
            "hits": {
                "total": {"value": len(matched_hits), "relation": "eq"},
                "hits": paginated_hits,
            },
            "aggregations": {
                "categories": {"buckets": [{"key": k, "doc_count": v} for k, v in cat_counts.most_common(20)]},
                "sources": {"buckets": [{"key": k, "doc_count": v} for k, v in src_counts.most_common(20)]},
                "content_types": {"buckets": [{"key": k, "doc_count": v} for k, v in ctype_counts.most_common(10)]},
                "entities": {"buckets": [{"key": k, "doc_count": v} for k, v in ent_counts.most_common(20)]},
            },
        }

    def index_memory_items(self):
        """Helper returning list of (id, doc) items."""
        return list(self._in_memory_docs.items())

    def _eval_filters(self, doc: Dict[str, Any], filter_clauses: List[Dict[str, Any]]) -> bool:
        """Evaluate boolean filter criteria against a document."""
        for fc in filter_clauses:
            if "term" in fc:
                field_name, expected = list(fc["term"].items())[0]
                expected = str(expected).lower()
                if field_name == "category":
                    if str(doc.get("category", "")).lower() != expected:
                        return False
                elif field_name == "source":
                    if str(doc.get("source", "")).lower() != expected:
                        return False
                elif field_name == "content_type":
                    if str(doc.get("content_type", "")).lower() != expected:
                        return False
                elif field_name == "tags":
                    doc_tags = [str(t).lower() for t in doc.get("tags", [])]
                    if expected not in doc_tags:
                        return False
                elif field_name == "entities.entity_type":
                    types = [str(e.get("entity_type", "")).lower() for e in doc.get("entities", [])]
                    if expected not in types:
                        return False

            elif "bool" in fc and "should" in fc["bool"]:
                # Used for entity matches (name or normalized_name)
                matched_should = False
                for should_clause in fc["bool"]["should"]:
                    if "term" in should_clause:
                        f_name, val = list(should_clause["term"].items())[0]
                        val_str = str(val).lower()
                        for ent in doc.get("entities", []):
                            norm = str(ent.get("normalized_name", "")).lower()
                            raw_n = str(ent.get("name", "")).lower()
                            if val_str in (norm, raw_n):
                                matched_should = True
                                break
                    if matched_should:
                        break
                if not matched_should:
                    return False

            elif "range" in fc and "published_at" in fc["range"]:
                r_spec = fc["range"]["published_at"]
                doc_pub = doc.get("published_at")
                if not doc_pub:
                    return False
                try:
                    doc_dt = datetime.fromisoformat(doc_pub.replace("Z", "+00:00"))
                    if "gte" in r_spec and r_spec["gte"]:
                        gte_dt = datetime.fromisoformat(r_spec["gte"].replace("Z", "+00:00"))
                        if doc_dt < gte_dt:
                            return False
                    if "lte" in r_spec and r_spec["lte"]:
                        lte_dt = datetime.fromisoformat(r_spec["lte"].replace("Z", "+00:00"))
                        if doc_dt > lte_dt:
                            return False
                except Exception:
                    pass

        return True


# Global client singleton
opensearch_client = OpenSearchClient()
