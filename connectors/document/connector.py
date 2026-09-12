"""
Document Intelligence Connector
Discovers, fetches, parses, and normalizes cybersecurity documents, whitepapers,
threat reports, and academic research papers across PDF, HTML, Markdown, TXT, DOCX, and PPTX.
Conforms strictly to IMPLEMENT.md Section 25.
"""

from datetime import datetime, timezone
import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Union
import httpx

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError, validate_url_for_ssrf
from services.documents.models import DocumentType, RetentionMode
from services.documents.processor import document_processor

logger = logging.getLogger("cyber_osint.connectors.document")


@connector_registry.register("document")
@connector_registry.register("pdf")
@connector_registry.register("whitepaper")
@connector_registry.register("research_paper")
class DocumentConnector(BaseConnector):
    """
    Ingestion connector for Cybersecurity Document Intelligence.
    Handles whitepapers, threat research reports, NIST/CISA advisories, and technical papers.
    """

    DEFAULT_USER_AGENT = "CyberOSINT-Document-Bot/1.0 (+https://cyber-osint.local/bot)"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.raw_document_content: Optional[Union[str, bytes]] = self.config.get("document_content")
        self.raw_documents_list: Optional[List[Dict[str, Any]]] = self.config.get("documents")
        self.retention_mode = RetentionMode(self.config.get("retention_mode", RetentionMode.FULL_TEXT.value))

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/pdf, text/html, text/markdown, text/plain, application/json, */*",
        }

    def discover(self) -> List[Dict[str, Any]]:
        """
        Discover document entries from configuration, local filesystem, or remote directory list.
        Enforces SSRF preflight protection on all remote network URLs.
        """
        # 1. Direct document content provided in config
        if self.raw_document_content is not None:
            return [{
                "title": self.config.get("title"),
                "url": self.source_url or "https://cyber-osint.local/doc/configured",
                "content": self.raw_document_content,
                "filename": self.config.get("filename", "document.pdf"),
                "content_type": self.config.get("content_type", "document"),
                "author": self.config.get("author"),
                "published_at": self.config.get("published_at"),
            }]

        # 2. Structured documents list provided in config
        if self.raw_documents_list:
            items = self.raw_documents_list
            if self.max_entries:
                items = items[: self.max_entries]
            return items

        # 3. Remote URL discovery
        if not self.source_url:
            return []

        # Validate URL against SSRF
        validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(self.source_url, headers=self._get_headers())
                resp.raise_for_status()

                content_type = resp.headers.get("content-type", "").lower()

                # If the URL itself is directly a PDF/doc file
                if any(ext in self.source_url.lower() for ext in (".pdf", ".docx", ".pptx", ".md", ".txt")) or "pdf" in content_type:
                    return [{
                        "url": self.source_url,
                        "content": resp.content,
                        "filename": os.path.basename(self.source_url) or "downloaded_document.pdf",
                        "content_type": "document",
                    }]

                # If JSON manifest
                if "json" in content_type:
                    data = resp.json()
                    if isinstance(data, list):
                        return data[: self.max_entries] if self.max_entries else data
                    if isinstance(data, dict) and "documents" in data:
                        docs = data["documents"]
                        return docs[: self.max_entries] if self.max_entries else docs

                # If HTML directory/listing or article
                return [{
                    "url": self.source_url,
                    "content": resp.text,
                    "filename": "document.html",
                    "content_type": "document",
                }]
        except Exception as exc:
            logger.error("Document discovery error at %s: %s", self.source_url, exc)
            return []

    def fetch(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Fetch full content for a discovered document item if not already loaded.
        """
        if "content" in item and item["content"] is not None:
            return item

        url = item.get("url")
        if not url:
            return item

        validate_url_for_ssrf(url, allow_private=self.allow_private)

        with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
            resp = client.get(url, headers=self._get_headers())
            resp.raise_for_status()
            item_copy = dict(item)
            item_copy["content"] = resp.content
            item_copy["fetched_size"] = len(resp.content)
            return item_copy

    def parse(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw document content into processed intelligence result.
        """
        raw_content = response.get("content", "")
        filename = response.get("filename") or response.get("url", "document.pdf")
        doc_type_hint = response.get("doc_type")
        source_url = response.get("url") or self.source_url

        doc_type = DocumentType(doc_type_hint) if doc_type_hint else None

        result = document_processor.process_document(
            content=raw_content,
            filename_or_url=filename,
            doc_type=doc_type,
            retention_mode=self.retention_mode,
            source_url=source_url,
            compute_embeddings=True,
        )

        response_copy = dict(response)
        response_copy["parsed_result"] = result
        return response_copy

    def normalize(self, data: Dict[str, Any]) -> NormalizedItem:
        """
        Normalize parsed document result into standard NormalizedItem contract.
        """
        result = data.get("parsed_result")
        if not result:
            # Re-parse if raw data passed directly
            data = self.parse(data)
            result = data.get("parsed_result")

        meta = result.metadata
        canonical_url = data.get("url") or meta.source_url or self.source_url or "https://cyber-osint.local/doc/untitled"

        # Determine best title
        title = data.get("title") or meta.title
        author = ", ".join(meta.authors) if meta.authors else data.get("author")

        # Determine published date
        pub_date_str = meta.publication_date or data.get("published_at")
        published_iso = pub_date_str or datetime.now(timezone.utc).isoformat()

        # Build clean summary
        summary = meta.abstract or (result.raw_text[:500] + "..." if len(result.raw_text) > 500 else result.raw_text)

        # Build structured document metadata payload
        structured_metadata = {
            "document_metadata": {
                "document_type": meta.document_type.value,
                "authors": meta.authors,
                "publication_date": meta.publication_date,
                "abstract": meta.abstract,
                "page_count": meta.page_count,
                "word_count": meta.word_count,
                "file_size_bytes": meta.file_size_bytes,
                "section_headings": meta.section_headings,
                "copyright_notice": meta.copyright_notice,
                "retention_mode": meta.retention_mode.value,
                "chunks_count": len(result.chunks),
                "chunks_preview": [c.to_dict() for c in result.chunks[:10]],
            },
            "extracted_entities": result.extracted_entities,
            "category": result.primary_category,
            "subcategory": result.subcategory,
            "classification_confidence": result.confidence,
        }

        # Include raw text in body if FULL_TEXT retention mode
        body_text = result.raw_text if meta.retention_mode == RetentionMode.FULL_TEXT else f"[Abstract] {meta.abstract or title}"

        return NormalizedItem(
            title=title,
            url=canonical_url,
            description=summary,
            author=author,
            published_at=published_iso,
            source=self.source_name or "Document Repository",
            content_type="document",
            category=result.primary_category,
            subcategory=result.subcategory,
            tags=result.taxonomy_tags,
            body=body_text,
            metadata=structured_metadata,
        )

    def health_check(self) -> ConnectorHealth:
        """
        Verify connector operational health.
        """
        start_time = time.perf_counter()
        target_url = self.source_url or "local://document"
        if not self.source_url or self.raw_document_content is not None or self.raw_documents_list:
            return ConnectorHealth(
                status="ok",
                source_url=target_url,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                details={"message": "DocumentConnector configured with inline documents or ready for input."},
            )

        try:
            validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)
            with httpx.Client(timeout=10.0, follow_redirects=True) as client:
                resp = client.head(self.source_url, headers=self._get_headers())
                latency = (time.perf_counter() - start_time) * 1000.0
                is_healthy = resp.status_code < 400
                return ConnectorHealth(
                    status="ok" if is_healthy else "failing",
                    source_url=self.source_url,
                    latency_ms=latency,
                    error_message=None if is_healthy else f"HTTP {resp.status_code}",
                    details={"http_status": resp.status_code},
                )
        except Exception as exc:
            return ConnectorHealth(
                status="failing",
                source_url=target_url,
                latency_ms=(time.perf_counter() - start_time) * 1000.0,
                error_message=str(exc),
            )
