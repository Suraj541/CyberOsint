"""
Document Intelligence Core Processor
Executes the standardized document intelligence pipeline:
Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
Supports PDF, HTML, Markdown, TXT, DOCX, and PPTX with copyright-aware retention controls.
Conforms strictly to IMPLEMENT.md Section 25.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple, Union

from packages.classifier import rule_classifier
from packages.extractor import entity_extractor
from services.semantic.embedder import embedder
from services.semantic.chunker import text_chunker

from .models import (
    DocumentChunk,
    DocumentMetadata,
    DocumentResult,
    DocumentSectionChunk,
    DocumentType,
    RetentionMode,
)
from .extractors.html_extractor import HtmlExtractor
from .extractors.markdown_extractor import MarkdownExtractor
from .extractors.office_extractor import OfficeExtractor
from .extractors.pdf_extractor import PdfExtractor
from .extractors.text_extractor import TextExtractor

logger = logging.getLogger("cyber_osint.services.documents.processor")


class DocumentProcessor:
    """
    Orchestrates end-to-end document intelligence:
    Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
    """

    def __init__(self):
        self.html_extractor = HtmlExtractor()
        self.markdown_extractor = MarkdownExtractor()
        self.office_extractor = OfficeExtractor()
        self.pdf_extractor = PdfExtractor()
        self.text_extractor = TextExtractor()

    def process_document(
        self,
        content: Union[str, bytes],
        filename_or_url: str,
        doc_type: Optional[DocumentType] = None,
        retention_mode: RetentionMode = RetentionMode.FULL_TEXT,
        source_url: Optional[str] = None,
        compute_embeddings: bool = True,
        max_chunk_size: int = 500,
        chunk_overlap: int = 80,
    ) -> DocumentResult:
        """
        Processes a raw document through the complete intelligence pipeline.
        """
        # 1. Determine Document Type
        effective_type = doc_type or DocumentType.from_filename_or_type(filename_or_url)

        # 2. Extract Document (Metadata, Full Text, Sections)
        metadata, full_text, sections = self._extract_raw(
            content=content,
            doc_type=effective_type,
            filename_or_url=filename_or_url,
            source_url=source_url or filename_or_url,
        )

        # 3. Apply Retention Controls
        # Section 25: "Do not automatically retain copyrighted documents merely because
        # they are publicly downloadable. Where appropriate, retain metadata and source references instead."
        effective_retention = retention_mode
        if metadata.copyright_notice and retention_mode == RetentionMode.FULL_TEXT:
            # Check if copyright restricts full retention
            lower_notice = metadata.copyright_notice.lower()
            if any(term in lower_notice for term in ("all rights reserved", "proprietary", "confidential", "permission required")):
                logger.info("Restricted copyright detected for '%s'; enforcing METADATA_ONLY retention", metadata.title)
                effective_retention = RetentionMode.METADATA_ONLY

        metadata.retention_mode = effective_retention

        # 4. Generate Section-Preserving Chunks
        chunks = self._generate_section_chunks(
            sections=sections,
            max_chunk_size=max_chunk_size,
            chunk_overlap=chunk_overlap,
        )

        # 5. Deterministic Entity Extraction
        # Extract CVEs, CWEs, Malware, Threat Actors, Technologies, Domains, IPs, Hashes, ATT&CK techniques
        extracted_entities = self._extract_entities(full_text)

        # 6. Taxonomy Classification & Tagging
        primary_category, subcategory, confidence, tags = self._classify_and_tag(
            title=metadata.title,
            abstract=metadata.abstract,
            full_text=full_text,
            extracted_entities=extracted_entities,
        )

        # 7. Dense Vector Embeddings
        if compute_embeddings:
            self._compute_chunk_embeddings(chunks)

        # Construct and return result
        result = DocumentResult(
            metadata=metadata,
            raw_text=full_text,
            chunks=chunks,
            extracted_entities=extracted_entities,
            taxonomy_tags=tags,
            primary_category=primary_category,
            subcategory=subcategory,
            confidence=confidence,
        )

        return result

    def _extract_raw(
        self,
        content: Union[str, bytes],
        doc_type: DocumentType,
        filename_or_url: str,
        source_url: Optional[str],
    ) -> Tuple[DocumentMetadata, str, List[Tuple[str, str]]]:
        """Routes to appropriate extractor based on document type."""
        if doc_type == DocumentType.PDF:
            raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
            return self.pdf_extractor.extract(raw_bytes, filename=filename_or_url, source_url=source_url)

        if doc_type == DocumentType.DOCX:
            raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
            return self.office_extractor.extract_docx(raw_bytes, filename=filename_or_url, source_url=source_url)

        if doc_type == DocumentType.PPTX:
            raw_bytes = content.encode("utf-8") if isinstance(content, str) else content
            return self.office_extractor.extract_pptx(raw_bytes, filename=filename_or_url, source_url=source_url)

        text_str = content.decode("utf-8", errors="ignore") if isinstance(content, bytes) else str(content)

        if doc_type == DocumentType.HTML:
            return self.html_extractor.extract(text_str, source_url=source_url)

        if doc_type == DocumentType.MARKDOWN:
            return self.markdown_extractor.extract(text_str, source_url=source_url)

        # Default fallback is Plain Text
        return self.text_extractor.extract(text_str, source_url=source_url)

    def _generate_section_chunks(
        self,
        sections: List[Tuple[str, str]],
        max_chunk_size: int,
        chunk_overlap: int,
    ) -> List[DocumentSectionChunk]:
        """
        Splits sections into chunks while preserving section headings.
        """
        chunks: List[DocumentSectionChunk] = []
        chunk_counter = 0
        running_offset = 0

        for heading, body in sections:
            if not body or not body.strip():
                continue

            sub_chunks = text_chunker.chunk_text(
                text=body,
                chunk_size=max_chunk_size,
                overlap=chunk_overlap,
            )

            for sc in sub_chunks:
                sc_len = len(sc)
                chunk = DocumentSectionChunk(
                    chunk_index=chunk_counter,
                    heading=heading,
                    text=f"[{heading}] {sc}" if heading and heading != "Content" else sc,
                    char_start=running_offset,
                    char_end=running_offset + sc_len,
                )
                chunks.append(chunk)
                chunk_counter += 1
                running_offset += sc_len + 2

        return chunks

    def _extract_entities(self, text: str) -> List[Dict[str, Any]]:
        """Extracts structured entities deterministically from text."""
        if not text:
            return []
        try:
            raw_extracted = entity_extractor.extract(text)
            results = []
            for item in raw_extracted:
                results.append({
                    "name": item.name,
                    "entity_type": item.entity_type,
                    "normalized_name": item.normalized_name,
                    "confidence": item.confidence,
                    "context": item.context_snippet,
                })
            return results
        except Exception as exc:
            logger.warning("Entity extraction error in document processor: %s", exc)
            return []

    def _classify_and_tag(
        self,
        title: str,
        abstract: Optional[str],
        full_text: str,
        extracted_entities: List[Dict[str, Any]],
    ) -> Tuple[Optional[str], Optional[str], float, List[str]]:
        """Classifies document and assembles taxonomy tags."""
        category = "threat_intelligence"
        subcategory = None
        confidence = 0.5
        tags: List[str] = ["document"]

        try:
            pred = rule_classifier.classify(
                title=title,
                description=abstract or "",
                content_text=full_text[:3000],
            )
            category = pred.category
            subcategory = pred.subcategory
            confidence = pred.confidence
            tags.append(category)
            if subcategory:
                tags.append(subcategory)
        except Exception as exc:
            logger.warning("Classification error in document processor: %s", exc)

        # Include entity-based tags
        for ent in extracted_entities:
            ename = ent.get("name")
            if ename and ename not in tags and len(tags) < 15:
                tags.append(ename)

        return category, subcategory, confidence, tags

    def _compute_chunk_embeddings(self, chunks: List[DocumentSectionChunk]) -> None:
        """Generates dense vector embeddings for each document chunk."""
        for chunk in chunks:
            try:
                emb = embedder.embed_text(chunk.text)
                chunk.embedding = emb
            except Exception as exc:
                logger.warning("Embedding error on chunk %d: %s", chunk.chunk_index, exc)


# Global document processor singleton
document_processor = DocumentProcessor()


def extract_document(
    content: Union[str, bytes],
    filename_or_url: str,
    doc_type: Optional[DocumentType] = None,
    retention_mode: RetentionMode = RetentionMode.FULL_TEXT,
    source_url: Optional[str] = None,
) -> DocumentResult:
    """Convenience helper to process a document with default settings."""
    return document_processor.process_document(
        content=content,
        filename_or_url=filename_or_url,
        doc_type=doc_type,
        retention_mode=retention_mode,
        source_url=source_url,
    )
