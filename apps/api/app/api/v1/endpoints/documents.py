"""
Document Intelligence REST API Endpoints
Provides endpoints for document ingestion, multi-format extraction, section chunking,
entity extraction, and vector embedding generation.
Conforms strictly to IMPLEMENT.md Section 25.
"""

import base64
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.chunk import ContentChunk
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.tag import ContentTag, Tag
from app.schemas.content import ContentResponse
from app.schemas.document import (
    DocumentChunkResponse,
    DocumentMetadataResponse,
    DocumentProcessRequest,
    DocumentProcessResponse,
)
from services.documents import (
    DocumentMetadata,
    DocumentResult,
    DocumentType,
    RetentionMode,
    document_processor,
)
from services.ingestion.deduplication import compute_content_hash

logger = logging.getLogger("cyber_osint.api.documents")

router = APIRouter(prefix="/documents", tags=["Document Intelligence"])


@router.post(
    "/process",
    response_model=DocumentProcessResponse,
    status_code=status.HTTP_200_OK,
    summary="Process Document through Intelligence Pipeline",
)
def process_document_endpoint(
    req: DocumentProcessRequest,
    db: Session = Depends(get_db),
) -> DocumentProcessResponse:
    """
    Executes the complete document intelligence pipeline:
    Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings.
    Supports PDF, HTML, Markdown, TXT, DOCX, and PPTX with copyright retention controls.
    """
    raw_content: Any = req.content or ""
    filename = req.filename or "document.pdf"

    # Handle base64 binary encoding for binary formats (PDF, DOCX, PPTX)
    if req.content and (filename.endswith((".pdf", ".docx", ".pptx")) or req.doc_type in ("pdf", "docx", "pptx")):
        try:
            raw_content = base64.b64decode(req.content)
        except Exception:
            # Fall back to string if not base64
            pass

    doc_type = DocumentType(req.doc_type) if req.doc_type else None
    retention_mode = RetentionMode(req.retention_mode) if req.retention_mode else RetentionMode.FULL_TEXT

    result: DocumentResult = document_processor.process_document(
        content=raw_content,
        filename_or_url=filename,
        doc_type=doc_type,
        retention_mode=retention_mode,
        source_url=req.url,
        compute_embeddings=True,
    )

    meta = result.metadata
    meta_resp = DocumentMetadataResponse(
        title=meta.title,
        authors=meta.authors,
        publication_date=meta.publication_date,
        abstract=meta.abstract,
        document_type=meta.document_type.value,
        page_count=meta.page_count,
        word_count=meta.word_count,
        file_size_bytes=meta.file_size_bytes,
        section_headings=meta.section_headings,
        copyright_notice=meta.copyright_notice,
        retention_mode=meta.retention_mode.value,
        source_url=meta.source_url,
    )

    chunks_resp = [
        DocumentChunkResponse(
            chunk_index=c.chunk_index,
            heading=c.heading,
            text=c.text,
            char_start=c.char_start,
            char_end=c.char_end,
            page_number=c.page_number,
            has_embedding=c.embedding is not None,
        )
        for c in result.chunks
    ]

    content_id: Optional[int] = None

    # Optionally persist parsed document into database
    if req.save_to_db:
        try:
            content_hash = compute_content_hash(
                url=req.url or f"https://cyber-osint.local/doc/{filename}",
                title=meta.title,
                raw_content=result.raw_text[:200],
            )

            body_to_save = result.raw_text if meta.retention_mode == RetentionMode.FULL_TEXT else f"[Abstract] {meta.abstract or meta.title}"

            content_record = Content(
                title=meta.title[:512],
                description=meta.abstract or result.raw_text[:500],
                content_type="document",
                canonical_url=(req.url or f"https://cyber-osint.local/doc/{filename}")[:2048],
                author=(", ".join(meta.authors) if meta.authors else "Document Repository")[:255],
                published_at=datetime.now(timezone.utc),
                discovered_at=datetime.now(timezone.utc),
                language="en",
                summary=meta.abstract,
                raw_content=body_to_save,
                content_hash=content_hash,
                quality_score=0.9,
                relevance_score=0.9,
                confidence_score=result.confidence or 0.9,
                status="parsed",
            )
            db.add(content_record)
            db.flush()
            content_id = content_record.id

            # Persist section chunks with dense vector embeddings
            for chunk in result.chunks:
                chunk_record = ContentChunk(
                    content_id=content_id,
                    chunk_index=chunk.chunk_index,
                    chunk_text=chunk.text,
                    chunk_tokens=len(chunk.text.split()),
                    embedding=chunk.embedding,
                )
                db.add(chunk_record)

            # Persist extracted entities
            seen_ent_ids = set()
            for ent_dict in result.extracted_entities:
                ename = ent_dict.get("name", "").strip()[:255]
                etype = ent_dict.get("entity_type", "technology")
                norm = ent_dict.get("normalized_name", ename.lower())
                if not ename:
                    continue

                entity_obj = db.query(Entity).filter(
                    Entity.entity_type == etype,
                    Entity.normalized_name == norm,
                ).first()
                if not entity_obj:
                    entity_obj = Entity(
                        name=ename,
                        entity_type=etype,
                        normalized_name=norm,
                        description=f"Extracted {etype}: {ename}",
                    )
                    db.add(entity_obj)
                    db.flush()

                if entity_obj.id not in seen_ent_ids:
                    seen_ent_ids.add(entity_obj.id)
                    db.add(
                        ContentEntity(
                            content_id=content_id,
                            entity_id=entity_obj.id,
                            confidence=ent_dict.get("confidence", 0.9),
                            context_snippet=ent_dict.get("context"),
                        )
                    )

            db.commit()
        except Exception as exc:
            db.rollback()
            logger.error("Failed to persist document to DB: %s", exc)

    return DocumentProcessResponse(
        metadata=meta_resp,
        raw_text_length=len(result.raw_text),
        retained_text=result.raw_text if meta.retention_mode == RetentionMode.FULL_TEXT else None,
        chunks_count=len(result.chunks),
        chunks=chunks_resp,
        extracted_entities=result.extracted_entities,
        taxonomy_tags=result.taxonomy_tags,
        primary_category=result.primary_category,
        subcategory=result.subcategory,
        confidence=result.confidence,
        content_id=content_id,
    )


@router.get(
    "",
    response_model=List[ContentResponse],
    status_code=status.HTTP_200_OK,
    summary="List Stored Intelligence Documents",
)
def list_documents_endpoint(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
) -> List[ContentResponse]:
    """Retrieve ingested documents, whitepapers, advisories, and research papers."""
    docs = (
        db.query(Content)
        .filter(Content.content_type.in_(["document", "paper", "whitepaper", "advisory"]))
        .order_by(Content.published_at.desc().nullslast())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return docs


@router.get(
    "/{content_id}/chunks",
    response_model=List[DocumentChunkResponse],
    status_code=status.HTTP_200_OK,
    summary="Get Semantic Chunks for a Document",
)
def get_document_chunks_endpoint(
    content_id: int,
    db: Session = Depends(get_db),
) -> List[DocumentChunkResponse]:
    """Retrieve all semantic section chunks for a given document."""
    content = db.query(Content).filter(Content.id == content_id).first()
    if not content:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with id {content_id} not found",
        )

    chunks = (
        db.query(ContentChunk)
        .filter(ContentChunk.content_id == content_id)
        .order_by(ContentChunk.chunk_index.asc())
        .all()
    )

    return [
        DocumentChunkResponse(
            chunk_index=c.chunk_index,
            heading=c.chunk_text.split("]")[0].strip("[") if c.chunk_text.startswith("[") else "Section",
            text=c.chunk_text,
            has_embedding=c.embedding is not None,
        )
        for c in chunks
    ]
