"""
Document Chunker Module
Splits threat intelligence documents, advisories, and articles into coherent,
overlapping text chunks preserving paragraph and sentence boundaries.
Conforms to IMPLEMENT.md Section 19.
"""

import re
from typing import List, Optional


class TextChunker:
    """
    Splits long text documents into semantically coherent chunks
    suitable for dense vector embedding generation.
    """

    def __init__(self, default_chunk_size: int = 500, default_overlap: int = 80):
        self.default_chunk_size = default_chunk_size
        self.default_overlap = default_overlap

    def chunk_text(
        self,
        text: str,
        chunk_size: Optional[int] = None,
        overlap: Optional[int] = None,
    ) -> List[str]:
        """
        Split text string into overlapping chunks respecting sentence or paragraph boundaries.
        """
        if not text:
            return []

        size = chunk_size or self.default_chunk_size
        ovlp = overlap or self.default_overlap
        clean_text = re.sub(r"\r\n?", "\n", text).strip()

        if len(clean_text) <= size:
            return [clean_text]

        # Break text into paragraphs or sentences
        paragraphs = [p.strip() for p in re.split(r"\n\s*\n", clean_text) if p.strip()]
        if not paragraphs:
            paragraphs = [clean_text]

        chunks: List[str] = []
        current_chunk = ""

        for para in paragraphs:
            # If paragraph itself is longer than chunk_size, split by sentences
            if len(para) > size:
                sentences = re.split(r"(?<=[.!?])\s+", para)
                for sentence in sentences:
                    if len(current_chunk) + len(sentence) + 1 <= size:
                        current_chunk = f"{current_chunk} {sentence}".strip() if current_chunk else sentence
                    else:
                        if current_chunk:
                            chunks.append(current_chunk)
                            # Retain overlap from end of current_chunk
                            overlap_text = current_chunk[-ovlp:].strip() if len(current_chunk) > ovlp else ""
                            current_chunk = f"{overlap_text} {sentence}".strip() if overlap_text else sentence
                        else:
                            # Sentence itself exceeds size, hard-wrap it
                            for i in range(0, len(sentence), size - ovlp):
                                sub = sentence[i : i + size].strip()
                                if sub:
                                    chunks.append(sub)
                            current_chunk = ""
            else:
                if len(current_chunk) + len(para) + 2 <= size:
                    current_chunk = f"{current_chunk}\n\n{para}".strip() if current_chunk else para
                else:
                    if current_chunk:
                        chunks.append(current_chunk)
                        overlap_text = current_chunk[-ovlp:].strip() if len(current_chunk) > ovlp else ""
                        current_chunk = f"{overlap_text}\n\n{para}".strip() if overlap_text else para
                    else:
                        current_chunk = para

        if current_chunk:
            chunks.append(current_chunk)

        # De-duplicate identical consecutive chunks if any
        deduped_chunks: List[str] = []
        for c in chunks:
            c_clean = c.strip()
            if c_clean and (not deduped_chunks or deduped_chunks[-1] != c_clean):
                deduped_chunks.append(c_clean)

        return deduped_chunks or [clean_text]

    def chunk_document(
        self,
        title: str,
        description: Optional[str] = None,
        summary: Optional[str] = None,
        body: Optional[str] = None,
        chunk_size: Optional[int] = None,
    ) -> List[str]:
        """
        Structure an entire threat intelligence document into sequential chunks,
        ensuring the title and overview are prioritized in the lead chunk.
        """
        size = chunk_size or self.default_chunk_size
        lead_elements = [title.strip()]
        if summary and summary.strip():
            lead_elements.append(summary.strip())
        elif description and description.strip():
            lead_elements.append(description.strip())

        lead_chunk = " — ".join(lead_elements)

        if not body or not body.strip():
            return [lead_chunk]

        body_clean = body.strip()
        body_chunks = self.chunk_text(body_clean, chunk_size=size)

        # If lead chunk is small, prepend it to the first body chunk
        if len(lead_chunk) + len(body_chunks[0]) + 2 <= size:
            combined_first = f"{lead_chunk}\n\n{body_chunks[0]}"
            return [combined_first] + body_chunks[1:]

        return [lead_chunk] + body_chunks


# Global chunker singleton
text_chunker = TextChunker()
