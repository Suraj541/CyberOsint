"""
Evidence Collector for AI Research Pipeline (Stage 7)
Extracts verbatim, high-salience factual snippets from top-ranked source texts
and structures them into numbered citation items.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

import html
import re
from typing import List, Set
from services.research.models import EvidenceItem
from services.research.retriever import CandidateContent


class EvidenceCollector:
    """Collects and deduplicates high-salience factual evidence items."""

    def _clean_snippet(self, raw_text: str) -> str:
        """Strip HTML tags and normalize whitespace."""
        text = html.unescape(raw_text)
        text = re.sub(r"<[^>]+>", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _extract_most_relevant_sentences(
        self, text: str, query_terms: List[str], max_chars: int = 400
    ) -> str:
        """Extract the most relevant sentences matching the query terms."""
        cleaned = self._clean_snippet(text)
        sentences = re.split(r"(?<=[.!?])\s+", cleaned)

        scored_sentences = []
        term_set = {t.lower() for t in query_terms if len(t) > 2}

        for s in sentences:
            s_clean = s.strip()
            if len(s_clean) < 20:
                continue
            s_lower = s_clean.lower()
            score = sum(1 for t in term_set if t in s_lower)
            if re.search(r"CVE-\d{4}-\d{4,7}", s_clean, re.I):
                score += 3
            if re.search(r"\bT1\d{3}\b", s_clean):
                score += 2
            scored_sentences.append((score, s_clean))

        scored_sentences.sort(key=lambda x: x[0], reverse=True)
        top_sentences = [s for _, s in scored_sentences[:3]]

        if top_sentences:
            combined = " ".join(top_sentences)
            return combined[:max_chars] + "..." if len(combined) > max_chars else combined

        # Fallback to lead text
        return cleaned[:max_chars] + "..." if len(cleaned) > max_chars else cleaned

    def collect_evidence(
        self,
        ranked_candidates: List[CandidateContent],
        query_terms: List[str],
        max_evidence: int = 8,
    ) -> List[EvidenceItem]:
        """
        Produce ordered, numbered evidence items [1], [2], ...
        """
        evidence_items: List[EvidenceItem] = []

        for idx, cand in enumerate(ranked_candidates[:max_evidence], start=1):
            content = cand.content
            source_name = content.source.name if content.source else "Security Advisory Repository"

            # Prefer matched semantic chunk if available, otherwise raw content or description
            source_text = ""
            if cand.matched_chunks:
                source_text = cand.matched_chunks[0]
            elif content.raw_content and len(content.raw_content) > 100:
                source_text = content.raw_content
            elif content.description:
                source_text = content.description
            elif content.summary:
                source_text = content.summary
            else:
                source_text = content.title

            snippet = self._extract_most_relevant_sentences(source_text, query_terms)

            # Discover referenced CVEs and techniques in snippet
            cves = sorted(list(set(re.findall(r"CVE-\d{4}-\d{4,7}", snippet, re.I))))
            techniques = sorted(list(set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", snippet))))
            all_entities = sorted(list(cand.matched_entities | set(cves) | set(techniques)))

            published_str = (
                content.published_at.isoformat()
                if content.published_at
                else (content.discovered_at.isoformat() if content.discovered_at else None)
            )

            evidence_items.append(
                EvidenceItem(
                    citation_id=idx,
                    content_id=content.id,
                    title=content.title,
                    source_name=source_name,
                    canonical_url=content.canonical_url,
                    published_at=published_str,
                    quality_tier=cand.quality_tier,
                    quality_score=round(cand.quality_score, 2),
                    relevance_score=round(cand.final_rank_score, 2),
                    snippet=snippet,
                    matched_entities=all_entities,
                )
            )

        return evidence_items


# Global evidence collector singleton
evidence_collector = EvidenceCollector()
