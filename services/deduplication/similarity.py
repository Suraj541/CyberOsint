"""
Text & Structural Similarity Scoring Module
Computes title similarity, description similarity, entity overlap, and n-gram semantic similarity.
Conforms strictly to IMPLEMENT.md Section 17 specifications.
"""

from collections import Counter
import difflib
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple


def _normalize_tokens(text: str) -> List[str]:
    """Tokenize and filter text into lowercase alphanumeric words."""
    if not text:
        return []
    clean = re.sub(r"[^\w\s]", " ", text.lower())
    return [w for w in clean.split() if len(w) > 1 or w.isdigit()]


def _jaccard_similarity(set_a: Set[Any], set_b: Set[Any]) -> float:
    """Compute standard Jaccard intersection over union."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union > 0 else 0.0


def calculate_title_similarity(title1: str, title2: str) -> float:
    """
    Compute title similarity combining token sort comparison and sequence matching.
    Robust to word reordering, punctuation differences, and minor edits.
    """
    if not title1 or not title2:
        return 0.0

    t1_clean = " ".join(_normalize_tokens(title1))
    t2_clean = " ".join(_normalize_tokens(title2))

    if not t1_clean or not t2_clean:
        return 0.0
    if t1_clean == t2_clean:
        return 1.0

    # 1. SequenceMatcher character ratio
    seq_ratio = difflib.SequenceMatcher(None, t1_clean, t2_clean).ratio()

    # 2. Token Sort Ratio (reorders tokens alphabetically to handle headline reordering)
    tokens1 = sorted(_normalize_tokens(t1_clean))
    tokens2 = sorted(_normalize_tokens(t2_clean))
    sorted_str1 = " ".join(tokens1)
    sorted_str2 = " ".join(tokens2)
    token_sort_ratio = difflib.SequenceMatcher(None, sorted_str1, sorted_str2).ratio()

    # 3. Token Jaccard similarity
    token_jaccard = _jaccard_similarity(set(tokens1), set(tokens2))

    # Check for conflicting numerical identifiers (e.g. CVE IDs, sequence/part numbers)
    nums1 = set(re.findall(r"\b\d+\b", title1))
    nums2 = set(re.findall(r"\b\d+\b", title2))
    num_penalty = 0.5 if (nums1 and nums2 and nums1 != nums2) else 1.0

    # Take maximum of sequence alignment and token sort representation
    base_score = max(seq_ratio, token_sort_ratio, token_jaccard * 0.95)
    return base_score * num_penalty


def calculate_description_similarity(desc1: Optional[str], desc2: Optional[str]) -> float:
    """Compute description similarity using 2-gram and word token overlap."""
    if not desc1 or not desc2:
        return 0.0

    tokens1 = _normalize_tokens(desc1)
    tokens2 = _normalize_tokens(desc2)
    if not tokens1 or not tokens2:
        return 0.0

    # Word unigrams
    unigram_jaccard = _jaccard_similarity(set(tokens1), set(tokens2))

    # Word bigrams
    bigrams1 = {f"{tokens1[i]} {tokens1[i+1]}" for i in range(len(tokens1) - 1)}
    bigrams2 = {f"{tokens2[i]} {tokens2[i+1]}" for i in range(len(tokens2) - 1)}
    bigram_jaccard = _jaccard_similarity(bigrams1, bigrams2) if bigrams1 and bigrams2 else unigram_jaccard

    return 0.6 * bigram_jaccard + 0.4 * unigram_jaccard


def calculate_entity_overlap(
    entities1: Optional[List[Any]],
    entities2: Optional[List[Any]],
) -> float:
    """
    Compute entity overlap Jaccard similarity.
    Entities can be ExtractedEntity objects, dictionaries, or (type, name) tuples.
    """
    if not entities1 or not entities2:
        return 0.0

    def _normalize_entity(e: Any) -> Tuple[str, str]:
        if hasattr(e, "entity_type") and hasattr(e, "normalized_name"):
            return (str(e.entity_type).lower(), str(e.normalized_name).lower())
        if isinstance(e, dict):
            t = str(e.get("type") or e.get("entity_type") or "generic").lower()
            n = str(e.get("name") or e.get("normalized_name") or "").lower()
            return (t, n)
        if isinstance(e, tuple) and len(e) >= 2:
            return (str(e[0]).lower(), str(e[1]).lower())
        return ("generic", str(e).lower())

    set1 = {_normalize_entity(e) for e in entities1 if e}
    set2 = {_normalize_entity(e) for e in entities2 if e}

    return _jaccard_similarity(set1, set2)


def calculate_semantic_similarity(text1: Optional[str], text2: Optional[str]) -> float:
    """
    Compute fast deterministic TF-IDF cosine similarity between two texts.
    No heavy neural dependencies required.
    """
    if not text1 or not text2:
        return 0.0

    tokens1 = _normalize_tokens(text1)
    tokens2 = _normalize_tokens(text2)
    if not tokens1 or not tokens2:
        return 0.0

    # Term frequencies
    tf1 = Counter(tokens1)
    tf2 = Counter(tokens2)

    # Vocabulary
    vocab = set(tf1.keys()) | set(tf2.keys())
    if not vocab:
        return 0.0

    # Cosine similarity
    dot = sum(tf1.get(w, 0) * tf2.get(w, 0) for w in vocab)
    norm1 = math.sqrt(sum(v * v for v in tf1.values()))
    norm2 = math.sqrt(sum(v * v for v in tf2.values()))

    if norm1 == 0 or norm2 == 0:
        return 0.0
    return min(1.0, dot / (norm1 * norm2))


def calculate_multi_signal_similarity(
    title1: str,
    title2: str,
    desc1: Optional[str] = None,
    desc2: Optional[str] = None,
    entities1: Optional[List[Any]] = None,
    entities2: Optional[List[Any]] = None,
    body1: Optional[str] = None,
    body2: Optional[str] = None,
) -> Dict[str, float]:
    """
    Evaluate all 4 similarity dimensions and compute adaptive composite score.
    Returns dictionary with individual scores and final composite_score.
    """
    title_sim = calculate_title_similarity(title1, title2)
    desc_sim = calculate_description_similarity(desc1, desc2)
    entity_sim = calculate_entity_overlap(entities1, entities2)

    # Combine available text for semantic vector similarity
    combined1 = f"{title1} {desc1 or ''} {body1 or ''}"
    combined2 = f"{title2} {desc2 or ''} {body2 or ''}"
    semantic_sim = calculate_semantic_similarity(combined1, combined2)

    # Adaptive weights based on available signals
    weights = {"title": 0.40, "desc": 0.25, "entity": 0.25, "semantic": 0.10}

    # If no entities in either, redistribute entity weight to title and desc
    if not entities1 and not entities2:
        weights = {"title": 0.55, "desc": 0.30, "entity": 0.0, "semantic": 0.15}

    # If descriptions are missing, redistribute to title
    if not desc1 and not desc2:
        weights["title"] += weights["desc"]
        weights["desc"] = 0.0

    composite = (
        weights["title"] * title_sim
        + weights["desc"] * desc_sim
        + weights["entity"] * entity_sim
        + weights["semantic"] * semantic_sim
    )

    return {
        "title_similarity": round(title_sim, 4),
        "description_similarity": round(desc_sim, 4),
        "entity_overlap": round(entity_sim, 4),
        "semantic_similarity": round(semantic_sim, 4),
        "composite_score": round(composite, 4),
    }
