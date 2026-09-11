"""
Vector Similarity Module
Computes mathematical cosine similarity between dense embedding vectors.
Conforms to IMPLEMENT.md Section 19.
"""

import math
from typing import List


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """
    Calculate cosine similarity between two float vectors.
    Returns score between -1.0 and 1.0 (typically 0.0 to 1.0 for normalized text vectors).
    """
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0

    dot = sum(a * b for a, b in zip(v1, v2))
    norm1 = math.sqrt(sum(a * a for a in v1))
    norm2 = math.sqrt(sum(b * b for b in v2))

    if norm1 == 0.0 or norm2 == 0.0:
        return 0.0

    sim = dot / (norm1 * norm2)
    # Clamp for floating-point inaccuracies
    return max(-1.0, min(1.0, round(sim, 4)))
