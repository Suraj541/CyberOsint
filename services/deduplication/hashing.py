"""
Content Hashing & Fingerprinting Module
Generates cryptographic SHA-256 fingerprints and 64-bit SimHash locality-sensitive
fingerprints for fast structural similarity detection.
Conforms strictly to IMPLEMENT.md Section 6, 9, and 17 specifications.
"""

import hashlib
import re
from typing import List, Optional

from services.deduplication.url import normalize_url


def normalize_title_text(title: str) -> str:
    """Clean and normalize title string for deterministic comparison."""
    if not title:
        return ""
    clean = re.sub(r"\s+", " ", title).strip()
    return clean.lower()


def compute_content_hash(
    url: str,
    title: str,
    raw_content: Optional[str] = None,
) -> str:
    """
    Compute deterministic SHA-256 fingerprint for deduplication.
    Conforms to the primary platform content_hash contract.
    """
    clean_url = normalize_url(url)
    clean_title = normalize_title_text(title)

    if clean_url and not clean_url.startswith("urn:"):
        payload = f"{clean_url}|{clean_title}"
    else:
        snippet = (raw_content or "")[:512].strip().lower()
        payload = f"{clean_title}|{snippet}"

    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _tokenize_shingles(text: str, n: int = 2) -> List[str]:
    """Extract word unigrams and bigram shingles from text."""
    clean = re.sub(r"[^\w\s]", " ", text.lower())
    words = [w for w in clean.split() if len(w) > 1]
    if not words:
        return [text.lower().strip()] if text.strip() else []
    bigrams = [f"{words[i]} {words[i+1]}" for i in range(len(words) - 1)]
    return words + bigrams


def compute_simhash(text: str, hash_bits: int = 64) -> int:
    """
    Compute a 64-bit SimHash fingerprint for text.
    Similar texts yield small Hamming distance.
    """
    if not text:
        return 0

    shingles = _tokenize_shingles(text)
    if not shingles:
        return 0

    v = [0] * hash_bits
    for shingle in shingles:
        # MD5 to get 128 bits, take low 64 bits
        shingle_hash = int(hashlib.md5(shingle.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(hash_bits):
            bit = (shingle_hash >> i) & 1
            v[i] += 1 if bit else -1

    fingerprint = 0
    for i in range(hash_bits):
        if v[i] > 0:
            fingerprint |= 1 << i

    return fingerprint


def simhash_hamming_distance(h1: int, h2: int) -> int:
    """Compute Hamming distance (differing bits) between two SimHash integers."""
    return bin(h1 ^ h2).count("1")


def simhash_similarity(h1: int, h2: int, hash_bits: int = 64) -> float:
    """Compute normalized similarity score (0.0 to 1.0) from two SimHash integers."""
    if h1 == 0 and h2 == 0:
        return 1.0
    if h1 == 0 or h2 == 0:
        return 0.0
    dist = simhash_hamming_distance(h1, h2)
    return max(0.0, 1.0 - (dist / hash_bits))
