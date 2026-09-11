"""
Deterministic Cybersecurity Entity Extraction Engine
Extracts 11 structured entity types (CVE, CWE, Vendor, Product, Malware, Threat Actor,
Technology, Domain, IP, Hash, ATT&CK Technique) using regular expressions, defanged IOC parsing,
and curated gazetteers.
Conforms strictly to IMPLEMENT.md Section 16 specifications.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from packages.extractor.gazetteers import (
    MALWARE_GAZETTEER,
    PRODUCT_GAZETTEER,
    TECHNOLOGY_GAZETTEER,
    THREAT_ACTOR_GAZETTEER,
    VENDOR_GAZETTEER,
    GazetteerEntry,
)
from packages.extractor.models import ExtractedEntity
from packages.extractor.patterns import (
    EXCLUDED_DOMAINS,
    RE_CVE,
    RE_CWE,
    RE_DEFANGED_DOMAIN,
    RE_DEFANGED_URL,
    RE_IPV4,
    RE_IPV4_DEFANGED,
    RE_IPV4_STANDARD,
    RE_MD5,
    RE_MITRE_TECHNIQUE,
    RE_SHA1,
    RE_SHA256,
    is_valid_public_ip,
    normalize_defanged,
)

logger = logging.getLogger("cyber_osint.packages.extractor")


def _generate_snippet(text: str, start: int, end: int, window: int = 50) -> str:
    """Generate a readable context snippet window surrounding a match."""
    snippet_start = max(0, start - window)
    snippet_end = min(len(text), end + window)
    raw_snippet = text[snippet_start:snippet_end].replace("\n", " ").strip()

    prefix = "..." if snippet_start > 0 else ""
    suffix = "..." if snippet_end < len(text) else ""
    return f"{prefix}{raw_snippet}{suffix}"


class DeterministicEntityExtractor:
    """
    High-performance deterministic entity extractor for unstructured cybersecurity text.
    """

    def __init__(self):
        # Pre-compile gazetteer keyword patterns
        self._malware_patterns = self._build_gazetteer_patterns(MALWARE_GAZETTEER)
        self._actor_patterns = self._build_gazetteer_patterns(THREAT_ACTOR_GAZETTEER)
        self._vendor_patterns = self._build_gazetteer_patterns(VENDOR_GAZETTEER)
        self._product_patterns = self._build_gazetteer_patterns(PRODUCT_GAZETTEER)
        self._tech_patterns = self._build_gazetteer_patterns(TECHNOLOGY_GAZETTEER)

    def _build_gazetteer_patterns(
        self, gazetteer: Dict[str, GazetteerEntry]
    ) -> List[Tuple[re.Pattern, GazetteerEntry]]:
        patterns = []
        for name, entry in gazetteer.items():
            terms = [name] + entry.aliases
            # Sort terms longest first to avoid partial prefix shadowing
            terms.sort(key=len, reverse=True)
            escaped_terms = [re.escape(t) for t in terms]
            regex_str = r"\b(" + "|".join(escaped_terms) + r")\b"
            pattern = re.compile(regex_str, re.IGNORECASE)
            patterns.append((pattern, entry))
        return patterns

    def extract(
        self,
        text: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[ExtractedEntity]:
        """
        Extract all deterministic entities from text.
        Returns deduplicated list of ExtractedEntity objects.
        """
        if not text:
            return []

        entities: List[ExtractedEntity] = []

        # -------------------------------------------------------------
        # 1. Regex Extraction: Structured Identifiers
        # -------------------------------------------------------------
        # 1a. CVE
        for m in RE_CVE.finditer(text):
            val = m.group(1).upper()
            entities.append(
                ExtractedEntity(
                    name=val,
                    entity_type="cve",
                    normalized_name=val,
                    confidence=0.9,
                    extraction_method="regex",
                    context_snippet=_generate_snippet(text, m.start(), m.end()),
                    metadata={"pattern": "cve_standard"},
                )
            )

        # 1b. CWE
        for m in RE_CWE.finditer(text):
            val = m.group(1).upper()
            entities.append(
                ExtractedEntity(
                    name=val,
                    entity_type="cwe",
                    normalized_name=val,
                    confidence=0.9,
                    extraction_method="regex",
                    context_snippet=_generate_snippet(text, m.start(), m.end()),
                    metadata={"pattern": "cwe_standard"},
                )
            )

        # 1c. MITRE ATT&CK Technique
        for m in RE_MITRE_TECHNIQUE.finditer(text):
            val = m.group(1).upper()
            entities.append(
                ExtractedEntity(
                    name=val,
                    entity_type="mitre_technique",
                    normalized_name=val,
                    confidence=0.9,
                    extraction_method="regex",
                    context_snippet=_generate_snippet(text, m.start(), m.end()),
                    metadata={"pattern": "mitre_technique"},
                )
            )

        # 1d. Cryptographic Hashes (SHA256, SHA1, MD5)
        seen_hash_spans: Set[Tuple[int, int]] = set()

        for m in RE_SHA256.finditer(text):
            val = m.group(1).lower()
            seen_hash_spans.add((m.start(), m.end()))
            entities.append(
                ExtractedEntity(
                    name=val,
                    entity_type="hash",
                    normalized_name=val,
                    confidence=1.0,
                    extraction_method="regex",
                    context_snippet=_generate_snippet(text, m.start(), m.end()),
                    metadata={"hash_type": "sha256"},
                )
            )

        for m in RE_SHA1.finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in seen_hash_spans):
                continue
            val = m.group(1).lower()
            seen_hash_spans.add((m.start(), m.end()))
            entities.append(
                ExtractedEntity(
                    name=val,
                    entity_type="hash",
                    normalized_name=val,
                    confidence=0.98,
                    extraction_method="regex",
                    context_snippet=_generate_snippet(text, m.start(), m.end()),
                    metadata={"hash_type": "sha1"},
                )
            )

        for m in RE_MD5.finditer(text):
            if any(s <= m.start() and m.end() <= e for s, e in seen_hash_spans):
                continue
            val = m.group(1).lower()
            # Basic sanity check: avoid pure numeric or repeated character matches
            if len(set(val)) > 3 and not val.isdigit():
                entities.append(
                    ExtractedEntity(
                        name=val,
                        entity_type="hash",
                        normalized_name=val,
                        confidence=0.95,
                        extraction_method="regex",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"hash_type": "md5"},
                    )
                )

        # 1e. IPv4 Addresses (standard and defanged)
        for m in RE_IPV4.finditer(text):
            raw_ip = m.group(1)
            clean_ip = normalize_defanged(raw_ip)
            if is_valid_public_ip(clean_ip):
                is_defanged = raw_ip != clean_ip
                entities.append(
                    ExtractedEntity(
                        name=clean_ip,
                        entity_type="ip",
                        normalized_name=clean_ip,
                        confidence=0.98 if is_defanged else 0.95,
                        extraction_method="defanged" if is_defanged else "regex",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"defanged": is_defanged, "ip_version": 4},
                    )
                )

        # 1f. Domains (Defanged domain syntax e.g. evil[.]com)
        for m in RE_DEFANGED_DOMAIN.finditer(text):
            raw_dom = m.group(1)
            clean_dom = normalize_defanged(raw_dom).lower()
            if clean_dom not in EXCLUDED_DOMAINS and len(clean_dom) > 4:
                entities.append(
                    ExtractedEntity(
                        name=clean_dom,
                        entity_type="domain",
                        normalized_name=clean_dom,
                        confidence=0.95,
                        extraction_method="defanged",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"defanged": True},
                    )
                )

        # -------------------------------------------------------------
        # 2. Gazetteer Dictionary Extraction
        # -------------------------------------------------------------
        # 2a. Malware
        for pattern, entry in self._malware_patterns:
            for m in pattern.finditer(text):
                entities.append(
                    ExtractedEntity(
                        name=entry.name,
                        entity_type="malware",
                        normalized_name=entry.normalized_name,
                        confidence=0.95,
                        extraction_method="dictionary",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"category": entry.category, "description": entry.description},
                    )
                )

        # 2b. Threat Actors
        for pattern, entry in self._actor_patterns:
            for m in pattern.finditer(text):
                entities.append(
                    ExtractedEntity(
                        name=entry.name,
                        entity_type="threat_actor",
                        normalized_name=entry.normalized_name,
                        confidence=0.95,
                        extraction_method="dictionary",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"category": entry.category, "description": entry.description},
                    )
                )

        # 2c. Vendors
        for pattern, entry in self._vendor_patterns:
            for m in pattern.finditer(text):
                entities.append(
                    ExtractedEntity(
                        name=entry.name,
                        entity_type="vendor",
                        normalized_name=entry.normalized_name,
                        confidence=0.92,
                        extraction_method="dictionary",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"category": entry.category, "description": entry.description},
                    )
                )

        # 2d. Products
        for pattern, entry in self._product_patterns:
            for m in pattern.finditer(text):
                entities.append(
                    ExtractedEntity(
                        name=entry.name,
                        entity_type="product",
                        normalized_name=entry.normalized_name,
                        confidence=0.92,
                        extraction_method="dictionary",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"category": entry.category, "description": entry.description},
                    )
                )

        # 2e. Technologies
        for pattern, entry in self._tech_patterns:
            for m in pattern.finditer(text):
                entities.append(
                    ExtractedEntity(
                        name=entry.name,
                        entity_type="technology",
                        normalized_name=entry.normalized_name,
                        confidence=0.90,
                        extraction_method="dictionary",
                        context_snippet=_generate_snippet(text, m.start(), m.end()),
                        metadata={"category": entry.category, "description": entry.description},
                    )
                )

        # Deduplicate entities preserving highest confidence and best snippet
        return self._deduplicate_entities(entities)

    def extract_from_content(
        self,
        title: str,
        description: Optional[str] = None,
        body: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> List[ExtractedEntity]:
        """
        Extract all entities across structured content fields with metadata enrichment.
        """
        combined_text = f"{title or ''}\n{description or ''}\n{body or ''}"
        extracted = self.extract(combined_text, metadata=metadata)

        # Ingest pre-existing structured entities from metadata (e.g. from CVEConnector or GitHubConnector)
        if metadata and isinstance(metadata.get("entities"), list):
            for raw_ent in metadata["entities"]:
                if isinstance(raw_ent, dict) and raw_ent.get("name") and raw_ent.get("type"):
                    name = str(raw_ent["name"]).strip()
                    ent_type = str(raw_ent["type"]).strip().lower()
                    norm_name = name.upper() if ent_type in ("cve", "cwe", "mitre_technique") else name.lower()
                    ent_meta = dict(raw_ent.get("metadata") or {})
                    if raw_ent.get("description") and "description" not in ent_meta:
                        ent_meta["description"] = raw_ent["description"]
                    extracted.append(
                        ExtractedEntity(
                            name=name,
                            entity_type=ent_type,
                            normalized_name=norm_name,
                            confidence=1.0,
                            extraction_method="structured",
                            context_snippet=raw_ent.get("description") or f"Direct connector entity {name}",
                            metadata=ent_meta,
                        )
                    )

        return self._deduplicate_entities(extracted)

    def _deduplicate_entities(self, entities: List[ExtractedEntity]) -> List[ExtractedEntity]:
        """Merge identical entities, keeping the one with higher confidence."""
        seen: Dict[Tuple[str, str], ExtractedEntity] = {}
        for ent in entities:
            key = (ent.entity_type, ent.normalized_name)
            if key not in seen or ent.confidence > seen[key].confidence:
                seen[key] = ent
        return list(seen.values())


# Global singleton instance
entity_extractor = DeterministicEntityExtractor()
