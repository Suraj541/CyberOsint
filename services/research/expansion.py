"""
Query Expansion Engine for AI Research Pipeline (Stage 2)
Expands user research questions with domain synonyms, acronyms, related entities,
and technical aliases to maximize retrieval precision across search, entity, and vector indexes.
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

import re
from typing import Dict, List, Set
from services.research.models import QueryExpansionResult

# Domain Expansion Synonyms & Technical Equivalences
DOMAIN_EXPANSION_MAP: Dict[str, List[str]] = {
    "kubernetes": ["k8s", "container", "kubelet", "api server", "etcd", "rbac", "pod", "cloud native"],
    "k8s": ["kubernetes", "container", "kubelet", "api server", "etcd", "cluster"],
    "container": ["docker", "containerd", "cgroups", "kubernetes", "image", "namespace"],
    "docker": ["container", "containerd", "daemon", "runc", "dockerfile"],
    "ransomware": ["extortion", "encryptor", "double extortion", "affiliate", "data exfiltration", "wiper"],
    "zero-day": ["zeroday", "0-day", "in-the-wild", "actively exploited", "unpatched"],
    "zeroday": ["zero-day", "0-day", "in the wild", "unpatched vulnerability"],
    "active directory": ["kerberos", "ntlm", "domain controller", "golden ticket", "dcsync", "ldap"],
    "kerberos": ["active directory", "golden ticket", "silver ticket", "as-rep", "roasting"],
    "vpn": ["gateway", "remote access", "perimeter", "ipsec", "ssl vpn", "firewall"],
    "pan-os": ["palo alto", "globalprotect", "cve-2024-3400", "firewall"],
    "fortios": ["fortinet", "fortigate", "ssl-vpn", "cve-2024-21762"],
    "cloud": ["aws", "azure", "gcp", "iam", "s3", "cloud security", "tenant"],
    "api": ["rest", "endpoint", "graphql", "tokens", "authentication", "authorization"],
    "phishing": ["spearphishing", "credential harvesting", "social engineering", "lure"],
    "supply chain": ["dependency", "repository", "package", "backdoor", "npm", "pypi", "xz utils"],
    "lockbit": ["lockbit 3.0", "lockbit black", "encryptor", "ransomware", "stealer"],
    "akira": ["akira ransomware", "megazord", "cisco vpn", "double extortion"],
}

COMMON_STOP_WORDS: Set[str] = {
    "what", "are", "the", "latest", "security", "developments", "involving", "with",
    "how", "does", "explain", "recent", "about", "tell", "me", "show", "findings",
    "overview", "summary", "report", "details", "critical", "update", "updates",
    "issue", "issues", "new", "and", "for", "from", "into", "over", "under", "is",
}


class QueryExpander:
    """Extracts concepts, detected entities, and expands query terms."""

    def expand_query(self, question: str) -> QueryExpansionResult:
        """
        Analyze question text and generate expanded query terms.
        """
        clean_text = question.strip()

        # 1. Detect explicit technical entities (CVEs, MITRE techniques, hashes)
        cves = sorted(list(set(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", clean_text, re.I))))
        techniques = sorted(list(set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", clean_text))))
        detected_entities = [c.upper() for c in cves] + techniques

        # 2. Extract core keywords
        words = re.findall(r"\b[a-zA-Z0-9_\-\.]+\b", clean_text.lower())
        meaningful_words = [w for w in words if w not in COMMON_STOP_WORDS and len(w) > 2]

        expanded_terms_set: Set[str] = set()

        # Check multi-word phrase keys first
        lower_q = clean_text.lower()
        for phrase, syns in DOMAIN_EXPANSION_MAP.items():
            if phrase in lower_q:
                expanded_terms_set.update(syns)

        # Check individual words
        for w in meaningful_words:
            if w in DOMAIN_EXPANSION_MAP:
                expanded_terms_set.update(DOMAIN_EXPANSION_MAP[w])

        # Always include the core meaningful words
        for w in meaningful_words:
            expanded_terms_set.add(w)

        # Ensure detected entities are included
        for ent in detected_entities:
            expanded_terms_set.add(ent.lower())

        expanded_terms = sorted(list(expanded_terms_set))

        # Build concise search keyword string prioritizing core words and top 4 synonyms
        top_terms = meaningful_words[:4] + [t for t in expanded_terms if t not in meaningful_words][:4]
        search_keywords = " ".join(top_terms) if top_terms else clean_text

        return QueryExpansionResult(
            original_query=question,
            expanded_terms=expanded_terms,
            detected_entities=detected_entities,
            search_keywords=search_keywords,
        )


# Global query expander singleton
query_expander = QueryExpander()
