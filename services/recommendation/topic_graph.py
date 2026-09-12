"""
Semantic Topic Correlation Graph
Maps cybersecurity domains, threat intelligence areas, and technology stacks into related topic recommendations.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from services.recommendation.models import TopicRecommendation


# Canonical Topic Knowledge Map conforming to Section 31 specification
CANONICAL_TOPIC_CORRELATIONS: Dict[str, List[str]] = {
    # Canonical Example from Section 31:
    # User reads: Kubernetes Security
    # Recommend: Container Security, Docker Security, Cloud Security, Kubernetes Threat Detection, Runtime Security
    "Kubernetes Security": [
        "Container Security",
        "Docker Security",
        "Cloud Security",
        "Kubernetes Threat Detection",
        "Runtime Security",
    ],
    "Container Security": [
        "Kubernetes Security",
        "Docker Security",
        "Cloud Security",
        "Runtime Security",
        "Container Image Vulnerability Scanning",
    ],
    "Docker Security": [
        "Container Security",
        "Kubernetes Security",
        "Linux Hardening",
        "Runtime Security",
        "Daemon Hardening",
    ],
    "Cloud Security": [
        "Kubernetes Security",
        "Container Security",
        "IAM Security",
        "Cloud Posture & CSPM",
        "Serverless Security",
    ],
    "Kubernetes Threat Detection": [
        "Kubernetes Security",
        "Runtime Security",
        "eBPF Observability",
        "Falco Rules",
        "Audit Log Analysis",
    ],
    "Runtime Security": [
        "Container Security",
        "Kubernetes Security",
        "eBPF Monitoring",
        "Kernel Security",
        "Process Sandboxing",
    ],
    "Ransomware": [
        "Malware Analysis",
        "Initial Access Brokers",
        "Data Exfiltration",
        "Incident Response",
        "Threat Actor Profiling",
    ],
    "Malware Analysis": [
        "Reverse Engineering",
        "Memory Analysis",
        "Ransomware",
        "C2 Infrastructure",
        "Behavioral Sandboxing",
    ],
    "Zero-Day Vulnerabilities": [
        "Exploit Development",
        "Memory Safety",
        "CVE Intelligence",
        "Patch Management",
        "Kernel Security",
    ],
    "Network Security": [
        "Intrusion Detection",
        "Firewall Architecture",
        "Zero Trust",
        "Traffic Analysis",
        "DDoS Mitigation",
    ],
    "Application Security": [
        "API Security",
        "OWASP Top 10",
        "Software Supply Chain",
        "DevSecOps",
        "Static Analysis (SAST)",
    ],
    "Threat Hunting": [
        "MITRE ATT&CK",
        "Endpoint Detection & Response (EDR)",
        "SIEM Engineering",
        "Behavioral Anomaly Detection",
        "Threat Intelligence",
    ],
    "Identity & Access Management": [
        "Zero Trust",
        "Privilege Escalation",
        "Active Directory Security",
        "Kerberos Attacks",
        "MFA Security",
    ],
}


class TopicGraph:
    """
    Semantic Topic Correlation Graph.
    Computes topic expansions, nearest neighbor correlations, and contextual recommendations.
    """

    def __init__(self) -> None:
        self._graph: Dict[str, List[str]] = {k: list(v) for k, v in CANONICAL_TOPIC_CORRELATIONS.items()}
        # Ensure bi-directional relationships
        for topic, related in list(self._graph.items()):
            for rel in related:
                if rel not in self._graph:
                    self._graph[rel] = []
                if topic not in self._graph[rel]:
                    self._graph[rel].append(topic)

    def _normalize(self, topic: str) -> str:
        """Normalizes topic text for resilient lookups."""
        t = topic.strip().lower()
        t = re.sub(r"[_\-]+", " ", t)
        t = re.sub(r"\s+", " ", t)
        return t

    def get_canonical_match(self, query_topic: str) -> Optional[str]:
        """Finds the closest canonical topic matching query string."""
        clean_query = self._normalize(query_topic)
        if not clean_query:
            return None

        # 1. Exact canonical normalized match
        for canonical in self._graph:
            if self._normalize(canonical) == clean_query:
                return canonical

        # 2. Key aliases and shortcuts
        alias_map = {
            "k8s": "Kubernetes Security",
            "k8s security": "Kubernetes Security",
            "kubernetes": "Kubernetes Security",
            "docker": "Docker Security",
            "container": "Container Security",
            "containers": "Container Security",
            "cloud": "Cloud Security",
            "runtime": "Runtime Security",
            "ransomware": "Ransomware",
            "zeroday": "Zero-Day Vulnerabilities",
            "zero day": "Zero-Day Vulnerabilities",
            "0day": "Zero-Day Vulnerabilities",
            "cve": "Zero-Day Vulnerabilities",
            "malware": "Malware Analysis",
            "appsec": "Application Security",
            "hunting": "Threat Hunting",
            "iam": "Identity & Access Management",
        }
        if clean_query in alias_map:
            return alias_map[clean_query]

        # 3. Substring matching
        for canonical in self._graph:
            norm_can = self._normalize(canonical)
            if clean_query in norm_can or norm_can in clean_query:
                return canonical

        return None

    def get_related_topics(self, topic: str, limit: int = 5) -> List[TopicRecommendation]:
        """
        Retrieves recommended topics related to the given topic.
        Guarantees exact Section 31 output for 'Kubernetes Security':
        Container Security, Docker Security, Cloud Security, Kubernetes Threat Detection, Runtime Security.
        """
        matched_canonical = self.get_canonical_match(topic)
        results: List[TopicRecommendation] = []

        if matched_canonical and matched_canonical in self._graph:
            related_list = self._graph[matched_canonical]
            for i, rel in enumerate(related_list[:limit]):
                score = round(0.95 - (i * 0.05), 2)
                results.append(
                    TopicRecommendation(
                        topic=rel,
                        score=score,
                        reason=f"Correlated with {matched_canonical}",
                        related_from=matched_canonical,
                    )
                )
            return results

        # Fallback: if topic is unknown, discover via fuzzy keyword search
        clean = self._normalize(topic)
        words = set(clean.split())
        scored_candidates: List[Tuple[float, str]] = []

        for canonical in self._graph:
            c_words = set(self._normalize(canonical).split())
            overlap = len(words & c_words)
            if overlap > 0:
                scored_candidates.append((overlap / len(words | c_words), canonical))

        scored_candidates.sort(reverse=True, key=lambda x: x[0])
        for score, can in scored_candidates[:limit]:
            results.append(
                TopicRecommendation(
                    topic=can,
                    score=round(score, 2),
                    reason=f"Topic semantic affinity with {topic}",
                    related_from=topic,
                )
            )

        # Default fallback if no overlap at all
        if not results:
            defaults = [
                "Cloud Security",
                "Container Security",
                "Zero-Day Vulnerabilities",
                "Threat Hunting",
                "Runtime Security",
            ]
            for i, def_topic in enumerate(defaults[:limit]):
                results.append(
                    TopicRecommendation(
                        topic=def_topic,
                        score=round(0.70 - (i * 0.05), 2),
                        reason="Featured cybersecurity domain",
                        related_from=topic,
                    )
                )

        return results[:limit]

    def expand_topic_weights(self, topics: List[str]) -> Dict[str, float]:
        """
        Takes a list of topics (e.g. from user interests or viewed history)
        and expands them across the graph with decay weights.
        """
        weights: Dict[str, float] = {}
        for t in topics:
            can = self.get_canonical_match(t) or t
            weights[can] = max(weights.get(can, 0.0), 1.0)
            if can in self._graph:
                for rel in self._graph[can]:
                    weights[rel] = max(weights.get(rel, 0.0), 0.65)
        return weights


topic_graph = TopicGraph()
