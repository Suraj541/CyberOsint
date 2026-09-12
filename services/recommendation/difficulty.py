"""
Technical Difficulty Classifier and Alignment Scorer
Estimates the technical depth of intelligence items and computes alignment with user skill level.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

import re
from typing import Dict, List, Optional
from services.recommendation.models import DifficultyLevel

DIFFICULTY_RANKS: Dict[str, int] = {
    DifficultyLevel.BEGINNER.value: 0,
    DifficultyLevel.INTERMEDIATE.value: 1,
    DifficultyLevel.ADVANCED.value: 2,
    DifficultyLevel.EXPERT.value: 3,
}

BEGINNER_PATTERNS = [
    r"\b(introduction|intro|basics|primer|getting started|fundamentals|101|overview|guide for beginners)\b",
    r"\b(what is|understanding|explaining|summary|high-level|concepts)\b",
]

INTERMEDIATE_PATTERNS = [
    r"\b(configuration|hardening|best practices|detection|monitoring|mitigation|playbook)\b",
    r"\b(deployment|audit|firewall rules|yara|snort|suricata|sigma rules|sysmon)\b",
]

ADVANCED_PATTERNS = [
    r"\b(reverse engineering|disassembly|payload|shellcode|privilege escalation|evasion)\b",
    r"\b(exploit|cve-\d{4}-\d+|zero-day|0-day|buffer overflow|rce|injection|c2 infrastructure)\b",
    r"\b(cobalt strike|mimikatz|lateral movement|dll sideloading|api hooking)\b",
]

EXPERT_PATTERNS = [
    r"\b(kernel space|hypervisor escape|aslr bypass|rop chain|gadget|heap grooming)\b",
    r"\b(side-channel|spectre|meltdown|cryptanalysis|microarchitectural|use-after-free primitive)\b",
    r"\b(v8 exploit|sandbox escape|formal verification|firmware reversing)\b",
]


class DifficultyClassifier:
    """
    Classifies technical depth of content items into beginner, intermediate, advanced, expert.
    Computes distance-based alignment score against user preference.
    """

    def classify(
        self,
        title: str,
        content_type: str = "article",
        text_sample: str = "",
        severity: Optional[str] = None,
        cvss_score: Optional[float] = None,
    ) -> str:
        """Determines the content difficulty tier."""
        combined = f"{title} {text_sample}".lower()

        # Expert signals
        for pat in EXPERT_PATTERNS:
            if re.search(pat, combined):
                return DifficultyLevel.EXPERT.value

        # Advanced signals (High CVSS or complex exploit terminology)
        if cvss_score and cvss_score >= 9.0:
            return DifficultyLevel.ADVANCED.value

        for pat in ADVANCED_PATTERNS:
            if re.search(pat, combined):
                return DifficultyLevel.ADVANCED.value

        # Research papers are by default advanced
        if content_type in ["research", "paper"]:
            return DifficultyLevel.ADVANCED.value

        # Beginner signals
        for pat in BEGINNER_PATTERNS:
            if re.search(pat, combined):
                return DifficultyLevel.BEGINNER.value

        if content_type == "video" and any(k in combined for k in ["talk", "podcast", "keynote"]):
            return DifficultyLevel.BEGINNER.value

        # Intermediate signals
        for pat in INTERMEDIATE_PATTERNS:
            if re.search(pat, combined):
                return DifficultyLevel.INTERMEDIATE.value

        # Default fallback
        return DifficultyLevel.INTERMEDIATE.value

    def score_alignment(self, user_level: str, content_level: str) -> float:
        """
        Computes similarity score [0.0 - 1.0] between user preference and content difficulty.
        """
        u_rank = DIFFICULTY_RANKS.get(user_level.lower(), 1)
        c_rank = DIFFICULTY_RANKS.get(content_level.lower(), 1)
        dist = abs(u_rank - c_rank)

        if dist == 0:
            return 1.0
        elif dist == 1:
            return 0.70
        elif dist == 2:
            return 0.35
        else:
            return 0.10


difficulty_classifier = DifficultyClassifier()
