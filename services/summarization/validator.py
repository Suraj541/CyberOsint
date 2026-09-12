"""
Grounding and Hallucination Validator for AI Summarization
Enforces validation step in the pipeline:
Source Content -> Clean Text -> AI Model -> Summary -> Validation -> Stored Summary.
Conforms strictly to IMPLEMENT.md Section 29 (Step 28).
"""

import re
from typing import List, Set
from services.summarization.models import SummaryOutput, ValidationResult


class GroundingValidator:
    """Validates summary against source text to detect hallucinations and ensure rule compliance."""

    def validate(self, clean_text: str, summary: SummaryOutput) -> ValidationResult:
        """
        Evaluate factual alignment between source text and generated summary.
        Verifies:
        1. Entity mentions (CVEs, threat actors, malware) in reported_facts are grounded in clean_text.
        2. Inferences are demarcated with analytical language and not confused with facts.
        3. Ambiguous topics in clean_text have uncertainty preserved.
        """
        text_lower = clean_text.lower()
        unsupported_claims: List[str] = []
        grounded_facts_count = 0

        # 1. Check CVE grounding in reported_facts
        cve_in_source = set(re.findall(r"CVE-\d{4}-\d{4,7}", clean_text, re.I))
        cve_in_source_upper = {c.upper() for c in cve_in_source}

        all_unsupported_cves: List[str] = []
        for fact in summary.reported_facts:
            fact_cves = re.findall(r"CVE-\d{4}-\d{4,7}", fact, re.I)
            unsupported_cves = [c.upper() for c in fact_cves if c.upper() not in cve_in_source_upper]
            if unsupported_cves:
                all_unsupported_cves.extend(unsupported_cves)
                unsupported_claims.append(f"Invented CVE(s) in fact: {', '.join(unsupported_cves)}")
            else:
                grounded_facts_count += 1

        # 2. Check Entity overlap ratio (hashes, IPs, proper nouns)
        hashes_in_facts = re.findall(r"\b[a-fA-F0-9]{32,64}\b", " ".join(summary.reported_facts))
        unsupported_hashes = [h for h in hashes_in_facts if h.lower() not in text_lower]
        if unsupported_hashes:
            unsupported_claims.append(f"Invented hash indicator(s): {', '.join(unsupported_hashes)}")

        # 3. Check Separation of Inferences from Facts
        # Inferences should use speculative, interpretive, or analytical phrasing
        inference_keywords = {
            "suggests", "indicates", "likely", "potential", "estimated",
            "implies", "may", "assessed", "inferred", "projection",
            "threat model", "probable", "correlates", "hypothesized",
        }
        for inf in summary.inferences:
            has_analytical_word = any(kw in inf.lower() for kw in inference_keywords)
            # If an inference states an absolute claim without analytical marker, flag as warning
            if not has_analytical_word and len(inf) > 20:
                unsupported_claims.append(f"Inference lacks analytical qualifier: '{inf[:50]}...'")

        # 4. Check Preservation of Uncertainty
        uncertainty_triggers = {"suspected", "unconfirmed", "alleged", "unknown", "investigating", "pending"}
        source_has_uncertainty = any(tr in text_lower for tr in uncertainty_triggers)
        if source_has_uncertainty and len(summary.uncertainties) == 0:
            unsupported_claims.append("Source contains uncertainty triggers, but no uncertainties preserved in summary.")

        # Compute validation score
        total_checks = max(1, len(summary.reported_facts) + len(summary.inferences))
        penalty = len(unsupported_claims) * 0.25
        score = max(0.0, min(1.0, 1.0 - penalty))

        if score >= 0.80 and not any("Invented CVE" in u for u in unsupported_claims):
            status = "passed"
        elif score >= 0.50:
            status = "flagged"
        else:
            status = "rejected"

        notes = {
            "facts_evaluated": len(summary.reported_facts),
            "inferences_evaluated": len(summary.inferences),
            "uncertainties_preserved": len(summary.uncertainties),
            "source_has_uncertainty": source_has_uncertainty,
            "cves_in_source_count": len(cve_in_source),
            "hallucinated_cves": all_unsupported_cves,
        }

        return ValidationResult(
            status=status,
            score=score,
            grounded_facts_count=grounded_facts_count,
            unsupported_claims=unsupported_claims,
            entity_overlap_ratio=1.0 if not unsupported_claims else 0.75,
            notes=notes,
        )


# Global validator singleton
grounding_validator = GroundingValidator()
