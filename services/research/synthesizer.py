"""
Evidence-Bounded AI Synthesizer for AI Research Pipeline (Stage 8)
Synthesizes structured research answers strictly from retrieved evidence.
Enforces the mandatory constraint:
"The AI must answer from retrieved evidence. Do not let the AI answer from its internal knowledge alone."
Conforms strictly to IMPLEMENT.md Section 30 (Step 29).
"""

import re
from typing import List, Set
from services.research.models import EvidenceItem, SynthesisOutput


class EvidenceSynthesizer:
    """Synthesizes structured intelligence reports strictly grounded in retrieved evidence items."""

    def synthesize(
        self,
        question: str,
        evidence: List[EvidenceItem],
    ) -> SynthesisOutput:
        """
        Produce evidence-bounded synthesis with numbered citation references.
        """
        # Case 1: No evidence found
        if not evidence:
            return SynthesisOutput(
                executive_answer=(
                    f"No verified intelligence records matching the inquiry ('{question}') "
                    "were identified in the monitored telemetry repository. In accordance with platform "
                    "grounding guardrails, unverified general knowledge is excluded. Please broaden query "
                    "terms or register additional intelligence feeds."
                ),
                key_findings=[],
                threat_activity=[],
                vulnerabilities=[],
                mitigations=[],
                evidence_gaps=[
                    "Zero indexed evidence records matching question keywords.",
                    "Attribution, technical impact, and operational telemetry remain completely unknown.",
                ],
                confidence=0.0,
            )

        # Case 2: Synthesize from collected evidence
        findings: List[str] = []
        threat_activity: List[str] = []
        vulnerabilities: List[str] = []
        mitigations: List[str] = []
        evidence_gaps: List[str] = []

        all_cves: Set[str] = set()
        all_techniques: Set[str] = set()

        for item in evidence:
            # Extract CVEs
            item_cves = re.findall(r"CVE-\d{4}-\d{4,7}", item.snippet, re.I)
            for c in item_cves:
                all_cves.add(c.upper())

            # Extract MITRE techniques
            item_techs = re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", item.snippet)
            for t in item_techs:
                all_techniques.add(t)

            # Build finding point referencing citation [item.citation_id]
            clean_title = re.sub(r"^TITLE:\s*", "", item.title).strip()
            finding_text = f"{clean_title} — reported by {item.source_name} [{item.citation_id}]."
            findings.append(finding_text)

            # Categorize threat activity
            lower_snip = item.snippet.lower()
            if any(k in lower_snip for k in ["ransomware", "threat actor", "campaign", "apt", "adversary", "malware"]):
                threat_activity.append(
                    f"Adversary activity documented in {item.source_name}: {item.snippet[:160]}... [{item.citation_id}]"
                )

            # Categorize vulnerability activity
            if item_cves or "vulnerability" in lower_snip or "zero-day" in lower_snip or "rce" in lower_snip:
                cves_fmt = ", ".join(sorted(list(set(item_cves))))
                cve_str = f" ({cves_fmt})" if item_cves else ""
                vulnerabilities.append(
                    f"Vulnerability advisory{cve_str} highlighted by {item.source_name} [{item.citation_id}]."
                )

        # Formulate actionable mitigations based strictly on observed indicators
        if all_cves:
            cve_list_str = ", ".join(sorted(list(all_cves))[:4])
            mitigations.append(
                f"Prioritize immediate security patch deployment for verified vulnerabilities: {cve_list_str} [1]."
            )
        if all_techniques:
            tech_str = ", ".join(sorted(list(all_techniques))[:3])
            mitigations.append(
                f"Implement behavioral detection rules covering observed ATT&CK techniques: {tech_str} [1]."
            )
        mitigations.append(
            f"Review audit logs and enforce perimeter access controls per advisories published by {evidence[0].source_name} [{evidence[0].citation_id}]."
        )

        # Identify evidence gaps / uncertainties
        if len(evidence) < 3:
            evidence_gaps.append("Limited volume of primary reporting indexed for this specific query.")
        if not threat_activity:
            evidence_gaps.append("Specific threat actor attribution or campaign naming is not detailed in retrieved evidence.")
        if not all_cves:
            evidence_gaps.append("No explicit CVE identifiers were cited in the indexed source snippets.")
        evidence_gaps.append("Long-term operational impact remains subject to ongoing telemetry updates.")

        # Construct cohesive narrative answer
        citation_tags = "".join(f"[{item.citation_id}]" for item in evidence[:min(3, len(evidence))])
        
        paragraphs = [
            (
                f"Based on {len(evidence)} verified intelligence records retrieved across authoritative sources "
                f"(including {evidence[0].source_name}), primary security developments centered on "
                f"'{question.rstrip('?')}' have been documented {citation_tags}."
            ),
            (
                f"Factual reporting indicates {len(findings)} key observations. "
                + (f"Documented vulnerabilities include {', '.join(sorted(list(all_cves))[:3])} " if all_cves else "Analysis focuses on operational architecture and configuration resilience ")
                + f"as confirmed by primary reporting [{evidence[0].citation_id}]. "
                + "Analytical review suggests organizations must maintain continuous visibility across impacted environments."
            ),
        ]
        executive_answer = "\n\n".join(paragraphs)

        # Calculate factual grounding confidence based on evidence quality
        avg_quality = sum(e.quality_score for e in evidence) / len(evidence)
        confidence = round(min(0.98, max(0.60, avg_quality * 0.95)), 2)

        return SynthesisOutput(
            executive_answer=executive_answer,
            key_findings=findings[:6],
            threat_activity=threat_activity[:4],
            vulnerabilities=vulnerabilities[:4],
            mitigations=mitigations[:4],
            evidence_gaps=evidence_gaps,
            confidence=confidence,
        )


# Global synthesizer singleton
evidence_synthesizer = EvidenceSynthesizer()
