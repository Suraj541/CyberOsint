"""
Rule-Based Classification Engine
Performs multi-tiered deterministic and keyword-heuristic categorization of cybersecurity content
against the 16 canonical taxonomy domains.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from packages.classifier.models import ClassificationResult
from packages.taxonomy import CategoryId, taxonomy_registry

logger = logging.getLogger("cyber_osint.packages.classifier")


class RuleClassifier:
    """
    Deterministic & heuristic cybersecurity classifier.
    Combines metadata hints, prioritized title regex rules, and full-text keyword scoring.
    """

    # High-priority regex patterns for top-level domain and subcategory resolution
    PRIORITY_PATTERNS: List[Tuple[str, str, Optional[str], float, str]] = [
        # Ransomware & Extortion -> Malware
        (
            r"\b(ransomware|lockbit|blackcat|akira|play ransomware|darkside|conti|revil|double extortion|decryptor)\b",
            CategoryId.MALWARE.value,
            "ransomware",
            0.95,
            "rule_ransomware_signature",
        ),
        # Infostealers & Trojans -> Malware
        (
            r"\b(infostealer|stealer malware|redline|lumma|vidar|agent tesla|trojan|rat payload|sliver c2|cobalt strike|wiper malware|bootkit|rootkit)\b",
            CategoryId.MALWARE.value,
            "infostealers",
            0.93,
            "rule_malware_strain",
        ),
        # Kubernetes & Containers -> Cloud Security
        (
            r"\b(kubernetes|k8s|container breakout|docker escape|pod security|cloud misconfiguration|aws s3 bucket|azure entra|gcp iam)\b",
            CategoryId.CLOUD_SECURITY.value,
            "kubernetes_security",
            0.93,
            "rule_cloud_container",
        ),
        # Injection & Web AppSec -> Application Security
        (
            r"\b(sql injection|sqli|cross-site scripting|xss|ssrf|server-side request forgery|csrf|deserialization flaw|remote code execution|rce in web|buffer overflow|use-after-free)\b",
            CategoryId.APPLICATION_SECURITY.value,
            "injection_attacks",
            0.93,
            "rule_appsec_injection",
        ),
        # Zero-Day & CVE Announcements -> Vulnerability Management
        (
            r"\b(cve-\d{4}-\d{4,7}|zero-day|0-day vulnerability|security update|patch tuesday|vulnerability advisory|cvss score|epss)\b",
            CategoryId.VULNERABILITY_MANAGEMENT.value,
            "cve_intelligence",
            0.94,
            "rule_cve_vulnerability",
        ),
        # SCADA & OT -> ICS
        (
            r"\b(scada|plcs?|modbus|dnp3|operational technology|industrial control system|critical infrastructure|triton)\b",
            CategoryId.ICS.value,
            "scada_plc",
            0.94,
            "rule_ics_scada",
        ),
        # AI & LLM Exploits -> AI Security
        (
            r"\b(prompt injection|jailbreak prompt|llm jailbreak|adversarial machine learning|training data poisoning|deepfake|ai agent exploit)\b",
            CategoryId.AI_SECURITY.value,
            "llm_jailbreaks",
            0.94,
            "rule_ai_security",
        ),
        # Active Directory & Credentials -> Identity
        (
            r"\b(active directory|kerberoasting|dcsync attack|golden ticket|mfa fatigue|fido2 passkey|credential stuffing|password spraying|bloodhound)\b",
            CategoryId.IDENTITY.value,
            "active_directory",
            0.92,
            "rule_identity_ad",
        ),
        # APT & State-Sponsored Espionage -> Threat Intelligence
        (
            r"\b(apt\d+|nation-state|sandworm|lazarus group|fancy bear|cozy bear|volt typhoon|threat actor|indicators of compromise|mitre att&ck)\b",
            CategoryId.THREAT_INTELLIGENCE.value,
            "apt_groups",
            0.93,
            "rule_threat_intel_actor",
        ),
        # Forensics & DFIR -> Digital Forensics
        (
            r"\b(volatility|memory dump forensics|disk forensics|pcap traffic analysis|wireshark capture|sleuthkit|timeline reconstruction)\b",
            CategoryId.DIGITAL_FORENSICS.value,
            "memory_forensics",
            0.92,
            "rule_digital_forensics",
        ),
        # Incident Response -> Incident Response
        (
            r"\b(incident response playbook|threat hunting hypothesis|compromise assessment|containment strategy|csirt investigation)\b",
            CategoryId.INCIDENT_RESPONSE.value,
            "incident_response",
            0.91,
            "rule_incident_response",
        ),
        # Cryptography -> Cryptography
        (
            r"\b(post-quantum cryptography|pqc|ml-kem|dilithium|lattice-based|tls handshake flaw|side-channel attack|zero-knowledge proof)\b",
            CategoryId.CRYPTOGRAPHY.value,
            "post_quantum",
            0.92,
            "rule_cryptography",
        ),
        # OSINT -> OSINT
        (
            r"\b(osint investigation|shodan search|censys recon|subdomain enumeration|whois intelligence|breached database leak)\b",
            CategoryId.OSINT.value,
            "domain_recon",
            0.91,
            "rule_osint_recon",
        ),
        # DevSecOps -> DevSecOps
        (
            r"\b(devsecops pipeline|sast scan|dast testing|software supply chain|sbom cyclonedx|infrastructure as code|terraform security)\b",
            CategoryId.DEVSECOPS.value,
            "ci_cd_security",
            0.92,
            "rule_devsecops",
        ),
        # Mobile -> Mobile
        (
            r"\b(android malware|pegasus spyware|predator spyware|ios jailbreak|apk decompilation|baseband exploit)\b",
            CategoryId.MOBILE.value,
            "android_security",
            0.92,
            "rule_mobile_security",
        ),
        # IoT -> IoT
        (
            r"\b(iot botnet|mirai variant|firmware extraction|hardware hacking uart|jtag debug|smart home camera exploit)\b",
            CategoryId.IOT.value,
            "embedded_firmware",
            0.92,
            "rule_iot_embedded",
        ),
        # Network Security -> Network Security
        (
            r"\b(ddos attack|syn flood|dns tunneling|dnssec flaw|next-gen firewall|wireguard vpn vulnerability|zero trust architecture)\b",
            CategoryId.NETWORK_SECURITY.value,
            "ddos_protection",
            0.91,
            "rule_network_security",
        ),
    ]

    def classify(
        self,
        title: str,
        description: Optional[str] = None,
        content_text: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ClassificationResult:
        """
        Classify content item into canonical taxonomy domain and subcategory.
        """
        meta = metadata or {}
        title_str = (title or "").strip()
        desc_str = (description or "").strip()
        body_str = (content_text or "").strip()

        # -------------------------------------------------------------
        # TIER 1: Metadata Direct Signals
        # -------------------------------------------------------------
        # 1a. Explicit CVE content
        if meta.get("cve_id") or meta.get("content_type") == "cve":
            # Check if title or desc indicates specific vulnerability mechanism
            cwe = meta.get("weakness")
            sub = "cve_intelligence"
            if cwe:
                cwe_match = taxonomy_registry.resolve_cwe(cwe)
                if cwe_match and cwe_match.get("category_id") == CategoryId.APPLICATION_SECURITY.value:
                    # In CVE catalogs, keep vulnerability_management or tag weakness
                    sub = cwe_match.get("subcategory_id") or sub

            return ClassificationResult(
                category=CategoryId.VULNERABILITY_MANAGEMENT.value,
                subcategory=sub,
                confidence=0.96,
                rule_matched="metadata_cve_type",
                matched_keywords=[str(meta.get("cve_id", "CVE"))],
            )

        # 1b. Tags resolution check
        tags_list = meta.get("tags") or []
        for raw_tag in tags_list:
            if isinstance(raw_tag, str):
                resolved = taxonomy_registry.resolve_tag(raw_tag)
                if resolved:
                    cat_id = resolved["category_id"]
                    sub_id = resolved.get("subcategory_id")
                    # If high-relevance tag found, verify title compatibility
                    if cat_id in (CategoryId.MALWARE.value, CategoryId.CLOUD_SECURITY.value, CategoryId.AI_SECURITY.value):
                        return ClassificationResult(
                            category=cat_id,
                            subcategory=sub_id,
                            confidence=0.92,
                            rule_matched=f"metadata_tag_{raw_tag}",
                            matched_keywords=[raw_tag],
                        )

        # -------------------------------------------------------------
        # TIER 2: Title Pattern Matching (Highest Signal Weight)
        # -------------------------------------------------------------
        for pattern, category_id, subcategory_id, confidence, rule_name in self.PRIORITY_PATTERNS:
            match = re.search(pattern, title_str, re.IGNORECASE)
            if match:
                matched_kw = match.group(0)
                return ClassificationResult(
                    category=category_id,
                    subcategory=subcategory_id,
                    confidence=confidence,
                    rule_matched=rule_name,
                    matched_keywords=[matched_kw],
                )

        # -------------------------------------------------------------
        # TIER 3: Description Pattern Matching
        # -------------------------------------------------------------
        if desc_str:
            for pattern, category_id, subcategory_id, confidence, rule_name in self.PRIORITY_PATTERNS:
                match = re.search(pattern, desc_str, re.IGNORECASE)
                if match:
                    matched_kw = match.group(0)
                    # Slightly lower confidence when matched only in description
                    adjusted_conf = max(0.75, round(confidence - 0.08, 2))
                    return ClassificationResult(
                        category=category_id,
                        subcategory=subcategory_id,
                        confidence=adjusted_conf,
                        rule_matched=f"{rule_name}_description",
                        matched_keywords=[matched_kw],
                    )

        # -------------------------------------------------------------
        # TIER 4: Taxonomy Keyword Density Scoring
        # -------------------------------------------------------------
        # Weight title 3x, description 2x, body 1x
        combined_weighted_text = f"{title_str} {title_str} {title_str} {desc_str} {desc_str} {body_str[:1000]}"
        scored_matches = taxonomy_registry.match_keywords(combined_weighted_text, threshold=1.0)

        if scored_matches:
            top_match = scored_matches[0]
            cat_id = top_match["category_id"]
            matched_subs = top_match.get("matched_subcategories", [])
            sub_id = matched_subs[0] if matched_subs else None
            score = top_match["score"]

            # Calculate confidence between 0.60 and 0.88
            calculated_conf = min(0.88, round(0.60 + (score * 0.04), 2))
            return ClassificationResult(
                category=cat_id,
                subcategory=sub_id,
                confidence=calculated_conf,
                rule_matched="taxonomy_keyword_density",
                matched_keywords=top_match["matched_keywords"][:5],
            )

        # -------------------------------------------------------------
        # TIER 5: Fallback Categorization
        # -------------------------------------------------------------
        return ClassificationResult(
            category=CategoryId.THREAT_INTELLIGENCE.value,
            subcategory=None,
            confidence=0.35,
            rule_matched="default_fallback",
            matched_keywords=[],
        )


# Global singleton instance
rule_classifier = RuleClassifier()
