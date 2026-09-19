"""
Importance Calculation Engine
Evaluates content severity, exploit weaponization signals, source reliability, and watchlist match depth.
Enforces importance thresholds as mandated by IMPLEMENT.md Section 33:
"Do not send every discovered article. Implement importance thresholds."
"""

import re
from typing import Any, Dict, List, Optional
from services.notification.models import ImportanceLevel, ImportanceScoreResult, NotificationChannel

# Severity mapping to normalized factor [0.0 - 1.0]
SEVERITY_FACTORS = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
    "INFO": 0.05,
}

# High-priority signals indicating weaponization or active exploitation
EXPLOIT_SIGNALS = [
    r"\b0-day\b",
    r"\bzero-day\b",
    r"\bkev\b",
    r"\bcisa\b",
    r"\bin[- ]the[- ]wild\b",
    r"\bactively exploited\b",
    r"\bweaponized\b",
    r"\brce\b",
    r"\bremote code execution\b",
    r"\bproof[- ]of[- ]concept\b",
    r"\bpoc\b",
    r"\bransomware\b",
]

# Default channel minimum importance thresholds to avoid alert fatigue
DEFAULT_CHANNEL_THRESHOLDS = {
    NotificationChannel.WEB: 0.35,      # In-app feed shows medium & above
    NotificationChannel.EMAIL: 0.70,    # Email reserved for High & Critical
    NotificationChannel.PUSH: 0.75,     # Push reserved for High & Critical
    NotificationChannel.WEBHOOK: 0.50,  # Webhooks dispatch Medium & above
}


class ImportanceCalculator:
    """
    Computes multi-dimensional importance scores for cybersecurity intelligence content.
    Combines:
    1. Severity Rank (35%)
    2. Vulnerability & Active Exploitation Signals (25%)
    3. Source Reliability & Provenance (20%)
    4. Watchlist Target Match Depth & High-Value Types (20%)
    """

    def __init__(self, default_threshold: float = 0.45):
        self.default_threshold = default_threshold

    def calculate(
        self,
        content_dict: Dict[str, Any],
        matched_items: Optional[List[Any]] = None,
        source_quality_score: Optional[float] = None,
        threshold_override: Optional[float] = None,
    ) -> ImportanceScoreResult:
        """
        Calculate composite importance score and determine if content meets sending threshold.
        """
        matched_items = matched_items or []
        threshold = threshold_override if threshold_override is not None else self.default_threshold

        # 1. Severity Factor (0.0 - 1.0)
        raw_sev = str(content_dict.get("severity") or "LOW").upper()
        severity_factor = SEVERITY_FACTORS.get(raw_sev, 0.2)

        # 2. Vulnerability & Active Exploitation Signals (0.0 - 1.0)
        exploit_factor = 0.0
        # Check CVSS score
        cvss = content_dict.get("cvss_score")
        if cvss is not None:
            try:
                cvss_val = float(cvss)
                exploit_factor = max(exploit_factor, min(cvss_val / 10.0, 1.0))
            except (ValueError, TypeError):
                pass

        # Check CVE count or entities
        entities = content_dict.get("entities", [])
        has_cve = False
        for ent in entities:
            if isinstance(ent, dict) and ent.get("entity_type", "").lower() == "cve":
                has_cve = True
                break
            elif isinstance(ent, str) and ent.upper().startswith("CVE-"):
                has_cve = True
                break

        if has_cve:
            exploit_factor = max(exploit_factor, 0.6)

        # Check textual exploitation signals
        text_corpus = f"{content_dict.get('title', '')} {content_dict.get('description', '')} {content_dict.get('summary', '')}".lower()
        tags = [str(t).lower() for t in content_dict.get("tags", [])]
        all_text = f"{text_corpus} {' '.join(tags)}"

        matched_signals_count = 0
        for pattern in EXPLOIT_SIGNALS:
            if re.search(pattern, all_text, re.IGNORECASE):
                matched_signals_count += 1

        if matched_signals_count > 0:
            signal_boost = min(0.15 * matched_signals_count, 0.4)
            exploit_factor = min(exploit_factor + signal_boost, 1.0)

        # 3. Source Reliability / Quality Factor (0.0 - 1.0)
        if source_quality_score is not None:
            source_factor = max(0.0, min(source_quality_score, 1.0))
        else:
            # Infer from source name or defaults
            source_name = str(content_dict.get("source", "")).lower()
            if any(trusted in source_name for trusted in ["cisa", "nvd", "cert", "microsoft", "google", "mandiant"]):
                source_factor = 0.95
            elif any(mid in source_name for mid in ["bleeping", "thehackernews", "krebsonsecurity", "darkreading"]):
                source_factor = 0.80
            else:
                source_factor = 0.60

        # 4. Watchlist Target Match Depth & Type Value (0.0 - 1.0)
        watchlist_factor = 0.0
        high_value_types = {"cve", "threat_actor", "malware"}
        med_value_types = {"product", "vendor", "technology", "tool"}

        for item in matched_items:
            itype = ""
            if hasattr(item, "item_type"):
                itype = getattr(item, "item_type", "").lower()
            elif isinstance(item, dict):
                itype = str(item.get("item_type", "")).lower()

            if itype in high_value_types:
                watchlist_factor += 0.35
            elif itype in med_value_types:
                watchlist_factor += 0.20
            else:
                watchlist_factor += 0.10

        # Base bonus if at least one item matched
        if matched_items:
            watchlist_factor = max(watchlist_factor, 0.30)
        watchlist_factor = min(watchlist_factor, 1.0)

        # Weighted Composite Score
        composite_score = (
            (0.35 * severity_factor)
            + (0.25 * exploit_factor)
            + (0.20 * source_factor)
            + (0.20 * watchlist_factor)
        )
        composite_score = round(max(0.0, min(composite_score, 1.0)), 3)

        # Categorize Level
        if composite_score >= 0.85:
            level = ImportanceLevel.CRITICAL
        elif composite_score >= 0.70:
            level = ImportanceLevel.HIGH
        elif composite_score >= 0.45:
            level = ImportanceLevel.MEDIUM
        elif composite_score >= 0.25:
            level = ImportanceLevel.LOW
        else:
            level = ImportanceLevel.INFO

        exceeds = composite_score >= threshold

        factors = {
            "severity_factor": round(severity_factor, 3),
            "exploit_factor": round(exploit_factor, 3),
            "source_factor": round(source_factor, 3),
            "watchlist_factor": round(watchlist_factor, 3),
        }

        reasons = []
        if severity_factor >= 0.8:
            reasons.append(f"{raw_sev} severity")
        if exploit_factor >= 0.6:
            reasons.append("exploitable/weaponized indicators")
        if watchlist_factor >= 0.3:
            reasons.append(f"{len(matched_items)} watchlist hits")
        if not reasons:
            reasons.append(f"baseline score {composite_score}")

        reason_str = f"{level.value} ({composite_score:.2f}): " + ", ".join(reasons)

        return ImportanceScoreResult(
            score=composite_score,
            level=level,
            factors=factors,
            exceeds_threshold=exceeds,
            threshold_used=threshold,
            reason=reason_str,
        )

    def should_send(
        self,
        channel: NotificationChannel,
        score: float,
        channel_threshold_override: Optional[float] = None,
    ) -> bool:
        """
        Determines whether a notification with given importance score should be sent over a specific channel.
        Prevents alert fatigue per IMPLEMENT.md Section 33.
        """
        threshold = (
            channel_threshold_override
            if channel_threshold_override is not None
            else DEFAULT_CHANNEL_THRESHOLDS.get(channel, self.default_threshold)
        )
        return score >= threshold


# Singleton instance
importance_calculator = ImportanceCalculator()
