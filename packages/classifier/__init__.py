"""
Cybersecurity Classification Package
Provides rule-based classification of intelligence content into the 16 canonical taxonomy domains.
Conforms strictly to IMPLEMENT.md Section 15 specifications.
"""

from packages.classifier.models import ClassificationResult
from packages.classifier.rule_engine import RuleClassifier, rule_classifier

classify_content = rule_classifier.classify

__all__ = [
    "ClassificationResult",
    "RuleClassifier",
    "rule_classifier",
    "classify_content",
]
