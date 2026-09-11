"""
Services Classifier Adapter Package
Re-exports the core classification engine for use across background services and ingestion pipelines.
"""

from packages.classifier import (
    ClassificationResult,
    RuleClassifier,
    classify_content,
    rule_classifier,
)

__all__ = [
    "ClassificationResult",
    "RuleClassifier",
    "rule_classifier",
    "classify_content",
]
