"""
Ingestion Metrics & Execution Telemetry
Captures fine-grained performance and counting metrics for each connector execution:
discovered, validated, normalized, ingested, duplicates skipped, errors, and execution duration.
Conforms strictly to IMPLEMENT.md Section 9 specifications.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional


@dataclass
class IngestionItemRecord:
    """Brief representation of an ingested content record."""

    id: int
    title: str
    url: str
    content_hash: str


@dataclass
class IngestionMetrics:
    """
    Tracks complete lifecycle telemetry for an ingestion run.
    Records counts for discovered, validated, normalized, ingested, duplicates skipped, and errors.
    """

    source_id: Optional[int] = None
    source_name: str = "Unknown"
    status: str = "pending"  # pending, success, partial, failed, empty
    discovered_count: int = 0
    validated_count: int = 0
    normalized_count: int = 0
    ingested_count: int = 0
    updated_count: int = 0
    duplicates_skipped: int = 0
    errors_count: int = 0
    duration_ms: float = 0.0
    errors: List[str] = field(default_factory=list)
    items: List[Dict[str, Any]] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None

    def __post_init__(self):
        self._start_perf = time.perf_counter()

    def record_error(self, message: str) -> None:
        """Record an error occurred during item processing."""
        self.errors_count += 1
        if len(self.errors) < 50:  # Cap recorded error messages to avoid bloat
            self.errors.append(message)

    def record_ingested(self, content_id: int, title: str, url: str, content_hash: str) -> None:
        """Record a successfully stored new content item."""
        self.ingested_count += 1
        self.items.append({
            "id": content_id,
            "title": title[:100],
            "url": url,
            "content_hash": content_hash,
            "action": "inserted",
        })

    def record_updated(self, content_id: int, title: str, url: str, content_hash: str) -> None:
        """Record a successfully updated existing content item (e.g. modified CVE)."""
        self.updated_count += 1
        self.items.append({
            "id": content_id,
            "title": title[:100],
            "url": url,
            "content_hash": content_hash,
            "action": "updated",
        })

    def record_duplicate(self, content_hash: str, title: str) -> None:
        """Record a skipped duplicate item."""
        self.duplicates_skipped += 1

    def finish(self, status_override: Optional[str] = None) -> "IngestionMetrics":
        """Finalize timing, evaluate final status, and return instance."""
        self.duration_ms = round((time.perf_counter() - self._start_perf) * 1000, 2)
        self.completed_at = datetime.now(timezone.utc)

        if status_override:
            self.status = status_override
        elif self.errors_count > 0 and (self.ingested_count > 0 or self.updated_count > 0):
            self.status = "partial"
        elif self.errors_count > 0 and self.ingested_count == 0 and self.updated_count == 0 and self.duplicates_skipped == 0:
            self.status = "failed"
        elif self.discovered_count == 0:
            self.status = "empty"
        else:
            self.status = "success"

        return self

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for API serialization or JSON logging."""
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "status": self.status,
            "discovered_count": self.discovered_count,
            "validated_count": self.validated_count,
            "normalized_count": self.normalized_count,
            "ingested_count": self.ingested_count,
            "updated_count": self.updated_count,
            "duplicates_skipped": self.duplicates_skipped,
            "errors_count": self.errors_count,
            "duration_ms": self.duration_ms,
            "errors": self.errors,
            "items": self.items,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }
