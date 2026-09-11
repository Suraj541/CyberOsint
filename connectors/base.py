"""
Base Connector Interface
Defines the standard contract that all OSINT data connectors must implement.
Conforms strictly to IMPLEMENT.md Section 7 specification.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class NormalizedItem(BaseModel):
    """
    Standard normalized output schema for any ingested content item.
    Conforms to IMPLEMENT.md Section 8 specification.
    """

    title: str = Field(..., description="Item title or advisory summary")
    url: str = Field(..., description="Canonical source URL")
    description: Optional[str] = Field(default=None, description="Short summary or excerpt")
    author: Optional[str] = Field(default=None, description="Author or publishing entity")
    published_at: Optional[str] = Field(default=None, description="ISO-formatted publishing timestamp")
    source: str = Field(..., description="Identifier or name of the originating source")
    content_type: str = Field(default="article", description="Type of content: article, advisory, cve, report, video")
    raw_content: Optional[str] = Field(default=None, description="Full raw article or document text")
    language: str = Field(default="en", description="Detected or declared language code")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Connector-specific extra attributes")


class ConnectorHealth(BaseModel):
    """Health check diagnostic result for a source or connector."""

    status: str = Field(default="ok", description="Status code: ok, degraded, or failing")
    source_url: str = Field(..., description="Endpoint or feed URL checked")
    latency_ms: Optional[float] = Field(default=None, description="Roundtrip check latency in milliseconds")
    error_message: Optional[str] = Field(default=None, description="Error details if status is degraded or failing")
    checked_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO UTC timestamp of the health check",
    )
    details: Dict[str, Any] = Field(default_factory=dict, description="Diagnostic telemetry")


class BaseConnector(ABC):
    """
    Abstract base connector interface.
    Every connector (RSS, API, CVE, Web, GitHub) must implement this interface.
    """

    def __init__(self, source_config: Optional[Dict[str, Any]] = None):
        self.config = source_config or {}
        self.source_name: str = self.config.get("name", "generic_source")
        self.source_url: str = self.config.get("url", "")
        self.source_id: Optional[int] = self.config.get("id")

    @abstractmethod
    def discover(self) -> List[Any]:
        """
        Discover available content items, feed entries, or resources from the source.
        Returns a list of raw discovered items or URLs.
        """
        raise NotImplementedError

    @abstractmethod
    def fetch(self, item: Any) -> Any:
        """
        Fetch raw response, document payload, or metadata for a single discovered item.
        """
        raise NotImplementedError

    @abstractmethod
    def parse(self, response: Any) -> Any:
        """
        Parse raw payload into structured intermediate data.
        """
        raise NotImplementedError

    @abstractmethod
    def normalize(self, data: Any) -> NormalizedItem:
        """
        Transform parsed data into the standard NormalizedItem contract.
        """
        raise NotImplementedError

    @abstractmethod
    def health_check(self) -> ConnectorHealth:
        """
        Perform an active ping, HTTP HEAD/GET preflight, or API status check on the source.
        """
        raise NotImplementedError

    def run_pipeline(self) -> List[NormalizedItem]:
        """
        Convenience pipeline executor executing:
        discover -> for each item: (fetch -> parse -> normalize).
        """
        items = self.discover()
        normalized_results: List[NormalizedItem] = []
        for raw_item in items:
            try:
                fetched = self.fetch(raw_item)
                parsed = self.parse(fetched)
                normalized = self.normalize(parsed)
                normalized_results.append(normalized)
            except Exception as e:
                # Log or handle individual item failure without crashing batch
                continue
        return normalized_results
