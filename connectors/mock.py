"""
Mock / Test Security Connector
Reference implementation of BaseConnector used for integration testing and contract validation.
"""

from typing import Any, Dict, List, Optional
from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry


@connector_registry.register("mock")
class MockSecurityConnector(BaseConnector):
    """Reference implementation of BaseConnector used for test harnesses."""

    def __init__(self, source_config: Optional[Dict[str, Any]] = None):
        super().__init__(source_config)
        self.should_fail: bool = self.config.get("should_fail", False)

    def discover(self) -> List[Dict[str, Any]]:
        """Return synthetic security advisories."""
        if self.should_fail:
            raise RuntimeError("Mock discovery failure")
        return [
            {
                "id": "advisory-101",
                "title": "Zero-Day Vulnerability Discovered in Cloud Gateway",
                "link": "https://mock-security.local/advisories/101",
                "published": "2026-09-11T12:00:00Z",
                "author": "Security Research Team",
                "summary": "Critical authentication bypass vulnerability affecting Cloud Gateway v4.x.",
            },
            {
                "id": "advisory-102",
                "title": "New Ransomware Variant Target Critical Infrastructure",
                "link": "https://mock-security.local/advisories/102",
                "published": "2026-09-11T14:30:00Z",
                "author": "Threat Intelligence Unit",
                "summary": "Sophisticated threat group deploys customized payload.",
            },
        ]

    def fetch(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate fetching raw payload."""
        return {
            "raw_payload": item,
            "status_code": 200,
            "fetched_at": "2026-09-11T15:00:00Z",
        }

    def parse(self, response: Dict[str, Any]) -> Dict[str, Any]:
        """Extract structured entry from raw payload."""
        return response.get("raw_payload", {})

    def normalize(self, data: Dict[str, Any]) -> NormalizedItem:
        """Transform into standard NormalizedItem."""
        return NormalizedItem(
            title=data.get("title", "Untitled"),
            url=data.get("link", ""),
            description=data.get("summary"),
            author=data.get("author"),
            published_at=data.get("published"),
            source=self.source_name,
            content_type="advisory",
            language="en",
            metadata={"advisory_id": data.get("id")},
        )

    def health_check(self) -> ConnectorHealth:
        """Simulate connector health probe."""
        if self.should_fail:
            return ConnectorHealth(
                status="failing",
                source_url=self.source_url,
                error_message="Simulated endpoint connection timeout",
            )
        return ConnectorHealth(
            status="ok",
            source_url=self.source_url or "https://mock-security.local",
            latency_ms=12.5,
            details={"entries_available": 2},
        )
