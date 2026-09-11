"""
Connectors Package
Provides the BaseConnector abstract interface and source registry mechanisms
for collecting and normalizing cybersecurity OSINT data.
"""

from connectors.base import BaseConnector, NormalizedItem, ConnectorHealth
from connectors.registry import connector_registry

__all__ = ["BaseConnector", "NormalizedItem", "ConnectorHealth", "connector_registry"]
