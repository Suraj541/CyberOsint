"""
Connectors Package
Provides the BaseConnector abstract interface and source registry mechanisms
for collecting and normalizing cybersecurity OSINT data.
"""

from connectors.base import BaseConnector, NormalizedItem, ConnectorHealth
from connectors.registry import connector_registry
from connectors.rss.connector import RSSConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.cert.connector import CERTConnector

__all__ = [
    "BaseConnector",
    "NormalizedItem",
    "ConnectorHealth",
    "connector_registry",
    "RSSConnector",
    "CVEConnector",
    "GitHubSecurityConnector",
    "CERTConnector",
]
