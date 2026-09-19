"""
Connectors Package
Provides the BaseConnector abstract interface, source registry, and advanced connector manager
for collecting and normalizing cybersecurity OSINT data across the 11 prioritized categories.
Conforms strictly to IMPLEMENT.md Section 34 (Step 33: Add Advanced OSINT Connectors).
"""

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.blog.connector import SecurityBlogConnector
from connectors.cert.connector import CERTConnector
from connectors.conference.connector import ConferenceSourceConnector
from connectors.cve.connector import CVEConnector
from connectors.document.connector import DocumentConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.config import (
    ConnectorConfig,
    ConnectorConfigManager,
    ConnectorsFileSchema,
    connector_config_manager,
)
from connectors.manager import (
    PRIORITY_CONNECTOR_SPECS,
    AdvancedConnectorManager,
    connector_manager,
)
from connectors.registry import connector_registry
from connectors.research.connector import ResearchDatabaseConnector
from connectors.rss.connector import RSSConnector
from connectors.social.connector import PublicSocialConnector
from connectors.specialized.connector import SpecializedSourceConnector
from connectors.vendor.connector import VendorAdvisoryConnector
from connectors.video.connector import VideoConnector

__all__ = [
    "BaseConnector",
    "NormalizedItem",
    "ConnectorHealth",
    "connector_registry",
    "connector_manager",
    "AdvancedConnectorManager",
    "PRIORITY_CONNECTOR_SPECS",
    "ConnectorConfig",
    "ConnectorsFileSchema",
    "ConnectorConfigManager",
    "connector_config_manager",
    # Priority 1 to 11 Connectors
    "RSSConnector",                 # Priority 1: Security feeds
    "CERTConnector",                # Priority 2: Government/CERT
    "CVEConnector",                 # Priority 3: CVE databases
    "VendorAdvisoryConnector",       # Priority 4: Vendor advisories
    "SecurityBlogConnector",        # Priority 5: Security blogs
    "GitHubSecurityConnector",      # Priority 6: GitHub
    "ResearchDatabaseConnector",    # Priority 7: Research databases
    "VideoConnector",               # Priority 8: Video platforms
    "ConferenceSourceConnector",    # Priority 9: Conference sources
    "PublicSocialConnector",        # Priority 10: Public social sources
    "SpecializedSourceConnector",   # Priority 11: Other specialized sources
    "DocumentConnector",            # Ancillary Document parsing connector
]
