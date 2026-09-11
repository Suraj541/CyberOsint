"""
GitHub Security Advisories Connector Package
Provides GitHubSecurityConnector for ingesting and normalizing GHSA advisories.
"""

from connectors.github.connector import GitHubSecurityConnector

__all__ = ["GitHubSecurityConnector"]
