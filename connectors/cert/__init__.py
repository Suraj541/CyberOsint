"""
National CERT & CSIRT Advisories Connector Package
Provides CERTConnector for ingesting operational cybersecurity alerts and advisories.
"""

from connectors.cert.connector import CERTConnector

__all__ = ["CERTConnector"]
