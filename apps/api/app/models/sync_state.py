"""
Persistent Connector Synchronization State Model.
Enables durable cursor tracking, high-water mark timestamps, ETags, and pagination state across restarts.
Conforms to continuous / near-real-time scheduled polling architecture.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, Integer, String, Text
from app.models.base import BaseModel


class ConnectorSyncState(BaseModel):
    """
    Durable cursor and synchronization checkpoint for an OSINT connector.
    Persists last_seen timestamps, pagination tokens, and payload hashes across application restarts.
    """

    __tablename__ = "connector_sync_states"

    connector_id = Column(String(100), unique=True, nullable=False, index=True)
    source_url = Column(String(2048), nullable=True)
    last_successful_sync = Column(DateTime(timezone=True), nullable=True)
    last_seen_published_at = Column(DateTime(timezone=True), nullable=True)
    last_seen_modified_at = Column(DateTime(timezone=True), nullable=True)
    cursor = Column(String(512), nullable=True)  # E.g. startIndex, pagination page/token, last ID
    etag = Column(String(255), nullable=True)
    last_payload_hash = Column(String(64), nullable=True)
    metadata_json = Column(Text, nullable=True)  # JSON-encoded extra checkpoint data
