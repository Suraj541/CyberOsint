"""
Persistent Synchronization State Manager.
Provides durable checkpoints, high-water marks, pagination cursors, and ETags across restarts.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from sqlalchemy.orm import Session

logger = logging.getLogger("cyber_osint.services.sync")

# File-backed durable fallback if database session is omitted or transient
STATE_DIR = Path(__file__).resolve().parent.parent.parent / "data"
STATE_FILE = STATE_DIR / "sync_state.json"


def _read_fallback_file() -> Dict[str, Any]:
    try:
        if STATE_FILE.exists():
            return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug("Error reading fallback sync state file: %s", e)
    return {}


def _write_fallback_file(data: Dict[str, Any]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    except Exception as e:
        logger.debug("Error writing fallback sync state file: %s", e)


class SyncStateManager:
    """Manages persistent cursor and synchronization checkpoints for connectors."""

    @staticmethod
    def get_state(db: Optional[Session], connector_id: str) -> Dict[str, Any]:
        """Retrieve persistent synchronization state for a connector."""
        if db is not None:
            try:
                from app.models.sync_state import ConnectorSyncState
                row = db.query(ConnectorSyncState).filter(ConnectorSyncState.connector_id == connector_id).first()
                if row:
                    extra = {}
                    if row.metadata_json:
                        try:
                            extra = json.loads(row.metadata_json)
                        except Exception:
                            pass
                    return {
                        "connector_id": row.connector_id,
                        "source_url": row.source_url,
                        "last_successful_sync": row.last_successful_sync.isoformat() if row.last_successful_sync else None,
                        "last_seen_published_at": row.last_seen_published_at.isoformat() if row.last_seen_published_at else None,
                        "last_seen_modified_at": row.last_seen_modified_at.isoformat() if row.last_seen_modified_at else None,
                        "cursor": row.cursor,
                        "etag": row.etag,
                        "last_payload_hash": row.last_payload_hash,
                        "metadata": extra,
                    }
            except Exception as exc:
                logger.debug("DB read error for sync state of '%s': %s", connector_id, exc)

        # Fallback to durable file state
        all_state = _read_fallback_file()
        return all_state.get(connector_id, {})

    @staticmethod
    def update_state(
        db: Optional[Session],
        connector_id: str,
        source_url: Optional[str] = None,
        last_successful_sync: Optional[datetime] = None,
        last_seen_published_at: Optional[datetime] = None,
        last_seen_modified_at: Optional[datetime] = None,
        cursor: Optional[str] = None,
        etag: Optional[str] = None,
        last_payload_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update or create persistent synchronization checkpoint for a connector."""
        now_dt = datetime.now(timezone.utc)
        sync_dt = last_successful_sync or now_dt

        # 1. Update Database if available
        if db is not None:
            try:
                from app.models.sync_state import ConnectorSyncState
                row = db.query(ConnectorSyncState).filter(ConnectorSyncState.connector_id == connector_id).first()
                if not row:
                    row = ConnectorSyncState(connector_id=connector_id)
                    db.add(row)

                if source_url is not None:
                    row.source_url = source_url
                row.last_successful_sync = sync_dt
                if last_seen_published_at is not None:
                    row.last_seen_published_at = last_seen_published_at
                if last_seen_modified_at is not None:
                    row.last_seen_modified_at = last_seen_modified_at
                if cursor is not None:
                    row.cursor = str(cursor)
                if etag is not None:
                    row.etag = etag
                if last_payload_hash is not None:
                    row.last_payload_hash = last_payload_hash
                if metadata is not None:
                    existing_meta = {}
                    if row.metadata_json:
                        try:
                            existing_meta = json.loads(row.metadata_json)
                        except Exception:
                            pass
                    existing_meta.update(metadata)
                    row.metadata_json = json.dumps(existing_meta)

                row.updated_at = now_dt
                db.commit()
            except Exception as exc:
                db.rollback()
                logger.debug("DB write error for sync state of '%s': %s", connector_id, exc)

        # 2. Update File Fallback
        all_state = _read_fallback_file()
        current = all_state.setdefault(connector_id, {})
        if source_url is not None:
            current["source_url"] = source_url
        current["last_successful_sync"] = sync_dt.isoformat()
        if last_seen_published_at is not None:
            current["last_seen_published_at"] = last_seen_published_at.isoformat()
        if last_seen_modified_at is not None:
            current["last_seen_modified_at"] = last_seen_modified_at.isoformat()
        if cursor is not None:
            current["cursor"] = str(cursor)
        if etag is not None:
            current["etag"] = etag
        if last_payload_hash is not None:
            current["last_payload_hash"] = last_payload_hash
        if metadata is not None:
            current.setdefault("metadata", {}).update(metadata)
        _write_fallback_file(all_state)

        return current


sync_state_manager = SyncStateManager()
