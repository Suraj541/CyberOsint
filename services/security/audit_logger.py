"""
Security Audit Logging Service.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Records immutable security events (auth, RBAC denials, rate-limiting, SSRF blocks, secret access).
"""

from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyber_osint.services.security.audit")


@dataclass
class SecurityAuditEvent:
    """Structured security audit log record."""
    event_id: str
    timestamp: str
    event_type: str  # 'auth_login', 'auth_failed', 'rbac_denied', 'rate_limited', 'ssrf_blocked', 'secret_accessed', 'connector_executed'
    actor: str       # user_id, username, or 'anonymous'
    role: str        # 'admin', 'analyst', 'viewer', 'anonymous'
    resource: str    # API endpoint, secret key, or connector id
    action: str      # 'GET', 'POST', 'ACCESS', 'RUN', 'SCAN'
    status: str      # 'allowed', 'denied', 'blocked', 'warning', 'success'
    client_ip: str
    details: Dict[str, Any] = field(default_factory=dict)


class SecurityAuditLogger:
    """
    Immutable Security Audit Logger.
    Maintains an in-memory ring buffer for rapid query execution
    and appends records to persistent JSON lines audit log.
    """

    MAX_BUFFER_SIZE = 2000

    def __init__(self, log_dir: Optional[Path] = None, log_file: Optional[Path] = None):
        if log_file:
            self.log_file = Path(log_file)
            self.log_dir = self.log_file.parent
        elif log_dir:
            self.log_dir = Path(log_dir)
            self.log_file = self.log_dir / "security_audit.jsonl"
        else:
            root_dir = Path(__file__).resolve().parent.parent.parent
            self.log_dir = root_dir / "logs"
            self.log_file = self.log_dir / "security_audit.jsonl"

        self._buffer: deque = deque(maxlen=self.MAX_BUFFER_SIZE)
        self._ensure_log_dir()

    def _ensure_log_dir(self) -> None:
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.debug("Could not create audit log directory: %s", exc)

    def log_event(
        self,
        event_type: str,
        actor: str = "anonymous",
        role: str = "anonymous",
        resource: str = "/",
        action: str = "ACCESS",
        status: str = "allowed",
        client_ip: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None,
    ) -> SecurityAuditEvent:
        """Records a new security event into memory ring-buffer and persistent log."""
        now = datetime.now(timezone.utc)
        event_id = f"aud_{now.strftime('%Y%m%d%H%M%S')}_{len(self._buffer)+1:04d}"

        event = SecurityAuditEvent(
            event_id=event_id,
            timestamp=now.isoformat(),
            event_type=event_type,
            actor=actor,
            role=role,
            resource=resource,
            action=action,
            status=status,
            client_ip=client_ip,
            details=details or {},
        )

        # Append to in-memory ring buffer
        self._buffer.append(event)

        # Append to persistent JSONL log file
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event)) + "\n")
        except Exception as exc:
            logger.debug("Could not write to audit log file: %s", exc)

        if status in {"denied", "blocked", "warning"}:
            logger.warning("SECURITY EVENT [%s] %s %s by %s from %s: %s", event_type, action, resource, actor, client_ip, status)
        else:
            logger.info("SECURITY EVENT [%s] %s %s by %s", event_type, action, resource, actor)

        return event

    def get_recent_events(
        self,
        limit: int = 100,
        event_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[SecurityAuditEvent]:
        """Queries recent security audit events with optional filtering."""
        events = list(self._buffer)
        events.reverse()  # Newest first

        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if status:
            events = [e for e in events if e.status == status]

        return events[:limit]


audit_logger = SecurityAuditLogger()
