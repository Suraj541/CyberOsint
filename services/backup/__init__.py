"""
services/backup/__init__.py
Section 43 (Step 42): Database Backup Service

Exports:
    backup_manager   — singleton BackupManager
    BackupRecord     — dataclass representing a single backup
    BackupStatus     — enum of backup lifecycle states
    BackupType       — enum of backup kinds (full, incremental, pitr_wal)
    RetentionPolicy  — configuration for automated backup pruning
"""

from services.backup.manager import BackupManager, BackupRecord, BackupStatus, BackupType
from services.backup.retention import RetentionPolicy

backup_manager = BackupManager()

__all__ = [
    "backup_manager",
    "BackupManager",
    "BackupRecord",
    "BackupStatus",
    "BackupType",
    "RetentionPolicy",
]
