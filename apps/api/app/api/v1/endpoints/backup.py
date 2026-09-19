"""
apps/api/app/api/v1/endpoints/backup.py
Section 43 (Step 42): Database Backup REST API

Endpoints:
  POST   /backup/create          — trigger a new backup (full/incremental/pitr_wal)
  POST   /backup/{id}/verify     — re-verify an existing backup by restoring it
  POST   /backup/{id}/restore    — disaster recovery: restore a backup
  GET    /backup                 — list all backups
  GET    /backup/{id}            — get a single backup record
  DELETE /backup/{id}            — manually delete (soft-delete via retention)
  GET    /backup/report/disaster-recovery  — DR readiness report
  POST   /backup/pitr/create     — create a PITR WAL snapshot
  POST   /backup/pitr/restore    — restore to a point-in-time
  GET    /backup/{id}/checksum   — validate file checksum
  POST   /backup/retention/apply — apply configured retention policy
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from services.backup import backup_manager
from services.backup.manager import BackupRecord, BackupStatus, BackupType
from services.backup.retention import POLICY_PRESETS, RetentionPolicy

logger = logging.getLogger("cyber_osint.backup_api")

router = APIRouter(prefix="/backup", tags=["Backup"])


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class BackupCreateRequest(BaseModel):
    backup_type: str = Field(default="full", description="full | incremental | pitr_wal")
    auto_verify: bool = Field(
        default=True,
        description="Immediately verify the backup by restoring it after creation. "
                    "Per IMPLEMENT.md: 'Do not assume a backup is valid until you have restored it.'",
    )


class BackupRestoreRequest(BaseModel):
    target_path: Optional[str] = Field(None, description="Target file path for SQLite restores")
    target_db_url: Optional[str] = Field(None, description="Target database URL for PostgreSQL restores")


class PITRRestoreRequest(BaseModel):
    target_timestamp: str = Field(..., description="ISO-8601 timestamp to recover to (e.g. 2026-09-17T10:00:00Z)")
    target_path: Optional[str] = Field(None, description="Target path for the restored database")


class RetentionApplyRequest(BaseModel):
    preset: Optional[str] = Field(None, description="Preset name: development | staging | production")
    max_age_days: Optional[int] = Field(None, ge=1)
    min_backups: Optional[int] = Field(None, ge=1)
    min_verified: Optional[int] = Field(None, ge=1)


def _record_to_response(r: BackupRecord) -> dict:
    return r.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.post(
    "/create",
    status_code=status.HTTP_201_CREATED,
    summary="Create Database Backup",
    description=(
        "Triggers a new database backup. "
        "When auto_verify=True (default), the backup is immediately verified "
        "by restoring it to a temporary location before being marked VERIFIED. "
        "Per IMPLEMENT.md Section 43: **'Do not assume a database backup is valid until you have restored it.'**"
    ),
)
def create_backup(payload: BackupCreateRequest = BackupCreateRequest()) -> dict:
    try:
        bt = BackupType(payload.backup_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid backup_type '{payload.backup_type}'. Valid: full, incremental, pitr_wal",
        )
    record = backup_manager.create_backup(backup_type=bt, auto_verify=payload.auto_verify)
    return _record_to_response(record)


@router.get(
    "",
    summary="List All Backups",
)
def list_backups(
    status_filter: Optional[str] = Query(None, description="Filter by status: pending|running|completed|verified|failed|deleted"),
    backup_type: Optional[str] = Query(None, description="Filter by type: full|incremental|pitr_wal"),
) -> List[dict]:
    records = backup_manager.list_backups()
    if status_filter:
        try:
            sf = BackupStatus(status_filter)
            records = [r for r in records if r.status == sf]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid status filter '{status_filter}'",
            )
    if backup_type:
        try:
            bt = BackupType(backup_type)
            records = [r for r in records if r.backup_type == bt]
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid backup_type filter '{backup_type}'",
            )
    return [_record_to_response(r) for r in records]


@router.get(
    "/report/disaster-recovery",
    summary="Disaster Recovery Readiness Report",
    description=(
        "Returns a comprehensive DR report: total backups by status, "
        "last verified backup, coverage gap since last verification, "
        "and PITR snapshot availability."
    ),
)
def disaster_recovery_report() -> dict:
    return backup_manager.disaster_recovery_report()


@router.get(
    "/{backup_id}",
    summary="Get Backup Record",
)
def get_backup(backup_id: str) -> dict:
    record = backup_manager.get_backup(backup_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Backup '{backup_id}' not found",
        )
    return _record_to_response(record)


@router.post(
    "/{backup_id}/verify",
    summary="Verify Backup by Restoring It",
    description=(
        "Re-verify a backup by restoring it to a temporary location and "
        "running integrity checks. Updates the backup status to VERIFIED or FAILED. "
        "Per IMPLEMENT.md: backups are only considered valid after restore verification."
    ),
)
def verify_backup(backup_id: str) -> dict:
    try:
        record = backup_manager.verify_backup(backup_id)
        return _record_to_response(record)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Backup '{backup_id}' not found")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/{backup_id}/restore",
    summary="Restore Backup (Disaster Recovery)",
    description=(
        "Restores a VERIFIED backup to the specified target. "
        "For SQLite: decompresses to target_path. "
        "For PostgreSQL: runs pg_restore to target_db_url. "
        "Only VERIFIED or COMPLETED backups may be restored."
    ),
)
def restore_backup(backup_id: str, payload: BackupRestoreRequest = BackupRestoreRequest()) -> dict:
    try:
        return backup_manager.restore_backup(
            backup_id=backup_id,
            target_path=payload.target_path,
            target_db_url=payload.target_db_url,
        )
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Backup '{backup_id}' not found")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.get(
    "/{backup_id}/checksum",
    summary="Validate Backup File Checksum",
    description="Recomputes SHA-256 of the backup file and compares with the stored hash to detect corruption.",
)
def validate_checksum(backup_id: str) -> dict:
    try:
        return backup_manager.validate_checksum(backup_id)
    except KeyError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Backup '{backup_id}' not found")
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))


@router.post(
    "/pitr/create",
    status_code=status.HTTP_201_CREATED,
    summary="Create PITR WAL Snapshot",
    description=(
        "Creates a Point-In-Time Recovery snapshot. "
        "For SQLite: timestamped online backup. "
        "For PostgreSQL: archives a WAL segment (provide wal_file_path in query)."
    ),
)
def create_pitr_snapshot(
    wal_file_path: Optional[str] = Query(None, description="Path to WAL segment file (PostgreSQL only)"),
) -> dict:
    record = backup_manager.create_pitr_wal_segment(wal_file_path=wal_file_path)
    return _record_to_response(record)


@router.post(
    "/pitr/restore",
    summary="Restore to Point-In-Time",
    description=(
        "Finds the nearest PITR snapshot at or before target_timestamp and restores it. "
        "Used for disaster recovery when recovering to a specific point in time."
    ),
)
def restore_pitr(payload: PITRRestoreRequest) -> dict:
    result = backup_manager.restore_pitr(
        target_timestamp=payload.target_timestamp,
        target_path=payload.target_path,
    )
    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("error", "PITR restore failed"),
        )
    return result


@router.post(
    "/retention/apply",
    summary="Apply Retention Policy",
    description=(
        "Prunes backups older than max_age_days, keeping at least min_backups. "
        "Use preset='production' | 'staging' | 'development' for standard policies, "
        "or provide custom parameters."
    ),
)
def apply_retention(payload: RetentionApplyRequest = RetentionApplyRequest()) -> dict:
    if payload.preset:
        if payload.preset not in POLICY_PRESETS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Unknown preset '{payload.preset}'. Valid: {list(POLICY_PRESETS.keys())}",
            )
        policy = POLICY_PRESETS[payload.preset]
    else:
        policy = RetentionPolicy(
            max_age_days=payload.max_age_days or 30,
            min_backups=payload.min_backups or 3,
            min_verified=payload.min_verified or 1,
        )

    deleted_ids = backup_manager.apply_retention_policy(policy)
    return {
        "policy": policy.to_dict(),
        "deleted_count": len(deleted_ids),
        "deleted_backup_ids": deleted_ids,
    }
