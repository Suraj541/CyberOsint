"""
Real PostgreSQL 16 Backup, Checksum, and Restoration Test Suite.
Validates:
1. Native pg_dump execution against running PostgreSQL 16 server.
2. Gzip compression and SHA-256 cryptographic checksum computation.
3. Manifest persistence and metadata recording (TOC entry count, engine=postgresql).
4. Full restoration via pg_restore into a fresh database (cyber_osint_verify).
5. Schema, table, and data equality verification between source and restored database.
6. Corruption detection on tampered archives.
"""

import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

# Ensure pgsql/bin is in PATH for this process
PG_BIN = Path(r"c:\Users\suraj\Desktop\the_info\pgsql\bin")
if str(PG_BIN) not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{PG_BIN};{os.environ.get('PATH', '')}"

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.models import Content, ContentEntity, Entity, Source, User
from services.backup.manager import BackupManager, BackupStatus, BackupType

SRC_URL = "postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/cyber_osint"
RESTORE_DB_NAME = "cyber_osint_verify"
RESTORE_URL = f"postgresql://postgres:postgres_secure_pass@127.0.0.1:5432/{RESTORE_DB_NAME}"


class TestPostgreSQLBackup(unittest.TestCase):
    """Verifies PostgreSQL 16 backup and disaster recovery."""

    @classmethod
    def setUpClass(cls):
        # Configure verify URL environment variable
        os.environ["PGVERIFY_DB_URL"] = RESTORE_URL
        cls.src_engine = create_engine(SRC_URL, pool_pre_ping=True)
        cls.restore_engine = create_engine(RESTORE_URL, pool_pre_ping=True)
        cls.SrcSession = sessionmaker(bind=cls.src_engine)
        cls.RestoreSession = sessionmaker(bind=cls.restore_engine)

    def setUp(self):
        self.tmp_backup_dir = Path(tempfile.mkdtemp(prefix="pg_backup_test_"))
        self.manager = BackupManager(
            backup_dir=self.tmp_backup_dir,
            database_url=SRC_URL,
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_backup_dir, ignore_errors=True)

    def test_01_real_pg_dump_creation_and_checksum(self):
        """Test full PostgreSQL backup using pg_dump, checksum, and TOC verification."""
        # 1. Seed distinctive test data in source database
        src_session = self.SrcSession()
        ts = int(datetime.now().timestamp() * 1000)
        source = Source(
            name=f"Backup Test Source #{ts}",
            url=f"https://backup-test-{ts}.local",
            source_type="advisory",
            active=True,
        )
        src_session.add(source)
        src_session.commit()

        content = Content(
            source_id=source.id,
            title=f"Critical Backup Advisory #{ts}",
            canonical_url=f"https://backup-test-{ts}.local/item-1",
            content_hash=hashlib.sha256(f"backup_{ts}".encode()).hexdigest(),
            status="ingested",
        )
        entity = Entity(
            name=f"CVE-2026-BK-{ts % 10000}",
            entity_type="cve",
            normalized_name=f"CVE-2026-BK-{ts % 10000}",
        )
        src_session.add_all([content, entity])
        src_session.commit()

        link = ContentEntity(
            content_id=content.id,
            entity_id=entity.id,
            confidence=1.0,
            extraction_method="regex",
        )
        src_session.add(link)
        src_session.commit()
        src_session.close()

        # 2. Execute full backup via BackupManager
        record = self.manager.create_backup(BackupType.FULL, auto_verify=True)

        # 3. Assertions on BackupRecord
        self.assertEqual(record.status, BackupStatus.VERIFIED)
        self.assertEqual(record.db_engine, "postgresql")
        self.assertIsNotNone(record.file_path)
        self.assertTrue(Path(record.file_path).exists())
        self.assertGreater(record.file_size_bytes, 0)
        self.assertIsNotNone(record.sha256_checksum)
        self.assertGreater(record.metadata.get("toc_entry_count", 0), 0)

        # 4. Verify SHA-256 checksum independently
        h = hashlib.sha256()
        with open(record.file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        self.assertEqual(h.hexdigest(), record.sha256_checksum)

    def test_02_pg_restore_into_fresh_database_data_integrity(self):
        """Restore PostgreSQL archive into clean database and verify data integrity."""
        # 1. Clean the target restore database first
        with self.restore_engine.connect() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
            conn.commit()

        # 2. Create a fresh backup
        record = self.manager.create_backup(BackupType.FULL, auto_verify=False)
        self.assertEqual(record.status, BackupStatus.COMPLETED)

        # 3. Decompress and run pg_restore into cyber_osint_verify
        backup_file = Path(record.file_path)
        with tempfile.NamedTemporaryFile(suffix=".pgdump", delete=False) as tmp:
            tmp_path = Path(tmp.name)

        try:
            with gzip.open(backup_file, "rb") as f_in, open(tmp_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

            env = os.environ.copy()
            env["PGPASSWORD"] = "postgres_secure_pass"
            cmd = [
                "pg_restore",
                "--no-password",
                "--no-privileges",
                "--no-owner",
                "-h", "127.0.0.1",
                "-p", "5432",
                "-U", "postgres",
                "-d", RESTORE_DB_NAME,
                str(tmp_path),
            ]
            res = subprocess.run(cmd, capture_output=True, env=env, text=True)
            # pg_restore exits 0 or 1 on non-fatal warnings
            self.assertIn(res.returncode, (0, 1), f"pg_restore failed: {res.stderr}")

            # 4. Verify restored database schema and tables
            with self.restore_engine.connect() as conn:
                tables = conn.execute(text(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name"
                )).scalars().all()
                self.assertGreaterEqual(len(tables), 40, f"Expected >= 40 tables, found {len(tables)}")
                self.assertIn("content", tables)
                self.assertIn("entities", tables)
                self.assertIn("sources", tables)
                self.assertIn("alembic_version", tables)

            # 5. Verify record counts match between source and restored database
            with self.src_engine.connect() as src_conn, self.restore_engine.connect() as rest_conn:
                src_count = src_conn.execute(text("SELECT count(*) FROM content")).scalar()
                rest_count = rest_conn.execute(text("SELECT count(*) FROM content")).scalar()
                self.assertEqual(src_count, rest_count, "Content row count mismatch after restore")

        finally:
            tmp_path.unlink(missing_ok=True)

    def test_03_backup_corruption_detection(self):
        """Verify that a corrupted or truncated backup archive fails verification."""
        record = self.manager.create_backup(BackupType.FULL, auto_verify=False)
        self.assertEqual(record.status, BackupStatus.COMPLETED)

        # Corrupt the archive by overwriting bytes in the middle of the gzip file
        backup_path = Path(record.file_path)
        with open(backup_path, "r+b") as f:
            f.seek(50)
            f.write(b"CORRUPTED_GARBAGE_BYTES_1234567890")

        # Now verify should fail
        verified_record = self.manager.verify_backup(record.backup_id)
        self.assertEqual(verified_record.status, BackupStatus.FAILED)
        self.assertIsNotNone(verified_record.verification_error)


if __name__ == "__main__":
    unittest.main()
