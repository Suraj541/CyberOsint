"""
Unit and Integration Tests for Section 36 (Step 35: Secret Management).
Conforms strictly to IMPLEMENT.md Section 36:
- Environment variables initially:
  - DATABASE_URL
  - REDIS_URL
  - SEARCH_URL
  - AI_API_KEY
  - VIDEO_API_KEY
  - GITHUB_TOKEN
- Never commit: .env, API keys, tokens, passwords, private certificates
- Production should use a dedicated secret manager
"""

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from services.secrets import (
    MANDATORY_SECRETS,
    AWSSecretManager,
    EncryptedFileSecretManager,
    EnvSecretManager,
    RepositorySecretScanner,
    VaultSecretManager,
    get_secret_manager,
    mask_connection_url,
    mask_secret,
    secret_manager,
)


class TestSecretManagementSection36(unittest.TestCase):
    """Test suite for Section 36 (Step 35: Secret Management)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_mandatory_secrets_specification(self):
        """Verify the 6 core secrets mandated by IMPLEMENT.md Section 36 are defined."""
        mandated_keys = [s["key"] for s in MANDATORY_SECRETS]
        expected_keys = [
            "DATABASE_URL",
            "REDIS_URL",
            "SEARCH_URL",
            "AI_API_KEY",
            "VIDEO_API_KEY",
            "GITHUB_TOKEN",
        ]
        for key in expected_keys:
            self.assertIn(key, mandated_keys, f"Missing mandated secret key: {key}")

        # Verify required vs optional classification
        required_map = {s["key"]: s["required"] for s in MANDATORY_SECRETS}
        self.assertTrue(required_map["DATABASE_URL"])
        self.assertTrue(required_map["REDIS_URL"])
        self.assertTrue(required_map["SEARCH_URL"])
        self.assertFalse(required_map["AI_API_KEY"])
        self.assertFalse(required_map["VIDEO_API_KEY"])
        self.assertFalse(required_map["GITHUB_TOKEN"])

    def test_02_credential_masking(self):
        """Verify masking sanitizes raw credentials and database URLs without leaking plaintext."""
        # 1. GitHub Token Masking
        gh_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
        masked_gh = mask_secret(gh_token)
        self.assertTrue(masked_gh.startswith("ghp_"))
        self.assertTrue(masked_gh.endswith("wxyz"))
        self.assertNotIn("1234567890abcdefghijkl", masked_gh)

        # 2. Database Connection URL Masking
        db_url = "postgresql://postgres:super_secret_password_123@db.prod.internal:5432/cyber_osint"
        masked_db = mask_connection_url(db_url)
        self.assertIn("postgresql://postgres:******@db.prod.internal:5432/cyber_osint", masked_db)
        self.assertNotIn("super_secret_password_123", masked_db)

        # 3. Redis URL Masking
        redis_url = "redis://:auth_secret_token@redis.prod.internal:6379/0"
        masked_redis = mask_connection_url(redis_url)
        self.assertIn(":******@", masked_redis)
        self.assertNotIn("auth_secret_token", masked_redis)

        # 4. Short / empty token handling
        self.assertEqual(mask_secret(""), "")
        self.assertEqual(mask_secret("short"), "********")

    def test_03_secret_manager_backends(self):
        """Verify dedicated secret manager implementations (Env, Vault, AWS, EncryptedFile)."""
        # 1. EnvSecretManager
        os.environ["CUSTOM_TEST_SECRET"] = "super_vault_value_42"
        env_mgr = EnvSecretManager()
        self.assertEqual(env_mgr.get_secret("CUSTOM_TEST_SECRET"), "super_vault_value_42")
        self.assertTrue(env_mgr.has_secret("CUSTOM_TEST_SECRET"))
        self.assertEqual(env_mgr.provider_name, "env")

        # 2. EncryptedFileSecretManager
        vault_file = Path(self.temp_dir) / "test_vault.enc"
        enc_mgr = EncryptedFileSecretManager(file_path=vault_file, master_key="test_master_key_32_bytes_long!")
        enc_mgr.set_secret("ENCRYPTED_API_KEY", "enc_secret_value_99")
        self.assertTrue(vault_file.exists())
        # Raw file content must NOT contain the plaintext secret
        raw_disk_content = vault_file.read_text(encoding="utf-8")
        self.assertNotIn("enc_secret_value_99", raw_disk_content)

        # Reloading decrypts properly
        reloaded_mgr = EncryptedFileSecretManager(file_path=vault_file, master_key="test_master_key_32_bytes_long!")
        self.assertEqual(reloaded_mgr.get_secret("ENCRYPTED_API_KEY"), "enc_secret_value_99")

        # 3. VaultSecretManager (Offline fallback resilience)
        vault_mgr = VaultSecretManager(vault_addr="http://127.0.0.1:9999", vault_token="")
        self.assertEqual(vault_mgr.provider_name, "vault")
        vault_mgr.set_secret("CACHED_VAL", "secret_in_vault")
        self.assertEqual(vault_mgr.get_secret("CACHED_VAL"), "secret_in_vault")

        # 4. AWSSecretManager (Offline fallback resilience)
        aws_mgr = AWSSecretManager()
        self.assertEqual(aws_mgr.provider_name, "aws")
        aws_mgr.set_secret("AWS_CACHED", "secret_in_aws")
        self.assertEqual(aws_mgr.get_secret("AWS_CACHED"), "secret_in_aws")

    def test_04_repository_secret_scanner_and_gitignore_rules(self):
        """
        Verify scanner audits .gitignore for .env, tokens, and private certificates.
        Conforms strictly to IMPLEMENT.md Section 36:
        'Never commit: .env, API keys, tokens, passwords, private certificates'
        """
        scanner = RepositorySecretScanner()
        gi_report = scanner.check_gitignore_compliance()

        # .gitignore must exist and be compliant
        self.assertTrue(gi_report["compliant"], f"Missing gitignore patterns: {gi_report.get('missing_patterns')}")
        self.assertIn(".env", gi_report["verified_patterns"])
        self.assertIn("*.pem", gi_report["verified_patterns"])
        self.assertIn("*.key", gi_report["verified_patterns"])
        self.assertIn("*.cert", gi_report["verified_patterns"])
        self.assertIn("*.crt", gi_report["verified_patterns"])

        # Full audit execution
        full_audit = scanner.run_full_audit()
        self.assertTrue(full_audit.gitignore_compliant)
        self.assertEqual(full_audit.critical_findings, 0, f"Critical findings detected: {full_audit.findings}")

    def test_05_fastapi_secret_endpoints(self):
        """Verify REST API endpoints for secret management status, audit, and verification."""
        # 1. GET /api/v1/secrets/status
        res_status = self.client.get("/api/v1/secrets/status")
        self.assertEqual(res_status.status_code, 200)
        status_data = res_status.json()
        self.assertIn("provider", status_data)
        self.assertEqual(status_data["total_tracked"], 6)
        self.assertTrue(status_data["gitignore_compliant"])

        # Verify masked previews (never raw password)
        secret_keys = [s["key"] for s in status_data["secrets"]]
        self.assertIn("DATABASE_URL", secret_keys)
        self.assertIn("REDIS_URL", secret_keys)
        self.assertIn("SEARCH_URL", secret_keys)
        for sec in status_data["secrets"]:
            if sec["masked_value"]:
                self.assertNotIn("postgres_secure_pass", sec["masked_value"])

        # 2. GET /api/v1/secrets/audit
        res_audit = self.client.get("/api/v1/secrets/audit")
        self.assertEqual(res_audit.status_code, 200)
        audit_data = res_audit.json()
        self.assertTrue(audit_data["gitignore_compliant"])
        self.assertIn("verified_patterns", audit_data)

        # 3. POST /api/v1/secrets/verify (Configured secret)
        res_verify_db = self.client.post("/api/v1/secrets/verify", json={"key": "DATABASE_URL"})
        self.assertEqual(res_verify_db.status_code, 200)
        db_res = res_verify_db.json()
        self.assertTrue(db_res["configured"])
        self.assertTrue(db_res["accessible"])
        self.assertIn("postgresql://", db_res["masked_preview"])

        # 4. POST /api/v1/secrets/verify (Unset secret)
        res_verify_unset = self.client.post("/api/v1/secrets/verify", json={"key": "UNKNOWN_TEST_KEY_NOT_SET"})
        self.assertEqual(res_verify_unset.status_code, 200)
        unset_res = res_verify_unset.json()
        self.assertFalse(unset_res["configured"])
        self.assertFalse(unset_res["accessible"])


if __name__ == "__main__":
    unittest.main()
