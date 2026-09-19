"""
Tests for Subsystem 10: Authentication.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing) and Section 37.
Validates user credential verification, API key authentication, JWT token generation,
tamper detection, token expiration, and identity resolution.
"""

from datetime import timedelta
from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.security import (
    SecurityAuthManager,
    UserIdentity,
    auth_manager,
)


class TestAuthenticationSubsystem(unittest.TestCase):
    """Subsystem 10: Authentication Unit Tests."""

    def test_01_user_identity_dataclass(self):
        """Verify UserIdentity dataclass contract and fields."""
        user = UserIdentity(
            user_id="usr_001",
            username="sec_analyst",
            role="analyst",
            scopes=["read:content", "write:content"],
            is_active=True,
        )
        self.assertEqual(user.user_id, "usr_001")
        self.assertEqual(user.username, "sec_analyst")
        self.assertEqual(user.role, "analyst")
        self.assertIn("read:content", user.scopes)
        self.assertTrue(user.is_active)

    def test_02_authenticate_user_with_password(self):
        """Verify password authentication returns valid user identity and rejects bad credentials."""
        # Valid credentials
        admin = auth_manager.authenticate_user("admin", "admin_secure_pass_2026")
        self.assertIsNotNone(admin)
        self.assertEqual(admin.role, "admin")
        self.assertIn("*", admin.scopes)

        # Invalid password
        bad_pass = auth_manager.authenticate_user("admin", "incorrect_password_attempt")
        self.assertIsNone(bad_pass)

        # Unknown user
        non_existent = auth_manager.authenticate_user("ghost_user", "some_password")
        self.assertIsNone(non_existent)

    def test_03_authenticate_with_api_key(self):
        """Verify programmatic API key authentication for automated connector services."""
        svc_user = auth_manager.authenticate_user("connector_service", "connector_service_api_key")
        self.assertIsNotNone(svc_user)
        self.assertEqual(svc_user.role, "service_connector")
        self.assertIn("connectors:run", svc_user.scopes)

    def test_04_jwt_token_lifecycle_and_tampering(self):
        """Verify JWT token creation, signature verification, and tampered token rejection."""
        user = UserIdentity(
            user_id="usr_002",
            username="threat_hunter",
            role="analyst",
            scopes=["read:content"],
        )
        token = auth_manager.create_access_token(user, expires_delta=timedelta(hours=1))
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 30)

        # Decode valid token
        decoded = auth_manager.decode_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.username, "threat_hunter")
        self.assertEqual(decoded.role, "analyst")

        # Reject tampered token signature
        tampered_token = token[:-5] + "x9z1q"
        self.assertIsNone(auth_manager.decode_token(tampered_token))

    def test_05_expired_jwt_token_rejection(self):
        """Verify expired tokens fail validation immediately."""
        user = UserIdentity(user_id="usr_003", username="temp_user", role="viewer")
        # Token expired 10 seconds ago
        token = auth_manager.create_access_token(user, expires_delta=timedelta(seconds=-10))
        decoded = auth_manager.decode_token(token)
        self.assertIsNone(decoded, "Expired token must not decode successfully")


if __name__ == "__main__":
    unittest.main()
