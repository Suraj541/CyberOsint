"""
Tests for Subsystem 11: Authorization (RBAC).
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing) and Section 37.
Validates role hierarchy (admin > analyst > viewer), permission scopes,
and authorization enforcement policies.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.security import (
    RBACPolicy,
    UserIdentity,
    rbac_policy,
)


class TestAuthorizationSubsystem(unittest.TestCase):
    """Subsystem 11: Authorization Unit Tests."""

    def test_01_role_hierarchy_admin(self):
        """Verify admin role satisfies all lower role requirements (admin, analyst, viewer)."""
        self.assertTrue(RBACPolicy.has_role_access("admin", "admin"))
        self.assertTrue(RBACPolicy.has_role_access("admin", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("admin", "viewer"))

    def test_02_role_hierarchy_analyst(self):
        """Verify analyst role satisfies analyst and viewer, but cannot access admin actions."""
        self.assertFalse(RBACPolicy.has_role_access("analyst", "admin"))
        self.assertTrue(RBACPolicy.has_role_access("analyst", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("analyst", "viewer"))

    def test_03_role_hierarchy_viewer(self):
        """Verify viewer role is strictly restricted to viewer actions."""
        self.assertFalse(RBACPolicy.has_role_access("viewer", "admin"))
        self.assertFalse(RBACPolicy.has_role_access("viewer", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("viewer", "viewer"))

    def test_04_scope_based_permission_evaluation(self):
        """Verify granular permission scope checks for various user identities."""
        # Admin wildcard
        admin_user = UserIdentity(user_id="u_admin", username="admin", role="admin", scopes=["*"])
        self.assertTrue(RBACPolicy.has_permission(admin_user, "write:system"))
        self.assertTrue(RBACPolicy.has_permission(admin_user, "delete:database"))

        # Analyst explicit permissions
        analyst_user = UserIdentity(
            user_id="u_analyst",
            username="analyst",
            role="analyst",
            scopes=["content:read", "content:write", "search:read"],
        )
        self.assertTrue(RBACPolicy.has_permission(analyst_user, "content:write"))
        self.assertFalse(RBACPolicy.has_permission(analyst_user, "admin:system"))

        # Viewer read-only permissions
        viewer_user = UserIdentity(
            user_id="u_viewer",
            username="viewer",
            role="viewer",
            scopes=["content:read", "search:read"],
        )
        self.assertTrue(RBACPolicy.has_permission(viewer_user, "content:read"))
        self.assertFalse(RBACPolicy.has_permission(viewer_user, "content:write"))

    def test_05_unauthorized_role_rejected(self):
        """Verify unprivileged role fails permission checks."""
        guest_user = UserIdentity(
            user_id="u_guest",
            username="guest",
            role="guest",
            scopes=[],
        )
        self.assertFalse(RBACPolicy.has_permission(guest_user, "write:system"))
        self.assertFalse(RBACPolicy.has_permission(guest_user, "content:read"))
        self.assertFalse(RBACPolicy.has_role_access("guest", "analyst"))


if __name__ == "__main__":
    unittest.main()
