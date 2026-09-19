"""
Role-Based Access Control (RBAC) Module.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Provides role hierarchies, permission scope resolution, and FastAPI route guards.
"""

from typing import Any, Callable, List, Optional, Set
from fastapi import Depends, HTTPException, status

from services.security.auth import UserIdentity, get_current_user

# Role hierarchy: higher roles inherit permissions from lower roles
ROLE_HIERARCHY = {
    "admin": {"admin", "analyst", "viewer", "service_connector"},
    "analyst": {"analyst", "viewer"},
    "viewer": {"viewer"},
    "service_connector": {"service_connector"},
}

# Explicit role permission mappings
ROLE_PERMISSIONS = {
    "admin": {"*"},
    "analyst": {
        "content:read",
        "content:write",
        "search:read",
        "connectors:read",
        "connectors:run",
        "watchlists:read",
        "watchlists:write",
        "notifications:read",
        "notifications:write",
        "secrets:read",
        "security:audit",
    },
    "viewer": {
        "content:read",
        "search:read",
        "connectors:read",
        "watchlists:read",
        "notifications:read",
    },
    "service_connector": {
        "connectors:run",
        "content:write",
    },
}


class RBACValidator:
    """Evaluates user identity against role requirements and permission scopes."""

    @staticmethod
    def has_role(user_role: str, required_role: str) -> bool:
        """Checks whether user_role satisfies the required_role hierarchy."""
        allowed_roles = ROLE_HIERARCHY.get(user_role, {user_role})
        return required_role in allowed_roles

    @staticmethod
    def has_role_access(current_role: str, required_role: str) -> bool:
        """Alias for has_role checking hierarchical role access."""
        return RBACValidator.has_role(current_role, required_role)

    @staticmethod
    def has_permission(
        user_or_role: Any,
        permission_or_scopes: Any,
        required_permission: Optional[str] = None,
    ) -> bool:
        """
        Checks whether user possesses the required permission scope.
        Supports both signatures:
          has_permission(user: UserIdentity, required_permission: str)
          has_permission(user_role: str, user_scopes: List[str], required_permission: str)
        """
        if isinstance(user_or_role, UserIdentity):
            user_role = user_or_role.role
            user_scopes = user_or_role.scopes
            req_perm = str(permission_or_scopes)
        elif required_permission is not None:
            user_role = str(user_or_role)
            user_scopes = list(permission_or_scopes)
            req_perm = required_permission
        else:
            user_role = str(user_or_role)
            user_scopes = []
            req_perm = str(permission_or_scopes)

        # 1. Check explicit wildcard in user scopes or role
        if "*" in user_scopes or user_role == "admin":
            return True

        # 2. Check user's granted scopes
        if req_perm in user_scopes:
            return True

        # 3. Check role's baseline permissions
        role_perms = ROLE_PERMISSIONS.get(user_role, set())
        if "*" in role_perms or req_perm in role_perms:
            return True

        return False


RBACPolicy = RBACValidator
rbac_policy = RBACValidator()



def require_role(required_role: str) -> Callable:
    """FastAPI route guard ensuring caller possesses the required role or higher."""

    def role_checker(user: UserIdentity = Depends(get_current_user)) -> UserIdentity:
        if not RBACValidator.has_role(user.role, required_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Required role '{required_role}', but current role is '{user.role}'.",
            )
        return user

    return role_checker


def require_permission(required_permission: str) -> Callable:
    """FastAPI route guard ensuring caller possesses the specified permission scope."""

    def permission_checker(user: UserIdentity = Depends(get_current_user)) -> UserIdentity:
        if not RBACValidator.has_permission(user.role, user.scopes, required_permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Missing required permission scope '{required_permission}'.",
            )
        return user

    return permission_checker
