"""
Authentication & API Authentication Module.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Provides JWT Bearer tokens and API key authentication with role mapping.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
from typing import Any, Dict, List, Optional
from fastapi import Depends, Header, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

logger = logging.getLogger("cyber_osint.services.security.auth")

DEFAULT_SECRET_KEY = "development_secret_key_please_change_in_production_32_chars_min"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440  # 24 hours


@dataclass
class UserIdentity:
    """Authenticated user context containing identity, role, and permission scopes."""
    user_id: str
    username: str
    role: str  # 'admin', 'analyst', 'viewer', 'service_connector'
    scopes: List[str] = field(default_factory=list)
    is_active: bool = True


# Pre-configured credentials and service accounts for authentication
SYSTEM_USERS: Dict[str, Dict[str, Any]] = {
    "admin": {
        "user_id": "usr_admin_01",
        "username": "admin",
        "password_hash": hashlib.sha256("admin_secure_pass_2026".encode("utf-8")).hexdigest(),
        "api_key": "admin_api_key_sec36",
        "role": "admin",
        "scopes": ["*"],
    },
    "analyst": {
        "user_id": "usr_analyst_01",
        "username": "analyst",
        "password_hash": hashlib.sha256("analyst_secure_pass_2026".encode("utf-8")).hexdigest(),
        "api_key": "analyst_api_key_sec36",
        "role": "analyst",
        "scopes": ["content:read", "content:write", "search:read", "connectors:read", "connectors:run", "watchlists:read", "watchlists:write", "notifications:read", "notifications:write", "secrets:read"],
    },
    "viewer": {
        "user_id": "usr_viewer_01",
        "username": "viewer",
        "password_hash": hashlib.sha256("viewer_secure_pass_2026".encode("utf-8")).hexdigest(),
        "api_key": "viewer_api_key_sec36",
        "role": "viewer",
        "scopes": ["content:read", "search:read", "connectors:read", "watchlists:read", "notifications:read"],
    },
    "connector_service": {
        "user_id": "srv_connector_01",
        "username": "connector_service",
        "password_hash": hashlib.sha256("service_connector_pass".encode("utf-8")).hexdigest(),
        "api_key": "connector_service_api_key",
        "role": "service_connector",
        "scopes": ["connectors:run", "content:write"],
    },
}

bearer_scheme = HTTPBearer(auto_error=False)


class AuthManager:
    """Manager handling token creation, verification, and API key authentication."""

    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or os.environ.get("SECRET_KEY", DEFAULT_SECRET_KEY)

    def create_access_token(
        self,
        user: UserIdentity,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Generates an HMAC-SHA256 signed JWT token for the user identity."""
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

        to_encode = {
            "sub": user.user_id,
            "username": user.username,
            "role": user.role,
            "scopes": user.scopes,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(to_encode, self.secret_key, algorithm=ALGORITHM)

    def verify_token(self, token: str) -> Optional[UserIdentity]:
        """Decodes and validates a JWT token, returning the UserIdentity."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[ALGORITHM])
            user_id: str = payload.get("sub")
            username: str = payload.get("username", "")
            role: str = payload.get("role", "viewer")
            scopes: List[str] = payload.get("scopes", [])
            if not user_id:
                return None
            return UserIdentity(user_id=user_id, username=username, role=role, scopes=scopes)
        except jwt.PyJWTError as exc:
            logger.debug("Token verification failed: %s", exc)
            return None

    def decode_token(self, token: str) -> Optional[UserIdentity]:
        """Alias for verify_token."""
        return self.verify_token(token)

    def verify_api_key(self, api_key: str) -> Optional[UserIdentity]:
        """Validates an API key against recognized system service accounts."""
        if not api_key:
            return None
        clean_key = api_key.strip()
        for uname, udata in SYSTEM_USERS.items():
            if hmac.compare_digest(udata["api_key"], clean_key):
                return UserIdentity(
                    user_id=udata["user_id"],
                    username=udata["username"],
                    role=udata["role"],
                    scopes=udata["scopes"],
                )
        return None

    def authenticate_user(self, username: str, password_or_key: str) -> Optional[UserIdentity]:
        """Authenticates user via username and password or API key."""
        user_record = SYSTEM_USERS.get(username)
        if not user_record:
            return None

        # Check API key match
        if hmac.compare_digest(user_record["api_key"], password_or_key):
            return UserIdentity(
                user_id=user_record["user_id"],
                username=user_record["username"],
                role=user_record["role"],
                scopes=user_record["scopes"],
            )

        # Check password hash match
        pwd_hash = hashlib.sha256(password_or_key.encode("utf-8")).hexdigest()
        if hmac.compare_digest(user_record["password_hash"], pwd_hash):
            return UserIdentity(
                user_id=user_record["user_id"],
                username=user_record["username"],
                role=user_record["role"],
                scopes=user_record["scopes"],
            )

        return None


auth_manager = AuthManager()


def get_current_user(
    request: Request,
    bearer: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> UserIdentity:
    """
    FastAPI dependency resolving the current user from Bearer token or X-API-Key header.
    In permissive dev mode (AUTH_ENFORCED=False), defaults to standard analyst identity
    if no credentials are provided, but rejects invalid tokens strictly.
    """
    # 1. Check API Key header
    if x_api_key:
        user = auth_manager.verify_api_key(x_api_key)
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or unrecognized API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # 2. Check Bearer Token
    if bearer and bearer.credentials:
        user = auth_manager.verify_token(bearer.credentials)
        if user:
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or malformed authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Check query param api_key for convenience
    query_key = request.query_params.get("api_key")
    if query_key:
        user = auth_manager.verify_api_key(query_key)
        if user:
            return user

    # 4. Check if authentication enforcement is required
    auth_enforced = os.environ.get("AUTH_ENFORCED", "false").lower() in {"true", "1", "yes"}
    if auth_enforced:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide Authorization: Bearer <token> or X-API-Key header.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Dev/Offline default identity with analyst role
    return UserIdentity(
        user_id="usr_dev_analyst",
        username="dev_analyst",
        role="analyst",
        scopes=SYSTEM_USERS["analyst"]["scopes"],
    )


SecurityAuthManager = AuthManager

