"""
Security Hardening Package.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Coordinates all 15 mandated platform defense controls.
"""

from services.security.audit_logger import (
    SecurityAuditEvent,
    SecurityAuditLogger,
    audit_logger,
)
from services.security.auth import (
    SYSTEM_USERS,
    AuthManager,
    SecurityAuthManager,
    UserIdentity,
    auth_manager,
    get_current_user,
)
from services.security.dependency_scanner import (
    ContainerScanner,
    DependencyScanner,
    container_scanner,
    dependency_scanner,
)
from services.security.file_validator import (
    DocumentSandbox,
    FileTypeValidator,
    FileValidationResult,
    file_validator,
    sandbox,
)
from services.security.input_validation import (
    InputValidator,
    input_validator,
)
from services.security.middleware import SecurityHeadersMiddleware
from services.security.rate_limiter import (
    RateLimiter,
    TIER_LIMITS,
    TieredRateLimiter,
    enforce_rate_limit,
    rate_limiter,
    tiered_rate_limiter,
)
from services.security.rbac import (
    ROLE_HIERARCHY,
    ROLE_PERMISSIONS,
    RBACPolicy,
    RBACValidator,
    rbac_policy,
    require_permission,
    require_role,
)
from services.security.ssrf import (
    DISALLOWED_HOSTS,
    DISALLOWED_NETWORKS,
    INTERNAL_DOMAIN_SUFFIXES,
    SENSITIVE_INTERNAL_PORTS,
    SSRFRedirectChainResult,
    SSRFRedirectHop,
    SSRFSecurityError,
    SSRFValidationResult,
    SSRFValidator,
    SecureURLFetcher,
    secure_fetcher,
    ssrf_validator,
)

__all__ = [
    # Auth & API Authentication
    "auth_manager",
    "get_current_user",
    "UserIdentity",
    "SYSTEM_USERS",
    "AuthManager",
    "SecurityAuthManager",
    # RBAC
    "RBACValidator",
    "RBACPolicy",
    "rbac_policy",
    "require_role",
    "require_permission",
    "ROLE_HIERARCHY",
    "ROLE_PERMISSIONS",
    # Rate Limiting
    "tiered_rate_limiter",
    "rate_limiter",
    "enforce_rate_limit",
    "TIER_LIMITS",
    "TieredRateLimiter",
    "RateLimiter",
    # Input Validation
    "InputValidator",
    "input_validator",
    # SSRF Protection & Fetcher
    "ssrf_validator",
    "secure_fetcher",
    "SSRFValidator",
    "SecureURLFetcher",
    "SSRFValidationResult",
    "SSRFRedirectHop",
    "SSRFRedirectChainResult",
    "SSRFSecurityError",
    "DISALLOWED_NETWORKS",
    "DISALLOWED_HOSTS",
    "INTERNAL_DOMAIN_SUFFIXES",
    "SENSITIVE_INTERNAL_PORTS",
    # Sandboxed Document & File Validation
    "file_validator",
    "FileTypeValidator",
    "FileValidationResult",
    "DocumentSandbox",
    "sandbox",
    # Audit Logging
    "audit_logger",
    "SecurityAuditLogger",
    "SecurityAuditEvent",
    # Middleware
    "SecurityHeadersMiddleware",
    # Dependency & Container Scanners
    "dependency_scanner",
    "container_scanner",
    "DependencyScanner",
    "ContainerScanner",
]

