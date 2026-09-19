"""
Security Tiered Rate Limiter Module.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Provides role-tiered sliding-window request throttling and quota enforcement.
"""

from datetime import datetime, timezone
import logging
import time
from typing import Any, Optional, Tuple
from fastapi import HTTPException, Request, status

from services.cache.rate_limiter import RateLimiter as BaseRateLimiter, rate_limiter as base_rate_limiter
from services.security.auth import UserIdentity

logger = logging.getLogger("cyber_osint.services.security.rate_limiter")

# Tiered request limits per 60-second window
TIER_LIMITS = {
    "admin": 1200,      # 20 req/sec
    "analyst": 300,     # 5 req/sec
    "viewer": 60,       # 1 req/sec
    "anonymous": 60,    # 1 req/sec
    "service_connector": 600,
}


class TieredRateLimiter:
    """Enforces tiered rate limits based on client identity and role."""

    def __init__(self, base_limiter: Optional[Any] = None, backend: str = "memory"):
        self.backend = backend
        self.limiter = base_limiter or base_rate_limiter

    def check_rate_limit(
        self,
        request_or_key: Any,
        user: Optional[UserIdentity] = None,
        custom_limit: Optional[int] = None,
        limit: Optional[int] = None,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, float]:
        """
        Validates whether the request or key is within its role-based quota.
        Returns: (allowed: bool, remaining: int, retry_after: float)
        """
        effective_limit = limit or custom_limit or (TIER_LIMITS.get(user.role, 60) if user else 60)

        if isinstance(request_or_key, str):
            identifier = f"sec_rate:{request_or_key}"
        else:
            client_ip = request_or_key.client.host if (request_or_key and hasattr(request_or_key, "client") and request_or_key.client) else "127.0.0.1"
            if user:
                identifier = f"sec_rate:{user.user_id}:{user.role}"
            else:
                identifier = f"sec_rate:ip:{client_ip}"

        allowed, remaining, reset_after = self.limiter.is_allowed(
            identifier=identifier,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

        return allowed, remaining, reset_after

    def get_rate_limit_headers(
        self,
        request_or_key: Any,
        limit: int = 60,
        window_seconds: int = 60,
    ) -> dict:
        """Returns standard OWASP rate limit headers."""
        if isinstance(request_or_key, str):
            identifier = f"sec_rate:{request_or_key}"
        else:
            client_ip = request_or_key.client.host if (request_or_key and hasattr(request_or_key, "client") and request_or_key.client) else "127.0.0.1"
            identifier = f"sec_rate:ip:{client_ip}"

        allowed, remaining, reset_after = self.limiter.is_allowed(
            identifier=identifier,
            limit=limit,
            window_seconds=window_seconds,
        )
        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(reset_after)),
        }


tiered_rate_limiter = TieredRateLimiter()
RateLimiter = TieredRateLimiter
rate_limiter = tiered_rate_limiter



def enforce_rate_limit(
    request: Request,
    custom_limit: Optional[int] = None,
    window_seconds: int = 60,
) -> None:
    """
    FastAPI dependency that enforces rate limiting and sets OWASP-standard headers.
    Throws HTTP 429 Too Many Requests when quota is exceeded.
    """
    allowed, remaining, reset_after, limit = tiered_rate_limiter.check_rate_limit(
        request=request,
        custom_limit=custom_limit,
        window_seconds=window_seconds,
    )

    # Attach response headers
    if not allowed:
        logger.warning("Rate limit exceeded for client %s", request.client.host if request.client else "unknown")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded ({limit} req/{window_seconds}s). Retry in {reset_after:.0f} seconds.",
            headers={
                "Retry-After": str(int(reset_after)),
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(reset_after)),
            },
        )
