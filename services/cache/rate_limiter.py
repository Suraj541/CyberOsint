"""
Rate Limiting Service
Provides sliding/fixed-window request throttling and quota enforcement using Redis.
Conforms strictly to IMPLEMENT.md Section 11 specifications.
"""

import logging
import time
from typing import Optional, Tuple
from fastapi import HTTPException, Request, status

from services.cache.client import RedisClient, redis_client

logger = logging.getLogger("cyber_osint.services.cache.rate_limiter")


class RateLimiter:
    """Rate limiter enforcing limits over configurable time windows."""

    def __init__(self, client: Optional[RedisClient] = None):
        self.client = client or redis_client

    def is_allowed(
        self,
        identifier: str,
        limit: int = 60,
        window_seconds: int = 60,
    ) -> Tuple[bool, int, float]:
        """
        Check whether an action under the given identifier is within rate limits.
        Returns:
            (allowed: bool, remaining_tokens: int, retry_after_seconds: float)
        """
        current_time = time.time()
        window_bucket = int(current_time // window_seconds)
        cache_key = f"rate_limit:{identifier}:{window_bucket}"

        # Increment count in the current window bucket
        current_count = self.client.incr(cache_key)

        # Set expiration if this is the first item in the bucket
        if current_count == 1:
            self.client.expire(cache_key, window_seconds + 5)

        remaining = max(0, limit - current_count)
        time_to_reset = float((window_bucket + 1) * window_seconds - current_time)

        allowed = current_count <= limit
        if not allowed:
            logger.warning(
                "Rate limit exceeded for '%s': %d/%d in %ds window (retry in %.1fs)",
                identifier,
                current_count,
                limit,
                window_seconds,
                time_to_reset,
            )

        return allowed, remaining, round(time_to_reset, 1)


class RateLimitDependency:
    """FastAPI route dependency enforcing request rate limits per client IP or token."""

    def __init__(self, limit: int = 60, window_seconds: int = 60, prefix: str = "api"):
        self.limit = limit
        self.window_seconds = window_seconds
        self.prefix = prefix
        self.limiter = RateLimiter()

    def __call__(self, request: Request) -> None:
        client_ip = request.client.host if request.client else "unknown"
        auth_header = request.headers.get("Authorization", "")
        identifier = f"{self.prefix}:{client_ip}"
        if auth_header:
            identifier = f"{self.prefix}:token:{hash(auth_header)}"

        allowed, remaining, reset_after = self.limiter.is_allowed(
            identifier=identifier,
            limit=self.limit,
            window_seconds=self.window_seconds,
        )

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Try again in {reset_after:.0f} seconds.",
                headers={
                    "Retry-After": str(int(reset_after)),
                    "X-RateLimit-Limit": str(self.limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(int(reset_after)),
                },
            )


# Global singleton instance
rate_limiter = RateLimiter()
