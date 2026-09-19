"""
Security Headers & Hardening Middleware.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
Injects OWASP/NIST defensive HTTP headers on all API responses.
"""

from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; object-src 'none';",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
    "X-Permitted-Cross-Domain-Policies": "none",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware applying OWASP-recommended HTTP security headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for header_name, header_value in SECURITY_HEADERS.items():
            if header_name not in response.headers:
                response.headers[header_name] = header_value
        return response
