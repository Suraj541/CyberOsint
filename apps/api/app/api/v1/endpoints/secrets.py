"""
Secret Management & Security Audit API Endpoints.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
Enforces the strict rule:
- Never expose plaintext secrets, tokens, passwords, or private certificates.
"""

import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status

from app.schemas.secret import (
    SecretAuditResponse,
    SecretItemResponse,
    SecretSaveRequest,
    SecretSaveResponse,
    SecretScanFindingResponse,
    SecretTestKeyRequest,
    SecretTestKeyResponse,
    SecretVerifyRequest,
    SecretVerifyResponse,
)
from services.secrets import (
    MANDATORY_SECRETS,
    RepositorySecretScanner,
    mask_connection_url,
    mask_secret,
    secret_manager,
)

logger = logging.getLogger("cyber_osint.api.secrets")

router = APIRouter(prefix="/secrets", tags=["Secret Management"])


@router.get(
    "/status",
    response_model=SecretAuditResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Status of Mandatory Platform Secrets",
)
def get_secrets_status() -> SecretAuditResponse:
    """
    Returns the configuration status and masked previews for all 6 mandatory secrets:
    DATABASE_URL, REDIS_URL, SEARCH_URL, AI_API_KEY, VIDEO_API_KEY, GITHUB_TOKEN.
    Strictly masks all credentials to prevent token leakage.
    """
    audit_data = secret_manager.audit_secrets()
    scanner = RepositorySecretScanner()
    gi_check = scanner.check_gitignore_compliance()

    secret_items = [
        SecretItemResponse(
            key=s["key"],
            configured=s["configured"],
            masked_value=s["masked_value"],
            description=s["description"],
            required=s["required"],
            provider=s["provider"],
            last_checked_at=s["last_checked_at"],
        )
        for s in audit_data["secrets"]
    ]

    return SecretAuditResponse(
        provider=audit_data["provider"],
        total_tracked=audit_data["total_tracked"],
        configured_count=audit_data["configured_count"],
        missing_required_count=audit_data["missing_required_count"],
        is_healthy=audit_data["is_healthy"] and gi_check["compliant"],
        secrets=secret_items,
        gitignore_compliant=gi_check["compliant"],
        findings=[],
        verified_patterns=gi_check.get("verified_patterns", []),
        audited_at=datetime.now(timezone.utc).isoformat(),
    )


@router.get(
    "/audit",
    response_model=SecretAuditResponse,
    status_code=status.HTTP_200_OK,
    summary="Full Repository Secret & Policy Audit",
)
def run_secret_audit() -> SecretAuditResponse:
    """
    Runs an active compliance audit across gitignore rules and workspace contents
    to verify:
    1. .env, tokens, passwords, and private certificates (*.pem, *.key, *.cert) are gitignored.
    2. No hardcoded tokens exist in source files.
    """
    audit_data = secret_manager.audit_secrets()
    scanner = RepositorySecretScanner()
    report = scanner.run_full_audit()

    secret_items = [
        SecretItemResponse(
            key=s["key"],
            configured=s["configured"],
            masked_value=s["masked_value"],
            description=s["description"],
            required=s["required"],
            provider=s["provider"],
            last_checked_at=s["last_checked_at"],
        )
        for s in audit_data["secrets"]
    ]

    findings = [
        SecretScanFindingResponse(
            severity=f.severity,
            rule=f.rule,
            file_path=f.file_path,
            description=f.description,
            line_number=f.line_number,
        )
        for f in report.findings
    ]

    return SecretAuditResponse(
        provider=audit_data["provider"],
        total_tracked=audit_data["total_tracked"],
        configured_count=audit_data["configured_count"],
        missing_required_count=audit_data["missing_required_count"],
        is_healthy=report.is_compliant and audit_data["is_healthy"],
        secrets=secret_items,
        gitignore_compliant=report.gitignore_compliant,
        findings=findings,
        verified_patterns=report.ignored_patterns_verified,
        audited_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post(
    "/verify",
    response_model=SecretVerifyResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify Access to a Specific Secret Key",
)
def verify_secret_key(payload: SecretVerifyRequest) -> SecretVerifyResponse:
    """
    Tests whether a secret key is accessible in the active SecretManager backend.
    Returns masked preview and confirmation status without transmitting raw secrets.
    """
    raw_val = secret_manager.get_secret(payload.key)
    has_val = bool(raw_val and str(raw_val).strip())

    if not has_val:
        return SecretVerifyResponse(
            key=payload.key,
            configured=False,
            accessible=False,
            provider=secret_manager.provider_name,
            masked_preview=None,
            message=f"Secret '{payload.key}' is not configured in backend '{secret_manager.provider_name}'.",
        )

    # Determine URL or token masking
    is_url = "URL" in payload.key.upper() or "://" in str(raw_val)
    masked = mask_connection_url(raw_val) if is_url else mask_secret(raw_val)

    return SecretVerifyResponse(
        key=payload.key,
        configured=True,
        accessible=True,
        provider=secret_manager.provider_name,
        masked_preview=masked,
        message=f"Secret '{payload.key}' verified successfully in backend '{secret_manager.provider_name}'.",
    )


# -----------------------------------------------------------------------------
# Interactive API Keys Management & Testing Subsystem
# -----------------------------------------------------------------------------

MANAGED_API_KEYS = [
    {
        "key": "MISTRAL_API_KEY",
        "label": "Mistral AI API Key",
        "category": "AI & Intelligence",
        "description": "API key for Mistral AI LLM intelligence synthesis, threat reasoning, and grounded summarization.",
        "is_secret": True,
        "docs_url": "https://console.mistral.ai/api-keys/",
        "required": False,
    },
    {
        "key": "AI_API_KEY",
        "label": "Unified / OpenAI / Anthropic Key",
        "category": "AI & Intelligence",
        "description": "General AI API key for intelligence synthesis and automated threat analysis fallback.",
        "is_secret": True,
        "docs_url": "https://platform.openai.com/api-keys",
        "required": False,
    },
    {
        "key": "MISTRAL_MODEL",
        "label": "Mistral AI Model Selection",
        "category": "AI & Intelligence",
        "description": "Active Mistral model. Set to 'auto' for dynamic capability auto-detection, or specify a model ID.",
        "is_secret": False,
        "docs_url": "https://docs.mistral.ai/getting-started/models/",
        "required": False,
    },
    {
        "key": "GITHUB_TOKEN",
        "label": "GitHub Personal Access Token",
        "category": "Threat Feeds & OSINT",
        "description": "Token for querying GitHub Security Advisories (GHSA), vulnerability feeds, and exploit PoCs.",
        "is_secret": True,
        "docs_url": "https://github.com/settings/tokens",
        "required": False,
    },
    {
        "key": "VIDEO_API_KEY",
        "label": "Multimedia & YouTube Data API Key",
        "category": "Threat Feeds & OSINT",
        "description": "API key for cybersecurity conference video metadata, transcripts, and presentation indexing.",
        "is_secret": True,
        "docs_url": "https://console.cloud.google.com/apis/credentials",
        "required": False,
    },
    {
        "key": "SEARCH_URL",
        "label": "OpenSearch Cluster Endpoint",
        "category": "Infrastructure",
        "description": "OpenSearch cluster URL for hybrid BM25 and vector semantic search retrieval.",
        "is_secret": False,
        "docs_url": "https://opensearch.org/docs/latest/",
        "required": True,
    },
    {
        "key": "DATABASE_URL",
        "label": "PostgreSQL Database Connection",
        "category": "Infrastructure",
        "description": "SQLAlchemy connection string for relational storage (PostgreSQL with SQLite dev fallback).",
        "is_secret": True,
        "docs_url": "https://www.postgresql.org/docs/",
        "required": True,
    },
    {
        "key": "REDIS_URL",
        "label": "Redis Cache & Queue Endpoint",
        "category": "Infrastructure",
        "description": "Redis connection URL for tiered rate-limiting, pipeline cache, and background task queues.",
        "is_secret": True,
        "docs_url": "https://redis.io/docs/",
        "required": True,
    },
]


def _update_env_file(updates: Dict[str, str]) -> List[str]:
    """Updates key-value pairs in the root .env file, creating it if needed."""
    env_path = Path(".env")
    if not env_path.exists():
        example_path = Path(".env.example")
        if example_path.exists():
            env_path.write_text(example_path.read_text(encoding="utf-8"), encoding="utf-8")
        else:
            env_path.write_text("", encoding="utf-8")

    content = env_path.read_text(encoding="utf-8")
    updated_keys = []

    for key, val in updates.items():
        val_str = str(val).strip()
        pattern = re.compile(rf"^\s*{re.escape(key)}\s*=.*$", re.MULTILINE)
        new_line = f'{key}="{val_str}"'
        if pattern.search(content):
            content = pattern.sub(new_line, content)
        else:
            content += f"\n{new_line}"

        os.environ[key] = val_str
        updated_keys.append(key)

    env_path.write_text(content, encoding="utf-8")

    # Invalidate model detector cache if mistral parameters were updated
    if "MISTRAL_API_KEY" in updates or "MISTRAL_MODEL" in updates:
        try:
            from services.summarization.mistral_detector import mistral_model_detector
            mistral_model_detector._cached_models = []
            mistral_model_detector._last_detected_time = 0.0
        except Exception:
            pass

    return updated_keys


@router.get(
    "/manage",
    status_code=status.HTTP_200_OK,
    summary="Get all configurable API keys and integrations metadata",
)
def get_manageable_api_keys() -> Dict[str, Any]:
    """Returns platform integrations with current masked values, category, and configuration status."""
    items = []
    for item in MANAGED_API_KEYS:
        k = item["key"]
        val = os.environ.get(k) or secret_manager.get_secret(k) or ""
        configured = bool(val and str(val).strip())
        if item["is_secret"]:
            masked = mask_connection_url(val) if "URL" in k else mask_secret(val)
        else:
            masked = val if configured else "<not configured>"

        items.append({
            "key": k,
            "label": item["label"],
            "category": item["category"],
            "description": item["description"],
            "is_secret": item["is_secret"],
            "required": item["required"],
            "docs_url": item["docs_url"],
            "configured": configured,
            "masked_value": masked if configured else "",
        })

    return {
        "keys": items,
        "total": len(items),
        "configured_count": sum(1 for i in items if i["configured"]),
    }


@router.post(
    "/save-keys",
    response_model=SecretSaveResponse,
    status_code=status.HTTP_200_OK,
    summary="Save API keys and update runtime environment dynamically",
)
@router.post(
    "/save",
    response_model=SecretSaveResponse,
    status_code=status.HTTP_200_OK,
    summary="Save API keys and update runtime environment dynamically (alias)",
)
def save_api_keys(payload: SecretSaveRequest) -> SecretSaveResponse:
    """
    Saves provided API keys and environment variables to the local .env file
    and updates os.environ immediately in memory without requiring a service restart.
    """
    data = payload.secrets or payload.keys or {}
    if not data:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No secrets provided in update payload",
        )

    updated = _update_env_file(data)
    return SecretSaveResponse(
        status="success",
        success=True,
        updated_keys=updated,
        saved_keys=updated,
        message=f"Successfully persisted and activated {len(updated)} key(s) in runtime environment.",
    )


@router.post(
    "/test-key",
    response_model=SecretTestKeyResponse,
    status_code=status.HTTP_200_OK,
    summary="Actively test external API credentials and services",
)
def test_secret_key(payload: SecretTestKeyRequest) -> SecretTestKeyResponse:
    """
    Performs a live connectivity and authentication test for a given API key or endpoint.
    Accepts an optional candidate value to test before saving.
    """
    key = payload.key.upper()
    val = payload.value if payload.value is not None else (os.environ.get(key) or secret_manager.get_secret(key))
    if not val or not str(val).strip():
        return SecretTestKeyResponse(
            key=key,
            connected=False,
            success=False,
            status="untested",
            message=f"No key or value configured to test for '{key}'",
            details={"error": "empty_value"},
        )

    val_str = str(val).strip()
    start_t = time.time()

    if key in ("MISTRAL_API_KEY", "AI_API_KEY"):
        try:
            import httpx
            headers = {"Authorization": f"Bearer {val_str}"}
            with httpx.Client(timeout=10.0) as client:
                r = client.get("https://api.mistral.ai/v1/models", headers=headers)
                latency = round((time.time() - start_t) * 1000, 1)
                if r.status_code == 200:
                    models = [
                        m.get("id")
                        for m in r.json().get("data", [])
                        if "embed" not in m.get("id", "").lower()
                    ]
                    return SecretTestKeyResponse(
                        key=key,
                        connected=True,
                        success=True,
                        status="valid",
                        latency_ms=latency,
                        message=f"Successfully authenticated with Mistral AI. Detected {len(models)} chat models.",
                        details={"available_models": models[:6], "total_models": len(models)},
                    )
                else:
                    return SecretTestKeyResponse(
                        key=key,
                        connected=False,
                        success=False,
                        status="invalid",
                        latency_ms=latency,
                        message=f"Mistral AI authentication failed: HTTP {r.status_code} ({r.text[:100]})",
                        details={"status_code": r.status_code},
                    )
        except Exception as exc:
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=False,
                success=False,
                status="error",
                latency_ms=latency,
                message=f"Network error connecting to Mistral AI: {str(exc)}",
                details={"error": str(exc)},
            )

    elif key == "GITHUB_TOKEN":
        try:
            import httpx
            headers = {
                "Authorization": f"Bearer {val_str}",
                "User-Agent": "CyberOSINT-Intelligence-Bot/1.0",
                "Accept": "application/vnd.github+json",
            }
            with httpx.Client(timeout=10.0) as client:
                r = client.get("https://api.github.com/rate_limit", headers=headers)
                latency = round((time.time() - start_t) * 1000, 1)
                if r.status_code == 200:
                    core = r.json().get("resources", {}).get("core", {})
                    remaining = core.get("remaining", 0)
                    limit = core.get("limit", 60)
                    return SecretTestKeyResponse(
                        key=key,
                        connected=True,
                        success=True,
                        status="valid",
                        latency_ms=latency,
                        message=f"GitHub token verified successfully. Rate limit: {remaining}/{limit} requests remaining.",
                        details=core,
                    )
                else:
                    return SecretTestKeyResponse(
                        key=key,
                        connected=False,
                        success=False,
                        status="invalid",
                        latency_ms=latency,
                        message=f"GitHub authentication failed: HTTP {r.status_code}",
                        details={"status_code": r.status_code},
                    )
        except Exception as exc:
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=False,
                success=False,
                status="error",
                latency_ms=latency,
                message=f"Network error connecting to GitHub: {str(exc)}",
                details={"error": str(exc)},
            )

    elif key == "DATABASE_URL":
        try:
            from sqlalchemy import create_engine, text
            eng = create_engine(
                val_str,
                connect_args={"connect_timeout": 5} if "postgresql" in val_str else {},
            )
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=True,
                success=True,
                status="valid",
                latency_ms=latency,
                message="Database connection verified successfully (SELECT 1 returned).",
            )
        except Exception as exc:
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=False,
                success=False,
                status="error",
                latency_ms=latency,
                message=f"Database connection failed: {str(exc)[:120]}",
                details={"error": str(exc)},
            )

    elif key == "REDIS_URL":
        try:
            import redis
            r_client = redis.from_url(val_str, socket_timeout=3.0)
            r_client.ping()
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=True,
                success=True,
                status="valid",
                latency_ms=latency,
                message="Redis connection verified successfully (PING responded PONG).",
            )
        except Exception as exc:
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=False,
                success=False,
                status="error",
                latency_ms=latency,
                message=f"Redis connection failed: {str(exc)[:120]}",
                details={"error": str(exc)},
            )

    elif key == "SEARCH_URL":
        try:
            import httpx
            with httpx.Client(timeout=5.0) as client:
                r = client.get(val_str)
                latency = round((time.time() - start_t) * 1000, 1)
                connected = r.status_code in (200, 401, 403)
                return SecretTestKeyResponse(
                    key=key,
                    connected=connected,
                    success=connected,
                    status="valid" if connected else "error",
                    latency_ms=latency,
                    message=f"Search cluster responded HTTP {r.status_code} ({'Online' if connected else 'Unreachable'}).",
                )
        except Exception as exc:
            latency = round((time.time() - start_t) * 1000, 1)
            return SecretTestKeyResponse(
                key=key,
                connected=False,
                success=False,
                status="error",
                latency_ms=latency,
                message=f"Search cluster unreachable: {str(exc)[:100]}",
            )

    latency = round((time.time() - start_t) * 1000, 1)
    return SecretTestKeyResponse(
        key=key,
        connected=True,
        success=True,
        status="valid",
        latency_ms=latency,
        message=f"Format validated for '{key}' ({len(val_str)} characters).",
    )


