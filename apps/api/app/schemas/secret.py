"""
Pydantic Schemas for Secret Management and Security Auditing.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class SecretItemResponse(BaseModel):
    """Information and masked representation of an individual platform secret."""
    key: str = Field(..., description="Secret environment variable name")
    configured: bool = Field(..., description="Whether the secret is actively configured and non-empty")
    masked_value: Optional[str] = Field(None, description="Masked preview of the secret (raw value never exposed)")
    description: str = Field(..., description="Functional purpose and subsystem dependency of the secret")
    required: bool = Field(..., description="Whether this secret is mandatory for basic system operations")
    provider: str = Field("env", description="Secret manager provider (env, vault, aws, encrypted_file)")
    last_checked_at: str = Field(..., description="ISO timestamp of last inspection")


class SecretScanFindingResponse(BaseModel):
    """Security audit finding identifying potentially committed credentials or gitignore violations."""
    severity: str = Field(..., description="Finding severity: critical, warning, info")
    rule: str = Field(..., description="Rule code triggered by finding")
    file_path: str = Field(..., description="Path to offending file")
    description: str = Field(..., description="Detailed description of the finding")
    line_number: Optional[int] = Field(None, description="Line number if applicable")


class SecretAuditResponse(BaseModel):
    """Comprehensive secret management and gitignore compliance audit report."""
    provider: str = Field(..., description="Active secret backend provider name")
    total_tracked: int = Field(..., description="Total tracked mandatory secrets (6 per Section 36)")
    configured_count: int = Field(..., description="Number of configured secrets")
    missing_required_count: int = Field(..., description="Number of missing mandatory secrets")
    is_healthy: bool = Field(..., description="True if all required secrets are configured without critical findings")
    secrets: List[SecretItemResponse] = Field(default_factory=list, description="List of individual secret statuses")
    gitignore_compliant: bool = Field(..., description="True if .gitignore correctly blocks .env and private certificates")
    findings: List[SecretScanFindingResponse] = Field(default_factory=list, description="Security scanner audit findings")
    verified_patterns: List[str] = Field(default_factory=list, description="List of verified gitignore patterns")
    audited_at: str = Field(..., description="ISO timestamp when audit was performed")


class SecretVerifyRequest(BaseModel):
    """Request to verify access to a specific secret key without retrieving plaintext."""
    key: str = Field(..., description="Secret key name to verify (e.g. DATABASE_URL, AI_API_KEY, GITHUB_TOKEN)")


class SecretVerifyResponse(BaseModel):
    """Result of verifying a secret key."""
    key: str = Field(..., description="Verified secret key name")
    configured: bool = Field(..., description="Whether secret is present and non-empty")
    accessible: bool = Field(..., description="Whether secret manager could read the secret")
    provider: str = Field(..., description="Secret manager provider that answered query")
    masked_preview: Optional[str] = Field(None, description="Masked preview of secret")
    message: str = Field(..., description="Human-readable verification result")


class SecretSaveRequest(BaseModel):
    """Payload containing API keys and environment variables to update."""
    secrets: Optional[dict] = Field(default_factory=dict, description="Dictionary of secret key-value pairs to persist")
    keys: Optional[dict] = Field(default_factory=dict, description="Alias for secrets payload field")


class SecretSaveResponse(BaseModel):
    """Response confirming persistence and runtime activation of secrets."""
    status: str = Field("success", description="Update status (success or error)")
    success: bool = Field(True, description="Boolean success indicator for frontend compatibility")
    updated_keys: List[str] = Field(default_factory=list, description="List of updated key names")
    saved_keys: List[str] = Field(default_factory=list, description="Alias for updated_keys for frontend client")
    message: str = Field(..., description="Summary confirmation message")


class SecretTestKeyRequest(BaseModel):
    """Payload to test connection for a specific secret key/token."""
    key: str = Field(..., description="Key name to test (e.g. MISTRAL_API_KEY, GITHUB_TOKEN, AI_API_KEY)")
    value: Optional[str] = Field(None, description="Optional raw candidate value to test before saving")


class SecretTestKeyResponse(BaseModel):
    """Result of active connectivity and authentication testing."""
    key: str = Field(..., description="Tested secret key name")
    connected: bool = Field(..., description="Whether connection test succeeded")
    success: bool = Field(True, description="Boolean success indicator for frontend client")
    status: str = Field("valid", description="Deterministic status string (valid, invalid, error, untested)")
    latency_ms: Optional[float] = Field(None, description="Roundtrip latency in milliseconds")
    message: str = Field(..., description="Human-readable test result and diagnostic message")
    details: Optional[dict] = Field(default_factory=dict, description="Additional provider metadata or diagnostics")

