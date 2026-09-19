"""
Pydantic Schemas for Security Hardening and Posture Assessment.
Conforms to IMPLEMENT.md Section 37 (Step 36: Security Hardening).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TokenRequest(BaseModel):
    """User credentials or API key authentication request."""
    username: str = Field(..., description="Username (e.g. admin, analyst, viewer)")
    password_or_key: str = Field(..., description="Account password or API key")


class TokenResponse(BaseModel):
    """JWT Bearer authentication response."""
    access_token: str = Field(..., description="Signed JWT Bearer access token")
    token_type: str = Field("bearer", description="Token protocol type")
    role: str = Field(..., description="Assigned RBAC role")
    scopes: List[str] = Field(default_factory=list, description="Granted permission scopes")
    expires_in_seconds: int = Field(86400, description="Token validity lifetime")


class UserIdentityResponse(BaseModel):
    """Current authenticated user identity and granted scopes."""
    user_id: str
    username: str
    role: str
    scopes: List[str]


class HardeningCheckItem(BaseModel):
    """Status of an individual security hardening control (1 of 15)."""
    id: str = Field(..., description="Identifier for the security control")
    name: str = Field(..., description="Human-readable title of the control")
    category: str = Field(..., description="Domain category: network, identity, data, runtime, audit")
    status: str = Field(..., description="Control status: active, hardened, warning, disabled")
    description: str = Field(..., description="Technical implementation summary")


class SecurityPostureResponse(BaseModel):
    """Overall 15-point security hardening posture report."""
    compliance_score: int = Field(..., description="Calculated security compliance percentage (0-100)")
    total_controls: int = Field(15, description="Total mandated security controls")
    hardened_controls: int = Field(..., description="Number of fully hardened controls")
    controls: List[HardeningCheckItem] = Field(default_factory=list, description="Detailed control scorecard")
    timestamp: str = Field(..., description="ISO timestamp of posture evaluation")


class URLValidationRequest(BaseModel):
    """Target URL to test against SSRF and network security gates."""
    url: str = Field(..., description="Destination URL to inspect")


class URLValidationResponse(BaseModel):
    """SSRF and network safety validation outcome."""
    url: str
    is_safe: bool
    hostname: str
    resolved_ips: List[str]
    violation_reason: Optional[str] = None


class AuditEventResponse(BaseModel):
    """Security audit event record."""
    event_id: str
    timestamp: str
    event_type: str
    actor: str
    role: str
    resource: str
    action: str
    status: str
    client_ip: str
    details: Dict[str, Any] = Field(default_factory=dict)


class SSRFRedirectHopResponse(BaseModel):
    """Details of an individual HTTP redirect hop."""
    hop_index: int = Field(..., description="0-indexed sequence in the redirect chain")
    url: str = Field(..., description="URL requested at this hop")
    hostname: str = Field(..., description="Hostname evaluated")
    status_code: int = Field(..., description="HTTP response status code (e.g. 301, 302, 200)")
    location_target: Optional[str] = Field(default=None, description="Location header target if redirect")
    resolved_ips: List[str] = Field(default_factory=list, description="Resolved IP addresses")
    is_safe: bool = Field(..., description="Whether this hop passed SSRF pre-flight validation")
    violation_reason: Optional[str] = Field(default=None, description="Violation reason if blocked")


class SSRFRedirectValidationRequest(BaseModel):
    """Request payload to trace and validate redirect chain against SSRF."""
    url: str = Field(..., description="Initial source or feed URL to follow")
    max_redirects: int = Field(5, ge=1, le=10, description="Maximum redirect hops to trace")


class SSRFRedirectValidationResponse(BaseModel):
    """Comprehensive multi-hop SSRF validation result."""
    initial_url: str = Field(..., description="Starting URL")
    final_url: Optional[str] = Field(default=None, description="Terminal URL reached")
    is_safe: bool = Field(..., description="True if all hops passed SSRF validation")
    total_hops: int = Field(..., description="Total redirect hops traced")
    hops: List[SSRFRedirectHopResponse] = Field(default_factory=list, description="Individual hop details")
    violation_reason: Optional[str] = Field(default=None, description="SSRF violation message if aborted")


# -----------------------------------------------------------------------------
# Sandboxed Document Processing Schemas (Section 39 Step 38)
# -----------------------------------------------------------------------------

class SandboxPipelineStageResponse(BaseModel):
    """Stage in the 5-stage document processing pipeline."""
    stage_name: str = Field(..., description="Pipeline stage (Worker, Sandbox, Parser, Extracted text, Sanitized result)")
    status: str = Field(..., description="Execution status: success, failed, blocked, skipped")
    duration_ms: float = Field(..., description="Execution duration in milliseconds")
    details: Optional[str] = Field(None, description="Diagnostic details for this stage")


class SandboxSecurityScanResponse(BaseModel):
    """Static security inspection findings for untrusted documents."""
    is_safe: bool = Field(..., description="True if free of active macros, embedded binaries, or exploits")
    detected_type: str = Field(..., description="Identified file format or binary header")
    macros_detected: List[str] = Field(default_factory=list, description="List of detected VBA/XLM macros")
    embedded_programs_detected: List[str] = Field(default_factory=list, description="List of detected embedded executables or /Launch actions")
    unknown_binaries_detected: List[str] = Field(default_factory=list, description="List of detected unknown binaries or spoofed formats")
    decompression_ratio: float = Field(1.0, description="Archive decompression ratio")
    quarantine_status: str = Field("clean", description="quarantine status: clean, quarantined, sanitized")
    rejection_reason: Optional[str] = Field(None, description="Violation reason if quarantined")


class SandboxProcessRequest(BaseModel):
    """Request payload to process an untrusted document in the sandboxed worker."""
    filename: str = Field("document.pdf", description="Document filename with extension")
    content_base64: Optional[str] = Field(None, description="Base64-encoded document bytes")
    content_text: Optional[str] = Field(None, description="Raw text or markdown document content")
    enforce_worker: bool = Field(True, description="Process in isolated worker subprocess")
    timeout_seconds: float = Field(15.0, ge=1.0, le=60.0, description="Worker execution timeout in seconds")


class SandboxProcessResponse(BaseModel):
    """Structured response from the 5-stage sandboxed document processing pipeline."""
    success: bool = Field(..., description="True if document was safely processed without threat violation")
    filename: str = Field(..., description="Original or assigned filename")
    detected_type: str = Field(..., description="Identified file format")
    sanitized_text: str = Field(..., description="Sanitized text output (control chars and scripts neutralized)")
    word_count: int = Field(..., description="Extracted word count")
    char_count: int = Field(..., description="Extracted character count")
    headings: List[str] = Field(default_factory=list, description="Extracted section headings")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extracted document metadata")
    security_scan: Optional[SandboxSecurityScanResponse] = Field(None, description="Security scanner audit findings")
    stages: List[SandboxPipelineStageResponse] = Field(default_factory=list, description="Audit record for each of the 5 pipeline stages")
    worker_pid: Optional[int] = Field(None, description="Process ID of the isolated worker")
    execution_time_ms: float = Field(..., description="Total processing time in milliseconds")
    error: Optional[str] = Field(None, description="Error message if processing failed or was quarantined")


class SandboxStatsResponse(BaseModel):
    """Telemetry metrics from the sandboxed document worker."""
    total_processed: int = Field(..., description="Total documents processed")
    macros_blocked: int = Field(..., description="Count of blocked active macros")
    embedded_programs_blocked: int = Field(..., description="Count of blocked embedded executables")
    unknown_binaries_blocked: int = Field(..., description="Count of blocked unknown binaries")
    clean_documents: int = Field(..., description="Count of clean documents processed")
    quarantined_documents: int = Field(..., description="Count of quarantined documents")
    threat_neutralization_rate: str = Field(..., description="Percentage of malicious documents neutralized")


