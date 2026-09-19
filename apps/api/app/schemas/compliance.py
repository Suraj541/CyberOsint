"""Section 50 (Step 49): Compliance, Readiness & Definition of Done Pydantic Schemas.

Covers schemas for:
  1. Definition of Done (31/31 checklist verification)
  2. Recommended Development Order (40/40 milestone verification)
  3. Section 52 Critical Architecture Pipeline Audit
  4. System Readiness Overview & Historical Reports
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── 1. Definition of Done Schemas ─────────────────────────────────────────────
class DoDCheckItem(BaseModel):
    """Represents a single criterion check from Section 51 Definition of Done."""

    id: str = Field(..., description="Criterion identifier (e.g. dod_01_sources_register)")
    criterion_number: int = Field(..., description="1-indexed sequence number (1-31)")
    category: str = Field(..., description="Domain category (Ingestion, Normalization, Search, Intelligence, Security, Operations)")
    title: str = Field(..., description="Short title of the requirement")
    description: str = Field(..., description="Exact requirement from Section 51 of IMPLEMENT.md")
    passed: bool = Field(..., description="Whether live programmatic verification succeeded")
    evidence: str = Field(..., description="Live evidence string, metric, or entity trace confirming verification")
    latency_ms: float = Field(0.0, description="Verification execution time in milliseconds")


class DoDVerificationResponse(BaseModel):
    """Aggregate response for live Section 51 Definition of Done verification."""

    status: str = Field(..., description="Overall status: PASSED, WARNING, FAILED")
    total_criteria: int = Field(31, description="Total criteria defined in Section 51")
    passed_criteria: int = Field(..., description="Count of criteria meeting passing thresholds")
    score_pct: float = Field(..., description="Percentage of criteria passed (e.g., 100.0)")
    verified_at: str = Field(..., description="ISO 8601 timestamp of verification")
    items: List[DoDCheckItem] = Field(..., description="Detailed verification result for each of the 31 criteria")


# ── 2. Development Order (40 Milestones) Schemas ──────────────────────────────
class MilestoneVerificationItem(BaseModel):
    """Verification item for one of the 40 steps from Section 50."""

    step_number: int = Field(..., description="Step number 1 to 40")
    code: str = Field(..., description="Two-digit code (e.g. 01, 15, 40)")
    name: str = Field(..., description="Milestone title (e.g. RSS connector, Knowledge graph)")
    category: str = Field(..., description="Milestone group (Core, Pipeline, Intelligence, Ops)")
    implemented: bool = Field(True, description="Whether milestone implementation is verified")
    module_path: str = Field(..., description="Primary module or package implementing this milestone")
    test_suite: str = Field(..., description="Corresponding test file verifying this milestone")
    status: str = Field("VERIFIED", description="Operational status: VERIFIED, PARTIAL, PENDING")


class MilestoneVerificationResponse(BaseModel):
    """Response aggregating all 40 milestones from Section 50."""

    status: str = Field(..., description="Overall milestone status")
    total_milestones: int = Field(40, description="Total milestones in development order")
    completed_milestones: int = Field(..., description="Count of verified completed milestones")
    completion_pct: float = Field(..., description="Completion percentage")
    milestones: List[MilestoneVerificationItem] = Field(..., description="List of 40 milestones")


# ── 3. Critical Architecture Pipeline Trace Schemas ───────────────────────────
class PipelineTraceItem(BaseModel):
    """Trace result for each stage of Section 52 Critical Engineering Rule."""

    stage_order: int = Field(..., description="Execution sequence number (1-10)")
    stage_name: str = Field(..., description="Stage name (e.g. Sources, Normalization, Knowledge Graph)")
    input_desc: str = Field(..., description="Input data contract")
    output_desc: str = Field(..., description="Output artifact / state contract")
    passed: bool = Field(True, description="Whether stage executed and verified data integrity")
    execution_time_ms: float = Field(..., description="Stage latency in milliseconds")
    provenance_intact: bool = Field(True, description="Whether source URL and cryptographic hash were preserved")
    details: Dict[str, Any] = Field(default_factory=dict, description="Telemetry details")


class PipelineAuditResponse(BaseModel):
    """End-to-end trace verification across all 10 stages of the Critical Architecture."""

    pipeline_integrity: str = Field(..., description="Overall integrity: VERIFIED, DEGRADED, BROKEN")
    stages_total: int = Field(10, description="Total stages traversed")
    stages_passed: int = Field(..., description="Count of stages passing integrity validation")
    total_duration_ms: float = Field(..., description="Total round-trip pipeline latency")
    synthetic_threat_cve: str = Field(..., description="Synthetic threat CVE tracked through the pipeline")
    provenance_verified: bool = Field(True, description="Whether cryptographic provenance remained intact end-to-end")
    traces: List[PipelineTraceItem] = Field(..., description="Trace results per stage")


# ── 4. System Readiness Overview & Reports ────────────────────────────────────
class ComplianceReportOut(BaseModel):
    """Historical audit report record."""

    id: int
    audit_id: str
    status: str
    dod_total_criteria: int
    dod_passed_criteria: int
    dod_score_pct: float
    milestones_total: int
    milestones_passed: int
    pipeline_integrity: str
    summary: Optional[str] = None
    executed_by: str
    execution_time_ms: float
    audit_timestamp: Any

    class Config:
        from_attributes = True


class SystemReadinessOverview(BaseModel):
    """Master readiness dashboard aggregation."""

    overall_readiness_score: float = Field(..., description="Overall platform readiness score (0-100)")
    readiness_tier: str = Field(..., description="Tier: PRODUCTION_CERTIFIED, STAGING_READY, IN_DEVELOPMENT")
    dod_passed_criteria: int = Field(31, description="DoD criteria passed")
    dod_total_criteria: int = Field(31, description="DoD criteria total")
    milestones_completed: int = Field(40, description="Milestones completed")
    milestones_total: int = Field(40, description="Milestones total")
    pipeline_integrity: str = Field("VERIFIED", description="Critical pipeline integrity status")
    active_sources_count: int = Field(..., description="Count of registered OSINT sources")
    active_connectors_count: int = Field(..., description="Active connector modules")
    security_controls_active: int = Field(..., description="Active defensive security controls")
    test_suites_passed_ratio: float = Field(1.0, description="Test suite pass ratio across all stages")
    last_audit_timestamp: str = Field(..., description="Timestamp of latest readiness audit")


# ── 5. Definition of Done Certification Schemas (Section 51 / Step 50) ───────
class DoDCertificateProofItem(BaseModel):
    """Cryptographic proof and status for a single Section 51 criterion."""

    criterion_number: int = Field(..., description="1-indexed sequence number (1-31)")
    id: str = Field(..., description="Unique criterion identifier")
    title: str = Field(..., description="Title of the criterion as defined in Section 51")
    category: str = Field(..., description="Domain category")
    passed: bool = Field(True, description="Whether criterion passed live verification")
    evidence: str = Field(..., description="Operational evidence summary")
    latency_ms: float = Field(0.0, description="Execution latency in ms")
    proof_hash: str = Field(..., description="SHA-256 fingerprint of the verification proof")
    verified_at: str = Field(..., description="Timestamp of verification")


class DoDCertificateOut(BaseModel):
    """Cryptographically signed Section 51 Definition of Done Certificate."""

    certificate_id: str = Field(..., description="Unique certificate identifier")
    status: str = Field(..., description="Certification status: CERTIFIED, DEGRADED")
    certified_by: str = Field(..., description="Authority name issuing the certification")
    system_version: str = Field("1.0.0-GA", description="Certified system software version")
    compliance_score_pct: float = Field(100.0, description="Compliance score percentage")
    total_criteria: int = Field(31, description="Total criteria evaluated")
    passed_criteria: int = Field(31, description="Passed criteria count")
    failed_criteria: int = Field(0, description="Failed criteria count")
    pipeline_integrity: str = Field("VERIFIED", description="Critical pipeline integrity status")
    sha256_signature: str = Field(..., description="HMAC-SHA256 signature sealing the audit record")
    executed_by: str = Field("system_auditor", description="Actor or service that triggered audit")
    issued_at: Any = Field(..., description="Certificate issuance timestamp")
    checklist_proofs: Optional[List[DoDCertificateProofItem]] = Field(default=None, description="Detailed proofs for all 31 criteria")
    markdown_certificate: Optional[str] = Field(default=None, description="Full rendered Markdown certification document")

    class Config:
        from_attributes = True


class DoDCertifyRequest(BaseModel):
    """Request payload to trigger and issue a fresh signed certificate."""

    executed_by: str = Field("lead_system_auditor", description="Name/role of the certifier")
    force_fresh_audit: bool = Field(True, description="Force a live re-evaluation of all 31 criteria")


class DoDCertificateVerifyRequest(BaseModel):
    """Payload to verify an existing certificate's cryptographic signature."""

    certificate_id: str = Field(..., description="Certificate ID to verify")
    issued_at: str = Field(..., description="Issuance timestamp")
    total_criteria: int = Field(31, description="Total criteria count")
    passed_criteria: int = Field(31, description="Passed criteria count")
    compliance_score_pct: float = Field(100.0, description="Compliance score")
    sha256_signature: str = Field(..., description="Signature to verify")
    checklist_proofs: List[Dict[str, Any]] = Field(..., description="Checklist proofs with hashes")


class DoDCertificateVerifyOut(BaseModel):
    """Result of certificate cryptographic verification."""

    valid: bool = Field(..., description="Whether digital signature matches and is untampered")
    certificate_id: str = Field(..., description="Verified certificate ID")
    status: str = Field(..., description="VERIFIED, INVALID_SIGNATURE, CORRUPTED")
    message: str = Field(..., description="Detailed explanation of verification outcome")


# ── 6. Section 52 Critical Architecture Schemas (Step 51) ─────────────────────
class DAGNodeInfo(BaseModel):
    """DAG node representation in Section 52 architecture."""

    id: str
    name: str
    layer: int
    branch: str
    description: str
    contract: str
    anti_pattern_role: str


class DAGEdgeInfo(BaseModel):
    """DAG directed edge representation."""

    source: str
    target: str


class DAGSplitInfo(BaseModel):
    """DAG triad split/join description."""

    name: str
    split_from: str
    branches: List[str]
    join_to: str


class DAGTopologyOut(BaseModel):
    """Full DAG topology for Section 52 visualization."""

    title: str
    specification: str
    prohibited_anti_pattern: str
    nodes_count: int
    edges_count: int
    nodes: List[DAGNodeInfo]
    edges: List[DAGEdgeInfo]
    triad_splits: List[DAGSplitInfo]


class ArchitectureStageTrace(BaseModel):
    """Single stage execution trace in Section 52 DAG."""

    stage_id: str
    stage_name: str
    layer: int
    branch: str
    status: str
    passed: bool
    execution_time_ms: float
    provenance_hash: str
    provenance_intact: bool
    input_contract: str
    output_contract: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ArchitectureAntiPatternGuardItem(BaseModel):
    """Audit item for anti-pattern prevention guard."""

    guard_id: str
    name: str
    prohibited_action: str
    status: str
    prevented: bool
    enforcement_mechanism: str
    evidence: str


class ArchitectureAntiPatternResponse(BaseModel):
    """Response verifying detection & rejection of 'Crawler -> Database -> Website'."""

    anti_pattern_guard_status: str
    prohibited_architecture: str
    guards_total: int
    guards_enforced: int
    all_anti_patterns_blocked: bool
    guards: List[ArchitectureAntiPatternGuardItem]


class ArchitectureAuditOut(BaseModel):
    """Execution trace and compliance status of Section 52 Critical Architecture."""

    audit_id: str
    audit_timestamp: Any
    architecture_status: str
    stages_count: int
    stages_passed: int
    triad_processing_passed: bool
    triad_delivery_passed: bool
    provenance_intact: bool
    anti_patterns_checked: int
    anti_patterns_prevented: int
    prohibited_architecture: str
    target_cve: str
    source_name: str
    execution_time_ms: float
    dag_traces: Optional[List[ArchitectureStageTrace]] = None
    anti_patterns: Optional[List[ArchitectureAntiPatternGuardItem]] = None
    executed_by: str = "critical_architecture_engine"

    class Config:
        from_attributes = True


class PluggableSourceTestRequest(BaseModel):
    """Payload to test zero-code ingestion of a novel source."""

    custom_source_name: str = Field("Honeypot Zero-Day Telemetry", description="Name of the new novel OSINT source")
    custom_url: str = Field("https://internal-honeypot.local/feed/alert-9012", description="Discovered source URL")
    custom_payload: Optional[str] = Field(None, description="Raw payload text from the novel source")


class PluggableSourceTestOut(BaseModel):
    """Verification result confirming zero-code addition of a new source."""

    pluggable_source_test_status: str
    custom_source_name: str
    custom_url: str
    zero_code_change_verified: bool
    schema_modification_required: bool
    api_modification_required: bool
    frontend_modification_required: bool
    stages_traversed: int
    stages_passed: int
    execution_time_ms: float
    provenance_hash: str
    triad_processing_verified: bool
    triad_delivery_verified: bool
    message: str


# ── 7. Section 53 Immediate First Milestone Golden Pipeline Schemas (Step 52) ──
class GoldenPipelineStepTrace(BaseModel):
    """Step execution trace within the Section 53 10-step Golden Pipeline."""

    step_order: int
    step_name: str
    layer: str
    status: str
    passed: bool
    execution_time_ms: float
    output_contract: str
    details: Dict[str, Any] = Field(default_factory=dict)


class GoldenPipelineRunRequest(BaseModel):
    """Payload to trigger an end-to-end Section 53 Golden Pipeline benchmark execution."""

    feed_source: Optional[str] = Field("https://cve.mitre.org/data/rss/cyber_advisory.xml", description="Target RSS feed URL")
    target_cve: Optional[str] = Field("CVE-2024-3400", description="Target CVE ID to verify through the pipeline")
    persist: bool = Field(True, description="Persist execution run to the database")


class GoldenPipelineRunResponse(BaseModel):
    """Result of the Section 53 10-step Golden Pipeline execution."""

    run_id: str
    run_timestamp: Any
    status: str
    feed_source: str
    article_title: str
    target_cve: str
    extracted_cves: List[str] = Field(default_factory=list)
    classification_category: str
    content_hash: str
    steps_total: int
    steps_passed: int
    total_duration_ms: float
    search_query_latency_ms: float
    step_traces: List[GoldenPipelineStepTrace] = Field(default_factory=list)
    message: str

    class Config:
        from_attributes = True


class GoldenPipelineStepSpec(BaseModel):
    """Specification item for each step in the Section 53 foundational pipeline."""

    step_order: int
    step_name: str
    layer: str
    component: str
    description: str
    contract: str
    anti_pattern_role: str


class GoldenPipelineSpecificationOut(BaseModel):
    """Formal specification of the 10-step Section 53 Immediate First Milestone."""

    title: str
    section: str
    pipeline_sequence: str
    total_steps: int
    steps: List[GoldenPipelineStepSpec]


