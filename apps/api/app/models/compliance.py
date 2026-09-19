"""Section 50 (Step 49): Compliance, System Readiness & Definition of Done Models.

Provides models for:
  1. ComplianceAuditReportModel (Historical Definition of Done and readiness audit records)
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    Text,
)
from app.models.base import BaseModel


class ComplianceAuditReportModel(BaseModel):
    """Stores full system readiness audit runs and Definition of Done verification results."""

    __tablename__ = "compliance_audit_reports"

    audit_id = Column(String(100), unique=True, nullable=False, index=True)
    status = Column(String(50), default="PASSED", nullable=False, index=True)  # PASSED, FAILED, WARNING
    dod_total_criteria = Column(Integer, default=31, nullable=False)
    dod_passed_criteria = Column(Integer, default=31, nullable=False)
    dod_score_pct = Column(Float, default=100.0, nullable=False)
    milestones_total = Column(Integer, default=40, nullable=False)
    milestones_passed = Column(Integer, default=40, nullable=False)
    pipeline_integrity = Column(String(50), default="VERIFIED", nullable=False)
    summary = Column(Text, nullable=True)
    findings_json = Column(JSON, default=list, nullable=False)
    pipeline_trace_json = Column(JSON, default=list, nullable=False)
    executed_by = Column(String(100), default="system_readiness_engine", nullable=False)
    execution_time_ms = Column(Float, default=0.0, nullable=False)
    audit_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class DoDCertificateModel(BaseModel):
    """Stores cryptographically signed Section 51 Definition of Done Certificates."""

    __tablename__ = "dod_certificates"

    certificate_id = Column(String(100), unique=True, nullable=False, index=True)
    status = Column(String(50), default="CERTIFIED", nullable=False, index=True)  # CERTIFIED, DEGRADED
    certified_by = Column(String(150), nullable=False)
    system_version = Column(String(50), default="1.0.0-GA", nullable=False)
    compliance_score_pct = Column(Float, default=100.0, nullable=False)
    total_criteria = Column(Integer, default=31, nullable=False)
    passed_criteria = Column(Integer, default=31, nullable=False)
    failed_criteria = Column(Integer, default=0, nullable=False)
    pipeline_integrity = Column(String(50), default="VERIFIED", nullable=False)
    sha256_signature = Column(String(128), nullable=False)
    checklist_proofs_json = Column(JSON, default=list, nullable=False)
    markdown_certificate = Column(Text, nullable=False)
    executed_by = Column(String(100), default="system_auditor", nullable=False)
    issued_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    @property
    def checklist_proofs(self):
        return self.checklist_proofs_json


class ArchitectureAuditModel(BaseModel):
    """Stores Section 52 Critical Engineering Architecture execution traces and anti-pattern guard audits."""

    __tablename__ = "architecture_audits"

    audit_id = Column(String(100), unique=True, nullable=False, index=True)
    architecture_status = Column(String(50), default="COMPLIANT", nullable=False, index=True)  # COMPLIANT, VIOLATED
    stages_count = Column(Integer, default=10, nullable=False)
    stages_passed = Column(Integer, default=10, nullable=False)
    triad_processing_passed = Column(Boolean, default=True, nullable=False)
    triad_delivery_passed = Column(Boolean, default=True, nullable=False)
    provenance_intact = Column(Boolean, default=True, nullable=False)
    anti_patterns_checked = Column(Integer, default=4, nullable=False)
    anti_patterns_prevented = Column(Integer, default=4, nullable=False)
    prohibited_architecture = Column(String(100), default="Crawler -> Database -> Website", nullable=False)
    target_cve = Column(String(100), default="CVE-2024-3400", nullable=False)
    source_name = Column(String(150), default="CISA KEV Feed", nullable=False)
    execution_time_ms = Column(Float, default=0.0, nullable=False)
    dag_traces_json = Column(JSON, default=list, nullable=False)
    anti_patterns_json = Column(JSON, default=list, nullable=False)
    executed_by = Column(String(100), default="critical_architecture_engine", nullable=False)
    audit_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    @property
    def dag_traces(self):
        return self.dag_traces_json

    @property
    def anti_patterns(self):
        return self.anti_patterns_json


class GoldenPipelineRunModel(BaseModel):
    """Stores Section 53 Immediate First Milestone golden pipeline execution runs and step traces."""

    __tablename__ = "golden_pipeline_runs"

    run_id = Column(String(100), unique=True, index=True, nullable=False)
    status = Column(String(50), default="PASSED", nullable=False)
    feed_source = Column(String(255), nullable=False)
    article_title = Column(String(500), nullable=False)
    target_cve = Column(String(100), nullable=False)
    extracted_cves_json = Column(JSON, default=list, nullable=False)
    classification_category = Column(String(100), nullable=False)
    content_hash = Column(String(128), nullable=False)
    steps_total = Column(Integer, default=10, nullable=False)
    steps_passed = Column(Integer, default=10, nullable=False)
    search_indexed = Column(Boolean, default=True, nullable=False)
    query_latency_ms = Column(Float, default=0.0, nullable=False)
    total_duration_ms = Column(Float, default=0.0, nullable=False)
    step_traces_json = Column(JSON, default=list, nullable=False)
    executed_by = Column(String(100), default="golden_pipeline_engine", nullable=False)
    run_timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    @property
    def step_traces(self):
        return self.step_traces_json

    @property
    def extracted_cves(self):
        return self.extracted_cves_json

    @property
    def search_query_latency_ms(self):
        return self.query_latency_ms

    @property
    def message(self):
        return (
            f"Section 53 Immediate First Milestone pipeline run '{self.run_id}' "
            f"completed with status {self.status}. "
            f"{self.steps_passed}/{self.steps_total} steps passed in {self.total_duration_ms:.1f}ms."
        )


