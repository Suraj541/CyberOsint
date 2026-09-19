"""
Pydantic Schemas for Advanced OSINT Connectors.
Conforms strictly to IMPLEMENT.md Section 34 (Step 33: Add Advanced OSINT Connectors).
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ConnectorToggleRequest(BaseModel):
    """Request payload to toggle independent connector enabled/disabled state."""
    enabled: bool = Field(..., description="Whether the connector should be enabled")


class ConnectorInfoResponse(BaseModel):
    """Information and runtime telemetry for a prioritized OSINT connector."""
    id: str = Field(..., description="Unique connector identifier")
    priority: int = Field(..., description="Strict priority rank from 1 to 11")
    name: str = Field(..., description="Human-readable connector name")
    category: str = Field(..., description="Mandated OSINT category")
    description: str = Field(..., description="Connector description and target feeds")
    connector_class: str = Field(..., description="Underlying Python connector class name")
    is_enabled: bool = Field(..., description="Whether connector is currently active")
    interval_minutes: Optional[int] = Field(60, description="Configured polling interval in minutes")
    priority_label: Optional[str] = Field("medium", description="Configured priority level (critical, high, medium, low)")
    url: Optional[str] = Field(None, description="Configured source URL")
    api_key_env: Optional[str] = Field(None, description="Configured API key environment variable name")
    last_run: Optional[str] = Field(None, description="ISO timestamp of last execution")
    last_started_at: Optional[str] = Field(None, description="ISO timestamp when execution started")
    last_finished_at: Optional[str] = Field(None, description="ISO timestamp when execution completed")
    last_success_at: Optional[str] = Field(None, description="ISO timestamp of last successful execution")
    last_error_at: Optional[str] = Field(None, description="ISO timestamp of last error")
    last_error: Optional[str] = Field(None, description="Error message from last failure")
    next_run_at: Optional[str] = Field(None, description="ISO timestamp of next scheduled execution")
    last_status: str = Field("idle", description="Last execution status: idle, running, success, error")
    items_count: int = Field(0, description="Total items discovered during last run")
    items_fetched: int = Field(0, description="Items fetched from source")
    items_processed: int = Field(0, description="Items parsed and processed")
    items_inserted: int = Field(0, description="Items inserted into database")
    items_updated: int = Field(0, description="Items updated in database")
    items_duplicate: int = Field(0, description="Duplicate items identified")
    items_failed: int = Field(0, description="Failed item count")
    execution_duration_ms: float = Field(0.0, description="Duration of last execution in milliseconds")


class ConnectorRunResponse(BaseModel):
    """Result of running a single connector."""
    id: str
    status: str
    items_count: int
    executed_at: str
    items: List[Dict[str, Any]] = Field(default_factory=list)


class ConnectorBatchSummaryItem(BaseModel):
    """Summary of execution for a single connector in a prioritized batch."""
    id: str
    priority: int
    status: str
    items_count: int
    error: Optional[str] = None


class ConnectorBatchRunResponse(BaseModel):
    """Result of executing all enabled connectors in strict priority order (1-11)."""
    total_items_discovered: int
    executed_connectors: int
    skipped_connectors: int
    failed_connectors: int
    priority_execution_order: List[str]
    batch_summary: List[ConnectorBatchSummaryItem]
    executed_at: str


class ConnectorHealthSummaryResponse(BaseModel):
    """Aggregated health status across all 11 prioritized connectors."""
    total_connectors: int
    healthy_count: int
    results: Dict[str, Any]
    checked_at: str


# ============================================================================
# Section 35 (Step 34): Declarative Connector Configuration Schemas
# ============================================================================

class ConnectorYamlConfigItem(BaseModel):
    """Parsed configuration entry from connectors.yaml."""
    key: str = Field(..., description="Unique key for the connector in connectors.yaml")
    enabled: bool = Field(True, description="Whether connector is enabled")
    type: str = Field(..., description="Connector protocol type: rss, cert, cve, vendor, blog, github, etc.")
    category: Optional[str] = Field(None, description="Associated OSINT category")
    url: Optional[str] = Field(None, description="Source feed or endpoint URL")
    interval_minutes: int = Field(60, ge=1, le=10080, description="Polling schedule interval in minutes")
    priority: str = Field("medium", description="Priority level: critical, high, medium, low")
    description: Optional[str] = Field(None, description="Human-readable description of source coverage")
    api_key_env: Optional[str] = Field(None, description="Environment variable name for API key (never plaintext)")
    auth_token_env: Optional[str] = Field(None, description="Environment variable name for auth token")
    timeout: float = Field(30.0, description="HTTP request timeout in seconds")
    options: Dict[str, Any] = Field(default_factory=dict, description="Additional connector-specific options")


class ConnectorsYamlResponse(BaseModel):
    """Response containing all parsed connectors from connectors.yaml."""
    total: int = Field(..., description="Total connectors configured")
    connectors: List[ConnectorYamlConfigItem] = Field(..., description="List of configured connectors")
    last_loaded_at: Optional[str] = Field(None, description="ISO timestamp when configuration was loaded")


class RawYamlConfigRequest(BaseModel):
    """Request payload to write and persist new raw connectors.yaml content."""
    yaml_content: str = Field(..., description="Raw YAML string defining connectors configuration")


class RawYamlConfigResponse(BaseModel):
    """Response returning raw connectors.yaml content."""
    yaml_content: str = Field(..., description="Raw YAML string defining connectors configuration")
    last_loaded_at: Optional[str] = Field(None, description="ISO timestamp when configuration was loaded")


class ConfigReloadResponse(BaseModel):
    """Response from hot-reloading connectors.yaml and syncing to runtime manager."""
    status: str = Field("success", description="Status of reload operation")
    message: str = Field(..., description="Informational message about reload result")
    total_loaded: int = Field(..., description="Number of connectors loaded from YAML")
    synced_to_runtime: int = Field(..., description="Number of priority categories synchronized")
    reloaded_at: str = Field(..., description="ISO timestamp of reload")


class ConnectorConfigUpdateRequest(BaseModel):
    """Request payload to partially update a single connector's configuration."""
    enabled: Optional[bool] = None
    url: Optional[str] = None
    interval_minutes: Optional[int] = Field(None, ge=1, le=10080)
    priority: Optional[str] = None
    description: Optional[str] = None
    api_key_env: Optional[str] = None
    auth_token_env: Optional[str] = None
    timeout: Optional[float] = Field(None, ge=1.0, le=120.0)
    options: Optional[Dict[str, Any]] = None
