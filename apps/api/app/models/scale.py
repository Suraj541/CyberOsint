"""Section 49 (Step 48): Version 4 Scale SQLAlchemy Models.

Provides models for:
  1. MarketplaceConnectorModel (Community connector marketplace registry)
  2. RegionNodeModel (Multi-region topology & replication nodes)
  3. BenchmarkRunModel (Automated pipeline evaluation runs & drift metrics)
  4. SourceReputationModel (Bayesian source quality & credibility states)
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


class MarketplaceConnectorModel(BaseModel):
    """Stores third-party community connectors, manifests, verification status, and install state."""

    __tablename__ = "marketplace_connectors"

    name = Column(String(255), nullable=False, unique=True, index=True)
    slug = Column(String(255), nullable=False, unique=True, index=True)
    version = Column(String(50), default="1.0.0", nullable=False)
    author = Column(String(255), nullable=False)
    category = Column(String(100), nullable=False, index=True)  # threat_intel, darkweb, cve, cloud, social
    description = Column(Text, nullable=True)
    repository_url = Column(String(500), nullable=True)
    manifest_json = Column(JSON, default=dict, nullable=False)
    is_installed = Column(Boolean, default=False, nullable=False, index=True)
    is_verified = Column(Boolean, default=False, nullable=False, index=True)
    rating = Column(Float, default=5.0, nullable=False)
    downloads_count = Column(Integer, default=0, nullable=False)


class RegionNodeModel(BaseModel):
    """Tracks multi-region deployments, regional datacenter nodes, replication lag, and status."""

    __tablename__ = "region_nodes"

    region_code = Column(String(50), nullable=False, unique=True, index=True)  # us-east-1, eu-central-1, ap-southeast-1
    name = Column(String(255), nullable=False)
    endpoint = Column(String(500), nullable=False)
    role = Column(String(50), default="replica", nullable=False, index=True)  # primary, replica, edge
    status = Column(String(50), default="healthy", nullable=False, index=True)  # healthy, degraded, offline
    latency_ms = Column(Float, default=15.0, nullable=False)
    replication_lag_ms = Column(Float, default=2.5, nullable=False)
    active_connections = Column(Integer, default=120, nullable=False)
    last_heartbeat = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class BenchmarkRunModel(BaseModel):
    """Stores automated evaluation benchmark runs, precision/recall/F1 metrics, and drift flags."""

    __tablename__ = "benchmark_runs"

    suite_name = Column(String(255), nullable=False, index=True)
    dataset_name = Column(String(255), nullable=False)
    total_samples = Column(Integer, default=100, nullable=False)
    precision_score = Column(Float, default=0.95, nullable=False)
    recall_score = Column(Float, default=0.92, nullable=False)
    f1_score = Column(Float, default=0.935, nullable=False)
    p95_latency_ms = Column(Float, default=45.0, nullable=False)
    drift_detected = Column(Boolean, default=False, nullable=False)
    details_json = Column(JSON, default=dict, nullable=False)


class SourceReputationModel(BaseModel):
    """Maintains dynamic Bayesian credibility rankings and reputation tiers for OSINT feeds."""

    __tablename__ = "source_reputations"

    source_name = Column(String(255), nullable=False, unique=True, index=True)
    reputation_score = Column(Float, default=85.0, nullable=False, index=True)  # 0.0 to 100.0
    tier = Column(String(50), default="silver", nullable=False, index=True)  # gold, silver, community, quarantine
    corroboration_rate = Column(Float, default=0.80, nullable=False)  # 0.0 to 1.0
    false_positive_rate = Column(Float, default=0.03, nullable=False)  # 0.0 to 1.0
    latency_rating_ms = Column(Float, default=250.0, nullable=False)
    total_items_evaluated = Column(Integer, default=100, nullable=False)
