"""Section 48 (Step 47): Version 3 Advanced Intelligence SQLAlchemy Models.

Provides models for:
  1. ThreatActorModel (Threat actor tracking)
  2. MalwareFamilyModel (Malware tracking)
  3. CampaignModel (Campaign tracking)
  4. IncidentTimelineModel (Incident timelines)
  5. CorrelationClusterModel (Cross-source correlation)
  6. LearningPathModel (Learning paths & cybersecurity curricula)
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


class ThreatActorModel(BaseModel):
    """Stores threat actor profiles, nation-state attribution, and TTP mapping."""

    __tablename__ = "threat_actors"

    name = Column(String(255), nullable=False, unique=True, index=True)
    aliases = Column(JSON, default=list, nullable=False)
    country = Column(String(100), nullable=True, index=True)
    motivation = Column(String(100), nullable=True, index=True)  # Espionage, Financial, Sabotage, Hacktivism
    target_sectors = Column(JSON, default=list, nullable=False)
    target_countries = Column(JSON, default=list, nullable=False)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    mitre_group_id = Column(String(50), nullable=True, index=True)  # e.g. G0016
    threat_level = Column(String(50), default="high", nullable=False, index=True)  # critical, high, medium, low
    status = Column(String(50), default="active", nullable=False, index=True)  # active, dormant, disrupted
    description = Column(Text, nullable=True)
    associated_malware = Column(JSON, default=list, nullable=False)
    associated_cves = Column(JSON, default=list, nullable=False)


class MalwareFamilyModel(BaseModel):
    """Stores malware family intelligence, platforms, YARA rules, and sample hashes."""

    __tablename__ = "malware_families"

    name = Column(String(255), nullable=False, unique=True, index=True)
    aliases = Column(JSON, default=list, nullable=False)
    malware_type = Column(String(100), nullable=False, index=True)  # ransomware, infostealer, trojan, loader, backdoor, c2, wiper
    target_platforms = Column(JSON, default=list, nullable=False)   # Windows, Linux, macOS, Android, iOS
    mitre_software_id = Column(String(50), nullable=True, index=True)  # e.g. S0154
    yara_rules = Column(JSON, default=list, nullable=False)
    sample_hashes = Column(JSON, default=list, nullable=False)  # list of {md5, sha1, sha256}
    severity = Column(String(50), default="high", nullable=False, index=True)
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)
    description = Column(Text, nullable=True)
    associated_actors = Column(JSON, default=list, nullable=False)
    associated_cves = Column(JSON, default=list, nullable=False)


class CampaignModel(BaseModel):
    """Stores coordinated malicious campaigns, target scopes, and active periods."""

    __tablename__ = "campaigns"

    name = Column(String(255), nullable=False, unique=True, index=True)
    actor_name = Column(String(255), nullable=True, index=True)
    status = Column(String(50), default="active", nullable=False, index=True)  # active, emerging, historical
    start_date = Column(DateTime(timezone=True), nullable=True)
    end_date = Column(DateTime(timezone=True), nullable=True)
    target_sectors = Column(JSON, default=list, nullable=False)
    target_countries = Column(JSON, default=list, nullable=False)
    malware_used = Column(JSON, default=list, nullable=False)
    cves_exploited = Column(JSON, default=list, nullable=False)
    description = Column(Text, nullable=True)
    confidence_score = Column(Float, default=0.85, nullable=False)


class IncidentTimelineModel(BaseModel):
    """Stores reconstructed chronological incident event sequences with kill-chain phases."""

    __tablename__ = "incident_timelines"

    title = Column(String(512), nullable=False, index=True)
    incident_name = Column(String(255), nullable=False, index=True)
    events = Column(JSON, default=list, nullable=False)  # list of {timestamp, phase, title, description, source_url, iocs, confidence}
    summary = Column(Text, nullable=True)


class CorrelationClusterModel(BaseModel):
    """Stores cross-source intelligence clusters linking disparate feeds to common events."""

    __tablename__ = "correlation_clusters"

    title = Column(String(512), nullable=False, index=True)
    matched_entities = Column(JSON, default=list, nullable=False)  # list of {entity_type, value}
    source_items = Column(JSON, default=list, nullable=False)      # list of {source, title, url, timestamp}
    correlation_score = Column(Float, default=0.9, nullable=False)
    first_observed = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    summary = Column(Text, nullable=True)


class LearningPathModel(BaseModel):
    """Stores structured cybersecurity learning pathways, competencies, and modules."""

    __tablename__ = "learning_paths"

    slug = Column(String(100), nullable=False, unique=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    difficulty = Column(String(50), default="intermediate", nullable=False)  # beginner, intermediate, advanced
    estimated_hours = Column(Integer, default=40, nullable=False)
    role = Column(String(100), nullable=False, index=True)  # SOC Analyst, Threat Hunter, Malware Analyst, etc.
    modules = Column(JSON, default=list, nullable=False)    # list of modules with labs, prerequisites, competencies
