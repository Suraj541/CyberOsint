"""Section 48 (Step 47): Version 3 Advanced Intelligence Pydantic Schemas.

Covers:
  - Threat Actor Tracking schemas
  - Malware Tracking schemas
  - Campaign Tracking schemas
  - Incident Timeline schemas
  - Cross-Source Correlation schemas
  - Learning Paths schemas
  - AI Research Assistant request/response schemas
  - High-level Intelligence Overview schemas
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ─── Threat Actor Schemas ──────────────────────────────────────────────────────
class ThreatActorBase(BaseModel):
    name: str = Field(..., description="Canonical actor name, e.g. APT29")
    aliases: List[str] = Field(default_factory=list, description="Common aliases, e.g. Cozy Bear, Nobelium")
    country: Optional[str] = Field(default=None, description="Country of origin or attribution")
    motivation: Optional[str] = Field(default="Espionage", description="Primary motivation")
    target_sectors: List[str] = Field(default_factory=list, description="Targeted industry sectors")
    target_countries: List[str] = Field(default_factory=list, description="Targeted nation states")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    mitre_group_id: Optional[str] = Field(default=None, description="MITRE ATT&CK Group ID, e.g. G0016")
    threat_level: str = Field(default="high", description="Threat level: critical, high, medium, low")
    status: str = Field(default="active", description="Operational status: active, dormant, disrupted")
    description: Optional[str] = None
    associated_malware: List[str] = Field(default_factory=list)
    associated_cves: List[str] = Field(default_factory=list)


class ThreatActorCreate(ThreatActorBase):
    pass


class ThreatActorOut(ThreatActorBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Malware Tracking Schemas ──────────────────────────────────────────────────
class MalwareFamilyBase(BaseModel):
    name: str = Field(..., description="Canonical malware name, e.g. Cobalt Strike")
    aliases: List[str] = Field(default_factory=list)
    malware_type: str = Field(..., description="ransomware, infostealer, trojan, loader, backdoor, wiper")
    target_platforms: List[str] = Field(default_factory=lambda: ["Windows"])
    mitre_software_id: Optional[str] = Field(default=None, description="MITRE Software ID, e.g. S0154")
    yara_rules: List[str] = Field(default_factory=list)
    sample_hashes: List[Dict[str, str]] = Field(default_factory=list)
    severity: str = Field(default="high")
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    description: Optional[str] = None
    associated_actors: List[str] = Field(default_factory=list)
    associated_cves: List[str] = Field(default_factory=list)


class MalwareFamilyCreate(MalwareFamilyBase):
    pass


class MalwareFamilyOut(MalwareFamilyBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Campaign Tracking Schemas ─────────────────────────────────────────────────
class CampaignBase(BaseModel):
    name: str = Field(..., description="Campaign name, e.g. Operation SolarWinds")
    actor_name: Optional[str] = Field(default=None, description="Attributed threat actor")
    status: str = Field(default="active", description="active, emerging, historical")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    target_sectors: List[str] = Field(default_factory=list)
    target_countries: List[str] = Field(default_factory=list)
    malware_used: List[str] = Field(default_factory=list)
    cves_exploited: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)


class CampaignCreate(CampaignBase):
    pass


class CampaignOut(CampaignBase):
    id: int
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Incident Timeline Schemas ─────────────────────────────────────────────────
class TimelineEvent(BaseModel):
    timestamp: str = Field(..., description="ISO timestamp or date string of the event")
    phase: str = Field(..., description="Initial Access, Execution, Persistence, Exfiltration, etc.")
    title: str = Field(..., description="Event milestone title")
    description: str = Field(..., description="Detailed event summary")
    source_url: Optional[str] = None
    iocs: List[str] = Field(default_factory=list)
    confidence: float = Field(default=0.9, ge=0.0, le=1.0)


class IncidentTimelineCreate(BaseModel):
    title: str
    incident_name: str
    events: List[TimelineEvent]
    summary: Optional[str] = None


class IncidentTimelineOut(BaseModel):
    id: int
    title: str
    incident_name: str
    events: List[TimelineEvent]
    summary: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Cross-Source Correlation Schemas ──────────────────────────────────────────
class CorrelationSourceItem(BaseModel):
    source: str
    title: str
    url: str
    timestamp: str
    snippet: Optional[str] = None


class CorrelationClusterOut(BaseModel):
    id: int
    title: str
    matched_entities: List[Dict[str, Any]]
    source_items: List[CorrelationSourceItem]
    correlation_score: float
    first_observed: datetime
    last_updated: datetime
    summary: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# ─── Learning Paths Schemas ────────────────────────────────────────────────────
class LearningModule(BaseModel):
    id: str
    title: str
    description: str
    duration_hours: int
    competencies: List[str]
    lab_exercise: Optional[str] = None
    linked_content_ids: List[int] = Field(default_factory=list)


class LearningPathOut(BaseModel):
    id: int
    slug: str
    title: str
    description: str
    difficulty: str
    estimated_hours: int
    role: str
    modules: List[LearningModule]

    model_config = ConfigDict(from_attributes=True)


# ─── AI Research Assistant Schemas ─────────────────────────────────────────────
class ResearchAssistantRequest(BaseModel):
    query: str = Field(..., description="Investigation question, e.g. Analyze Volt Typhoon living-off-the-land techniques")
    focus_areas: List[str] = Field(default_factory=lambda: ["threat_actors", "cves", "tactics", "mitigations"])
    max_sources: int = Field(default=5, ge=1, le=20)


class ResearchFinding(BaseModel):
    topic: str
    summary: str
    confidence: float
    evidence_sources: List[str]


class ResearchAssistantDossier(BaseModel):
    query: str
    executive_summary: str
    threat_actor_profile: Optional[Dict[str, Any]] = None
    key_findings: List[ResearchFinding]
    attack_path_milestones: List[str]
    recommended_mitigations: List[str]
    citations: List[Dict[str, str]]
    generated_at: str


# ─── Intelligence Overview ─────────────────────────────────────────────────────
class IntelligenceOverviewOut(BaseModel):
    total_threat_actors: int
    active_threat_actors: int
    total_malware_families: int
    active_campaigns: int
    incident_timelines_count: int
    correlated_clusters_count: int
    learning_paths_count: int
    top_threat_actors: List[ThreatActorOut]
    recent_campaigns: List[CampaignOut]
