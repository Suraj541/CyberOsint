"""
MITRE ATT&CK Domain Models
Defines schema and data structures for MITRE ATT&CK Enterprise Matrix entities:
Tactics, Techniques, Sub-techniques, Groups, Software, Mitigations, Data Sources,
and their directional relationships per IMPLEMENT.md Section 26.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackTactic(BaseModel):
    """MITRE ATT&CK Tactical Phase (e.g. Initial Access, Execution, Persistence)."""

    id: str = Field(..., description="External ID, e.g. TA0001")
    name: str = Field(..., description="Canonical tactic name")
    description: str = Field(default="", description="Detailed narrative of tactical objective")
    order: int = Field(default=1, description="Sequential phase order in kill chain (1-14)")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackTechnique(BaseModel):
    """MITRE ATT&CK Technique or Sub-technique (e.g. T1190, T1059.001)."""

    id: str = Field(..., description="External ID, e.g. T1190 or T1059.001")
    name: str = Field(..., description="Canonical technique name")
    description: str = Field(default="", description="Technical mechanism description")
    tactic_id: str = Field(..., description="Primary parent tactic ID, e.g. TA0001")
    tactic_name: Optional[str] = Field(default=None, description="Human readable tactic name")
    parent_technique_id: Optional[str] = Field(default=None, description="Parent ID if sub-technique (e.g. T1059 for T1059.001)")
    is_subtechnique: bool = Field(default=False, description="True if technique is a granular sub-technique")
    platforms: List[str] = Field(default_factory=list, description="Target platforms: Linux, Windows, macOS, Cloud, Containers")
    data_sources: List[str] = Field(default_factory=list, description="Names or IDs of detecting data sources")
    detection_methods: Optional[str] = Field(default=None, description="Recommended telemetry or rule detection guidance")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackGroup(BaseModel):
    """MITRE ATT&CK Threat Actor Group (e.g. APT29, Lazarus Group, Volt Typhoon)."""

    id: str = Field(..., description="External ID, e.g. G0016")
    name: str = Field(..., description="Primary canonical name, e.g. APT29")
    aliases: List[str] = Field(default_factory=list, description="Known industry aliases (e.g. Cozy Bear, Nobelium)")
    description: str = Field(default="", description="Origin, targeted sectors, and geopolitical profile")
    associated_techniques: List[str] = Field(default_factory=list, description="List of technique IDs utilized by group")
    associated_software: List[str] = Field(default_factory=list, description="List of software IDs deployed by group")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackSoftware(BaseModel):
    """MITRE ATT&CK Software tool or malware family (e.g. Cobalt Strike, Mimikatz, Akira)."""

    id: str = Field(..., description="External ID, e.g. S0154")
    name: str = Field(..., description="Canonical software name")
    software_type: str = Field(default="malware", description="'malware' or 'tool'")
    aliases: List[str] = Field(default_factory=list, description="Software aliases or variant family names")
    description: str = Field(default="", description="Technical capability summary")
    associated_techniques: List[str] = Field(default_factory=list, description="Technique IDs implemented by software")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackMitigation(BaseModel):
    """MITRE ATT&CK Defensive Mitigation (e.g. Multi-factor Authentication, Antivirus)."""

    id: str = Field(..., description="External ID, e.g. M1036")
    name: str = Field(..., description="Mitigation title")
    description: str = Field(default="", description="Remediation or hardening recommendation")
    associated_techniques: List[str] = Field(default_factory=list, description="Technique IDs mitigated by this control")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackDataSource(BaseModel):
    """MITRE ATT&CK Telemetry Data Source (e.g. Process Creation, Network Traffic)."""

    id: str = Field(..., description="External ID, e.g. DS0017")
    name: str = Field(..., description="Data source name")
    description: str = Field(default="", description="Telemetry stream and monitoring surface")
    collection_layers: List[str] = Field(default_factory=list, description="e.g. Host, Network, Cloud, Identity")
    associated_techniques: List[str] = Field(default_factory=list, description="Technique IDs detected by this data source")
    url: Optional[str] = Field(default=None, description="Official MITRE reference URL")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class AttackRelationship(BaseModel):
    """
    Directional ATT&CK relationship edge.
    Supports mandated patterns:
    - Threat Actor (Group) -> uses -> Technique
    - Malware (Software) -> implements -> Technique
    - Technique -> belongs_to -> Tactic
    - Technique -> detected_by -> Data Source
    - Mitigation -> mitigates -> Technique
    """

    source_id: str = Field(..., description="Source entity ID (e.g. G0016, S0154, T1190)")
    source_type: str = Field(..., description="Entity type: group, software, technique, mitigation, data_source")
    relationship: str = Field(..., description="Relationship verb: uses, implements, belongs_to, detected_by, mitigates")
    target_id: str = Field(..., description="Target entity ID (e.g. T1190, TA0001, DS0015)")
    target_type: str = Field(..., description="Entity type: technique, tactic, data_source")
    description: Optional[str] = Field(default=None, description="Contextual notes on how or where the edge applies")
    confidence: float = Field(default=1.0, description="Extraction or association confidence score")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
