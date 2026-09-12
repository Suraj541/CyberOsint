"""
MITRE ATT&CK Pydantic Schemas
Defines request and response schemas for MITRE ATT&CK REST endpoints.
Conforms strictly to IMPLEMENT.md Section 26.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class MitreTacticOut(BaseModel):
    id: str
    name: str
    description: str
    order: int
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreTechniqueOut(BaseModel):
    id: str
    name: str
    description: str
    tactic_id: str
    tactic_name: Optional[str] = None
    parent_technique_id: Optional[str] = None
    is_subtechnique: bool = False
    platforms: List[str] = []
    data_sources: List[str] = []
    detection_methods: Optional[str] = None
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreGroupOut(BaseModel):
    id: str
    name: str
    aliases: List[str] = []
    description: str
    associated_techniques: List[str] = []
    associated_software: List[str] = []
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreSoftwareOut(BaseModel):
    id: str
    name: str
    software_type: str
    aliases: List[str] = []
    description: str
    associated_techniques: List[str] = []
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreMitigationOut(BaseModel):
    id: str
    name: str
    description: str
    associated_techniques: List[str] = []
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreDataSourceOut(BaseModel):
    id: str
    name: str
    description: str
    collection_layers: List[str] = []
    associated_techniques: List[str] = []
    url: Optional[str] = None

    class Config:
        from_attributes = True


class MitreRelationshipOut(BaseModel):
    source_id: str
    source_type: str
    relationship: str
    target_id: str
    target_type: str
    description: Optional[str] = None
    confidence: float = 1.0

    class Config:
        from_attributes = True


class MitreTechniqueDetailOut(BaseModel):
    technique: MitreTechniqueOut
    tactic: Optional[MitreTacticOut] = None
    subtechniques: List[MitreTechniqueOut] = []
    threat_actors: List[MitreGroupOut] = []
    software: List[MitreSoftwareOut] = []
    mitigations: List[MitreMitigationOut] = []
    data_sources: List[MitreDataSourceOut] = []


class MitreTechniqueWithSubs(BaseModel):
    technique: MitreTechniqueOut
    subtechniques: List[MitreTechniqueOut] = []


class MitreMatrixColumnOut(BaseModel):
    tactic: MitreTacticOut
    techniques_count: int
    total_techniques_count: int
    techniques: List[MitreTechniqueWithSubs] = []


class MitreMatrixResponse(BaseModel):
    matrix: List[MitreMatrixColumnOut]
    total_tactics: int
    total_techniques: int
