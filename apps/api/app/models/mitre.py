"""
MITRE ATT&CK SQLAlchemy Database Models
Stores canonical Enterprise ATT&CK entities and directional relationships:
Tactics, Techniques, Sub-techniques, Groups, Software, Mitigations, Data Sources.
Conforms strictly to IMPLEMENT.md Section 26.
"""

from sqlalchemy import Boolean, Column, Float, Integer, String, Text, UniqueConstraint
from app.models.base import BaseModel


class MitreTacticModel(BaseModel):
    """Stores ATT&CK tactical phases (e.g. Initial Access TA0001)."""

    __tablename__ = "mitre_tactics"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    sort_order = Column(Integer, default=1, nullable=False)
    url = Column(String(500), nullable=True)


class MitreTechniqueModel(BaseModel):
    """Stores ATT&CK techniques and sub-techniques (e.g. T1190, T1059.001)."""

    __tablename__ = "mitre_techniques"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    tactic_id = Column(String(50), nullable=False, index=True)
    parent_id = Column(String(50), nullable=True, index=True)
    is_subtechnique = Column(Boolean, default=False, nullable=False)
    platforms = Column(String(255), nullable=True)
    url = Column(String(500), nullable=True)


class MitreGroupModel(BaseModel):
    """Stores threat actor groups (e.g. APT29 G0016)."""

    __tablename__ = "mitre_groups"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    aliases = Column(Text, nullable=True)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)


class MitreSoftwareModel(BaseModel):
    """Stores malware families and adversary tools (e.g. Cobalt Strike S0154)."""

    __tablename__ = "mitre_software"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    software_type = Column(String(50), default="malware", nullable=False)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)


class MitreMitigationModel(BaseModel):
    """Stores defensive mitigations (e.g. Multi-factor Authentication M1036)."""

    __tablename__ = "mitre_mitigations"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)


class MitreDataSourceModel(BaseModel):
    """Stores detection data sources (e.g. Command Execution DS0015)."""

    __tablename__ = "mitre_data_sources"

    external_id = Column(String(50), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)


class MitreRelationshipModel(BaseModel):
    """
    Stores directional graph edges between ATT&CK entities:
    Threat Actor -> uses -> Technique
    Malware -> implements -> Technique
    Technique -> belongs_to -> Tactic
    Technique -> detected_by -> Data Source
    Mitigation -> mitigates -> Technique
    """

    __tablename__ = "mitre_relationships"

    source_id = Column(String(50), nullable=False, index=True)
    source_type = Column(String(50), nullable=False, index=True)
    relationship = Column(String(50), nullable=False, index=True)
    target_id = Column(String(50), nullable=False, index=True)
    target_type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)

    __table_args__ = (
        UniqueConstraint("source_id", "relationship", "target_id", name="uq_mitre_source_rel_target"),
    )
