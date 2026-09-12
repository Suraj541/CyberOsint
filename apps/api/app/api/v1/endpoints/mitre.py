"""
MITRE ATT&CK REST Endpoints
Exposes Enterprise ATT&CK matrix hierarchy, tactics, techniques, groups,
software, mitigations, data sources, and relationship graph traversals.
Conforms strictly to IMPLEMENT.md Section 26.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.mitre import (
    MitreDataSourceOut,
    MitreGroupOut,
    MitreMatrixColumnOut,
    MitreMatrixResponse,
    MitreMitigationOut,
    MitreRelationshipOut,
    MitreSoftwareOut,
    MitreTacticOut,
    MitreTechniqueDetailOut,
    MitreTechniqueOut,
)
from packages.mitre.service import mitre_service

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/tactics", response_model=List[MitreTacticOut])
def list_tactics() -> List[MitreTacticOut]:
    """Retrieve all 14 MITRE ATT&CK Enterprise tactics ordered by tactical phase."""
    tactics = mitre_service.get_tactics()
    return [MitreTacticOut(**t.to_dict()) for t in tactics]


@router.get("/tactics/{tactic_id}", response_model=MitreTacticOut)
def get_tactic(tactic_id: str) -> MitreTacticOut:
    """Retrieve details for a specific MITRE ATT&CK tactic."""
    tactic = mitre_service.get_tactic(tactic_id)
    if not tactic:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MITRE ATT&CK tactic '{tactic_id}' not found",
        )
    return MitreTacticOut(**tactic.to_dict())


@router.get("/matrix", response_model=MitreMatrixResponse)
def get_enterprise_matrix() -> MitreMatrixResponse:
    """
    Retrieve full Enterprise Matrix hierarchy:
    Tactics (14 columns) -> Techniques -> Sub-techniques.
    """
    raw_matrix = mitre_service.get_matrix()
    total_techs = sum(c["total_techniques_count"] for c in raw_matrix)

    matrix_cols = []
    for col in raw_matrix:
        techs_out = []
        for item in col["techniques"]:
            techs_out.append({
                "technique": MitreTechniqueOut(**item["technique"].to_dict()),
                "subtechniques": [MitreTechniqueOut(**s.to_dict()) for s in item["subtechniques"]],
            })

        matrix_cols.append(MitreMatrixColumnOut(
            tactic=MitreTacticOut(**col["tactic"].to_dict()),
            techniques_count=col["techniques_count"],
            total_techniques_count=col["total_techniques_count"],
            techniques=techs_out,
        ))

    return MitreMatrixResponse(
        matrix=matrix_cols,
        total_tactics=len(matrix_cols),
        total_techniques=total_techs,
    )


@router.get("/techniques", response_model=List[MitreTechniqueOut])
def list_techniques(
    tactic_id: Optional[str] = Query(None, description="Filter by tactic external ID (e.g. TA0001)"),
    include_subtechniques: bool = Query(True, description="Whether to include sub-techniques"),
    query: Optional[str] = Query(None, description="Search term in technique ID, name, or description"),
) -> List[MitreTechniqueOut]:
    """List techniques filtered by tactic, search keyword, or subtechnique flag."""
    techs = mitre_service.get_techniques(
        tactic_id=tactic_id,
        include_subtechniques=include_subtechniques,
        query=query,
    )
    return [MitreTechniqueOut(**t.to_dict()) for t in techs]


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueDetailOut)
def get_technique_details(technique_id: str) -> MitreTechniqueDetailOut:
    """
    Retrieve comprehensive technique intelligence:
    - Base technique profile
    - Parent tactic
    - Sub-techniques
    - Threat actor groups using this technique
    - Malware/tools implementing this technique
    - Hardening mitigations
    - Telemetry data sources for detection.
    """
    data = mitre_service.get_technique(technique_id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MITRE ATT&CK technique '{technique_id}' not found",
        )

    return MitreTechniqueDetailOut(
        technique=MitreTechniqueOut(**data["technique"].to_dict()),
        tactic=MitreTacticOut(**data["tactic"].to_dict()) if data["tactic"] else None,
        subtechniques=[MitreTechniqueOut(**s.to_dict()) for s in data["subtechniques"]],
        threat_actors=[MitreGroupOut(**g.to_dict()) for g in data["threat_actors"]],
        software=[MitreSoftwareOut(**s.to_dict()) for s in data["software"]],
        mitigations=[MitreMitigationOut(**m.to_dict()) for m in data["mitigations"]],
        data_sources=[MitreDataSourceOut(**d.to_dict()) for d in data["data_sources"]],
    )


@router.get("/groups", response_model=List[MitreGroupOut])
def list_groups() -> List[MitreGroupOut]:
    """List active threat actor groups in MITRE ATT&CK."""
    groups = mitre_service.get_groups()
    return [MitreGroupOut(**g.to_dict()) for g in groups]


@router.get("/groups/{group_id}")
def get_group_details(group_id: str) -> Dict[str, Any]:
    """Retrieve threat actor profile, associated techniques, and deployed software."""
    data = mitre_service.get_group(group_id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat actor group '{group_id}' not found",
        )
    return {
        "group": MitreGroupOut(**data["group"].to_dict()),
        "techniques": [MitreTechniqueOut(**t.to_dict()) for t in data["techniques"]],
        "software": [MitreSoftwareOut(**s.to_dict()) for s in data["software"]],
    }


@router.get("/software", response_model=List[MitreSoftwareOut])
def list_software() -> List[MitreSoftwareOut]:
    """List software tools and malware families in MITRE ATT&CK."""
    sw_list = mitre_service.get_software_list()
    return [MitreSoftwareOut(**s.to_dict()) for s in sw_list]


@router.get("/software/{software_id}")
def get_software_details(software_id: str) -> Dict[str, Any]:
    """Retrieve software profile, implemented techniques, and deploying threat actors."""
    data = mitre_service.get_software(software_id)
    if not data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Software '{software_id}' not found",
        )
    return {
        "software": MitreSoftwareOut(**data["software"].to_dict()),
        "techniques": [MitreTechniqueOut(**t.to_dict()) for t in data["techniques"]],
        "threat_actors": [MitreGroupOut(**g.to_dict()) for g in data["threat_actors"]],
    }


@router.get("/mitigations", response_model=List[MitreMitigationOut])
def list_mitigations() -> List[MitreMitigationOut]:
    """List defensive mitigations in MITRE ATT&CK."""
    mitigations = mitre_service.get_mitigations()
    return [MitreMitigationOut(**m.to_dict()) for m in mitigations]


@router.get("/data-sources", response_model=List[MitreDataSourceOut])
def list_data_sources() -> List[MitreDataSourceOut]:
    """List telemetry data sources in MITRE ATT&CK."""
    ds_list = mitre_service.get_data_sources()
    return [MitreDataSourceOut(**d.to_dict()) for d in ds_list]


@router.get("/relationships", response_model=List[MitreRelationshipOut])
def list_relationships(
    source_id: Optional[str] = Query(None, description="Filter by source entity ID (e.g. G0016, S0154)"),
    target_id: Optional[str] = Query(None, description="Filter by target entity ID (e.g. T1190, TA0001)"),
    relationship: Optional[str] = Query(None, description="Filter by verb: uses, implements, belongs_to, detected_by, mitigates"),
    source_type: Optional[str] = Query(None, description="Filter by source type: group, software, technique, mitigation"),
    target_type: Optional[str] = Query(None, description="Filter by target type: technique, tactic, data_source"),
) -> List[MitreRelationshipOut]:
    """Query directional relationship edges across the ATT&CK graph."""
    edges = mitre_service.get_relationships(
        source_id=source_id,
        target_id=target_id,
        relationship=relationship,
        source_type=source_type,
        target_type=target_type,
    )
    return [MitreRelationshipOut(**e.to_dict()) for e in edges]


@router.post("/sync")
def sync_database_records(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Synchronize MITRE ATT&CK canonical data into database tables."""
    counts = mitre_service.seed_database(db)
    return {
        "status": "success",
        "synced": counts,
    }
