"""
MITRE ATT&CK Intelligence Service
Orchestrates entity queries, hierarchy assembly, relationship lookups,
and database persistence for the MITRE ATT&CK Enterprise framework.
Conforms strictly to IMPLEMENT.md Section 26.
"""

from typing import Any, Dict, List, Optional, Set
import logging
from sqlalchemy.orm import Session

from packages.mitre.canonical_data import (
    CANONICAL_DATA_SOURCES,
    CANONICAL_GROUPS,
    CANONICAL_MITIGATIONS,
    CANONICAL_RELATIONSHIPS,
    CANONICAL_SOFTWARE,
    CANONICAL_TACTICS,
    CANONICAL_TECHNIQUES,
)
from packages.mitre.models import (
    AttackDataSource,
    AttackGroup,
    AttackMitigation,
    AttackRelationship,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
)

logger = logging.getLogger("cyber_osint.packages.mitre.service")


class MitreAttackService:
    """
    Core query and correlation engine for MITRE ATT&CK.
    Provides fast in-memory indexing of canonical data with database synchronization.
    """

    def __init__(self):
        self._tactics: Dict[str, AttackTactic] = {t.id: t for t in CANONICAL_TACTICS}
        self._techniques: Dict[str, AttackTechnique] = {t.id: t for t in CANONICAL_TECHNIQUES}
        self._groups: Dict[str, AttackGroup] = {g.id: g for g in CANONICAL_GROUPS}
        self._software: Dict[str, AttackSoftware] = {s.id: s for s in CANONICAL_SOFTWARE}
        self._mitigations: Dict[str, AttackMitigation] = {m.id: m for m in CANONICAL_MITIGATIONS}
        self._data_sources: Dict[str, AttackDataSource] = {ds.id: ds for ds in CANONICAL_DATA_SOURCES}
        self._relationships: List[AttackRelationship] = list(CANONICAL_RELATIONSHIPS)

        # Build reverse alias lookups
        self._group_aliases: Dict[str, str] = {}
        for g in CANONICAL_GROUPS:
            self._group_aliases[g.name.lower()] = g.id
            for alias in g.aliases:
                self._group_aliases[alias.lower()] = g.id

        self._software_aliases: Dict[str, str] = {}
        for s in CANONICAL_SOFTWARE:
            self._software_aliases[s.name.lower()] = s.id
            for alias in s.aliases:
                self._software_aliases[alias.lower()] = s.id

    # ----------------------------------------------------------------------
    # Query Methods
    # ----------------------------------------------------------------------

    def get_tactics(self) -> List[AttackTactic]:
        """Return all 14 tactics ordered by standard kill chain phase (1 to 14)."""
        return sorted(self._tactics.values(), key=lambda t: t.order)

    def get_tactic(self, tactic_id: str) -> Optional[AttackTactic]:
        """Look up tactic by external ID (e.g. TA0001)."""
        return self._tactics.get(tactic_id.upper())

    def get_techniques(
        self,
        tactic_id: Optional[str] = None,
        include_subtechniques: bool = True,
        query: Optional[str] = None,
    ) -> List[AttackTechnique]:
        """Filter techniques by tactic, subtechnique flag, or keyword search."""
        results = list(self._techniques.values())

        if tactic_id:
            tid_upper = tactic_id.upper()
            results = [t for t in results if t.tactic_id == tid_upper]

        if not include_subtechniques:
            results = [t for t in results if not t.is_subtechnique]

        if query:
            q_lower = query.lower().strip()
            results = [
                t for t in results
                if q_lower in t.id.lower() or q_lower in t.name.lower() or q_lower in t.description.lower()
            ]

        return sorted(results, key=lambda t: (t.tactic_id, t.is_subtechnique, t.id))

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve technique with complete contextual graph:
        - Parent tactic
        - Sub-techniques (if parent) or parent technique (if sub-technique)
        - Threat actors using this technique
        - Software / malware implementing this technique
        - Mitigations applicable
        - Data sources detecting it.
        """
        tid = technique_id.upper()
        tech = self._techniques.get(tid)
        if not tech:
            return None

        # Find sub-techniques
        subtechniques = [t for t in self._techniques.values() if t.parent_technique_id == tid]
        relevant_tids = {tid} | {s.id for s in subtechniques}
        if tech.parent_technique_id:
            relevant_tids.add(tech.parent_technique_id)

        # Find threat actors using technique or any of its sub-techniques
        using_groups = [
            g for g in self._groups.values()
            if any(t in relevant_tids for t in g.associated_techniques)
        ]

        # Find malware implementing technique or any of its sub-techniques
        implementing_sw = [
            s for s in self._software.values()
            if any(t in relevant_tids for t in s.associated_techniques)
        ]

        # Find mitigations applicable to technique or its sub-techniques
        mitigations = [
            m for m in self._mitigations.values()
            if any(t in relevant_tids for t in m.associated_techniques)
        ]

        # Find detecting data sources
        data_sources = [
            ds for ds in self._data_sources.values()
            if any(t in relevant_tids for t in ds.associated_techniques)
        ]

        tactic = self._tactics.get(tech.tactic_id)

        return {
            "technique": tech,
            "tactic": tactic,
            "subtechniques": subtechniques,
            "threat_actors": using_groups,
            "software": implementing_sw,
            "mitigations": mitigations,
            "data_sources": data_sources,
        }

    def get_matrix(self) -> List[Dict[str, Any]]:
        """
        Generate hierarchical Enterprise Matrix:
        Tactics (ordered) -> Techniques -> Sub-techniques.
        """
        matrix = []
        for tactic in self.get_tactics():
            # Get parent techniques under this tactic
            parent_techs = [
                t for t in self._techniques.values()
                if t.tactic_id == tactic.id and not t.is_subtechnique
            ]

            techs_with_subs = []
            for pt in sorted(parent_techs, key=lambda t: t.id):
                subs = [
                    st for st in self._techniques.values()
                    if st.parent_technique_id == pt.id
                ]
                techs_with_subs.append({
                    "technique": pt,
                    "subtechniques": sorted(subs, key=lambda s: s.id),
                })

            matrix.append({
                "tactic": tactic,
                "techniques_count": len(parent_techs),
                "total_techniques_count": len(parent_techs) + sum(len(x["subtechniques"]) for x in techs_with_subs),
                "techniques": techs_with_subs,
            })

        return matrix

    def get_groups(self) -> List[AttackGroup]:
        """Return all threat actor groups."""
        return sorted(self._groups.values(), key=lambda g: g.name)

    def get_group(self, group_id_or_name: str) -> Optional[Dict[str, Any]]:
        """Lookup threat group by ID (e.g. G0016) or name/alias (e.g. APT29, Cozy Bear)."""
        key = group_id_or_name.strip()
        grp = self._groups.get(key.upper())
        if not grp:
            gid = self._group_aliases.get(key.lower())
            if gid:
                grp = self._groups.get(gid)

        if not grp:
            return None

        # Resolve associated techniques
        techniques = [self._techniques[tid] for tid in grp.associated_techniques if tid in self._techniques]
        # Resolve associated software
        software = [self._software[sid] for sid in grp.associated_software if sid in self._software]

        return {
            "group": grp,
            "techniques": techniques,
            "software": software,
        }

    def get_software_list(self) -> List[AttackSoftware]:
        """Return all software (tools and malware)."""
        return sorted(self._software.values(), key=lambda s: (s.software_type, s.name))

    def get_software(self, software_id_or_name: str) -> Optional[Dict[str, Any]]:
        """Lookup software by ID (e.g. S0154) or name/alias (e.g. Cobalt Strike, Beacon)."""
        key = software_id_or_name.strip()
        sw = self._software.get(key.upper())
        if not sw:
            sid = self._software_aliases.get(key.lower())
            if sid:
                sw = self._software.get(sid)

        if not sw:
            return None

        techniques = [self._techniques[tid] for tid in sw.associated_techniques if tid in self._techniques]

        # Find threat actors that deploy this software
        deploying_groups = [
            g for g in self._groups.values()
            if sw.id in g.associated_software
        ]

        return {
            "software": sw,
            "techniques": techniques,
            "threat_actors": deploying_groups,
        }

    def get_mitigations(self) -> List[AttackMitigation]:
        """Return all defensive mitigations."""
        return sorted(self._mitigations.values(), key=lambda m: m.id)

    def get_mitigation(self, mitigation_id: str) -> Optional[Dict[str, Any]]:
        """Lookup mitigation by ID (e.g. M1036)."""
        mit = self._mitigations.get(mitigation_id.upper())
        if not mit:
            return None
        techniques = [self._techniques[tid] for tid in mit.associated_techniques if tid in self._techniques]
        return {
            "mitigation": mit,
            "techniques": techniques,
        }

    def get_data_sources(self) -> List[AttackDataSource]:
        """Return all telemetry data sources."""
        return sorted(self._data_sources.values(), key=lambda ds: ds.id)

    def get_data_source(self, data_source_id: str) -> Optional[Dict[str, Any]]:
        """Lookup telemetry data source by ID (e.g. DS0015)."""
        ds = self._data_sources.get(data_source_id.upper())
        if not ds:
            return None
        techniques = [self._techniques[tid] for tid in ds.associated_techniques if tid in self._techniques]
        return {
            "data_source": ds,
            "techniques": techniques,
        }

    def get_relationships(
        self,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        relationship: Optional[str] = None,
        source_type: Optional[str] = None,
        target_type: Optional[str] = None,
    ) -> List[AttackRelationship]:
        """Filter the directional relationships graph."""
        res = self._relationships
        if source_id:
            res = [r for r in res if r.source_id.upper() == source_id.upper()]
        if target_id:
            res = [r for r in res if r.target_id.upper() == target_id.upper()]
        if relationship:
            res = [r for r in res if r.relationship.lower() == relationship.lower()]
        if source_type:
            res = [r for r in res if r.source_type.lower() == source_type.lower()]
        if target_type:
            res = [r for r in res if r.target_type.lower() == target_type.lower()]
        return res

    def correlate_entity(self, entity_type: str, name: str) -> Optional[Dict[str, Any]]:
        """
        Map an extracted entity name to MITRE ATT&CK knowledge base.
        Supported types: threat_actor, malware, tool, mitre_technique.
        """
        clean_name = name.strip()
        etype = entity_type.lower()

        if etype in ("threat_actor", "threat-actor", "group"):
            grp_data = self.get_group(clean_name)
            if grp_data:
                return {
                    "matched_type": "group",
                    "id": grp_data["group"].id,
                    "canonical_name": grp_data["group"].name,
                    "techniques_count": len(grp_data["techniques"]),
                    "techniques": [t.id for t in grp_data["techniques"]],
                }

        elif etype in ("malware", "tool", "software"):
            sw_data = self.get_software(clean_name)
            if sw_data:
                return {
                    "matched_type": "software",
                    "id": sw_data["software"].id,
                    "canonical_name": sw_data["software"].name,
                    "software_type": sw_data["software"].software_type,
                    "techniques_count": len(sw_data["techniques"]),
                    "techniques": [t.id for t in sw_data["techniques"]],
                }

        elif etype in ("mitre_technique", "technique"):
            tech_data = self.get_technique(clean_name)
            if tech_data:
                return {
                    "matched_type": "technique",
                    "id": tech_data["technique"].id,
                    "canonical_name": tech_data["technique"].name,
                    "tactic": tech_data["tactic"].name if tech_data["tactic"] else None,
                    "threat_actors_count": len(tech_data["threat_actors"]),
                    "software_count": len(tech_data["software"]),
                }

        return None

    def seed_database(self, db: Session) -> Dict[str, int]:
        """
        Populate or synchronize database tables with canonical MITRE ATT&CK records.
        """
        from app.models.mitre import (
            MitreDataSourceModel,
            MitreGroupModel,
            MitreMitigationModel,
            MitreRelationshipModel,
            MitreSoftwareModel,
            MitreTacticModel,
            MitreTechniqueModel,
        )

        counts = {
            "tactics": 0,
            "techniques": 0,
            "groups": 0,
            "software": 0,
            "mitigations": 0,
            "data_sources": 0,
            "relationships": 0,
        }

        # 1. Tactics
        for t in self.get_tactics():
            existing = db.query(MitreTacticModel).filter(MitreTacticModel.external_id == t.id).first()
            if not existing:
                rec = MitreTacticModel(
                    external_id=t.id,
                    name=t.name,
                    description=t.description,
                    sort_order=t.order,
                    url=t.url,
                )
                db.add(rec)
                counts["tactics"] += 1

        # 2. Techniques
        for tech in self._techniques.values():
            existing = db.query(MitreTechniqueModel).filter(MitreTechniqueModel.external_id == tech.id).first()
            if not existing:
                rec = MitreTechniqueModel(
                    external_id=tech.id,
                    name=tech.name,
                    description=tech.description,
                    tactic_id=tech.tactic_id,
                    parent_id=tech.parent_technique_id,
                    is_subtechnique=tech.is_subtechnique,
                    platforms=",".join(tech.platforms),
                    url=tech.url,
                )
                db.add(rec)
                counts["techniques"] += 1

        # 3. Groups
        for g in self._groups.values():
            existing = db.query(MitreGroupModel).filter(MitreGroupModel.external_id == g.id).first()
            if not existing:
                rec = MitreGroupModel(
                    external_id=g.id,
                    name=g.name,
                    aliases=",".join(g.aliases),
                    description=g.description,
                    url=g.url,
                )
                db.add(rec)
                counts["groups"] += 1

        # 4. Software
        for s in self._software.values():
            existing = db.query(MitreSoftwareModel).filter(MitreSoftwareModel.external_id == s.id).first()
            if not existing:
                rec = MitreSoftwareModel(
                    external_id=s.id,
                    name=s.name,
                    software_type=s.software_type,
                    description=s.description,
                    url=s.url,
                )
                db.add(rec)
                counts["software"] += 1

        # 5. Mitigations
        for m in self._mitigations.values():
            existing = db.query(MitreMitigationModel).filter(MitreMitigationModel.external_id == m.id).first()
            if not existing:
                rec = MitreMitigationModel(
                    external_id=m.id,
                    name=m.name,
                    description=m.description,
                    url=m.url,
                )
                db.add(rec)
                counts["mitigations"] += 1

        # 6. Data Sources
        for ds in self._data_sources.values():
            existing = db.query(MitreDataSourceModel).filter(MitreDataSourceModel.external_id == ds.id).first()
            if not existing:
                rec = MitreDataSourceModel(
                    external_id=ds.id,
                    name=ds.name,
                    description=ds.description,
                    url=ds.url,
                )
                db.add(rec)
                counts["data_sources"] += 1

        # 7. Relationships
        for rel in self._relationships:
            existing = (
                db.query(MitreRelationshipModel)
                .filter(
                    MitreRelationshipModel.source_id == rel.source_id,
                    MitreRelationshipModel.relationship == rel.relationship,
                    MitreRelationshipModel.target_id == rel.target_id,
                )
                .first()
            )
            if not existing:
                rec = MitreRelationshipModel(
                    source_id=rel.source_id,
                    source_type=rel.source_type,
                    relationship=rel.relationship,
                    target_id=rel.target_id,
                    target_type=rel.target_type,
                    description=rel.description,
                    confidence=rel.confidence,
                )
                db.add(rec)
                counts["relationships"] += 1

        db.commit()
        logger.info("Synchronized MITRE ATT&CK entities into database: %s", counts)
        return counts


# Global singleton instance
mitre_service = MitreAttackService()
