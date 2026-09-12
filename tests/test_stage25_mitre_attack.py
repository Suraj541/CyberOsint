"""
Stage 25: MITRE ATT&CK Baseline Tests
Validates Section 26 / Step 25 implementation:
- 7 ATT&CK Entity Types: Tactics, Techniques, Sub-techniques, Groups, Software, Mitigations, Data Sources.
- Relationships:
  - Threat Actor -> uses -> Technique
  - Malware -> implements -> Technique
  - Technique -> belongs_to -> Tactic
  - Technique -> detected_by -> Data Source
  - Mitigation -> mitigates -> Technique
- Enterprise matrix hierarchy assembly (14 tactical phases)
- REST APIs: /api/v1/mitre/tactics, /matrix, /techniques/{id}, /groups, /software, /relationships.
- Database models and synchronization.
Conforms strictly to IMPLEMENT.md Section 26 specifications.
"""

from pathlib import Path
import sys
import unittest

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models.base import Base
from app.models.mitre import (
    MitreDataSourceModel,
    MitreGroupModel,
    MitreMitigationModel,
    MitreRelationshipModel,
    MitreSoftwareModel,
    MitreTacticModel,
    MitreTechniqueModel,
)
from packages.mitre import (
    AttackDataSource,
    AttackGroup,
    AttackMitigation,
    AttackRelationship,
    AttackSoftware,
    AttackTactic,
    AttackTechnique,
    CANONICAL_DATA_SOURCES,
    CANONICAL_GROUPS,
    CANONICAL_MITIGATIONS,
    CANONICAL_RELATIONSHIPS,
    CANONICAL_SOFTWARE,
    CANONICAL_TACTICS,
    CANONICAL_TECHNIQUES,
    MitreAttackService,
    mitre_service,
)


class TestStage25MitreAttack(unittest.TestCase):
    """Test suite validating Section 26 / Step 25 MITRE ATT&CK Framework."""

    def setUp(self):
        """Set up an isolated in-memory SQLite database for testing."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up in-memory database and dependency overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        app.dependency_overrides.clear()

    def test_mitre_package_structure(self):
        """Confirm all mandated MITRE ATT&CK modules exist."""
        pkg_dir = repo_root / "packages" / "mitre"
        self.assertTrue(pkg_dir.exists(), "packages/mitre directory missing")
        for mod in ("__init__.py", "models.py", "canonical_data.py", "service.py"):
            self.assertTrue((pkg_dir / mod).exists(), f"packages/mitre/{mod} missing")

        model_file = api_root / "app" / "models" / "mitre.py"
        self.assertTrue(model_file.exists(), "apps/api/app/models/mitre.py missing")

        endpoint_file = api_root / "app" / "api" / "v1" / "endpoints" / "mitre.py"
        self.assertTrue(endpoint_file.exists(), "apps/api/app/api/v1/endpoints/mitre.py missing")

    def test_all_seven_attack_entity_types_created(self):
        """Confirm all 7 ATT&CK entity types from Section 26 are modeled and populated."""
        tactics = mitre_service.get_tactics()
        self.assertEqual(len(tactics), 14, "Must contain all 14 standard ATT&CK enterprise tactics")
        self.assertTrue(all(isinstance(t, AttackTactic) for t in tactics))

        techniques = mitre_service.get_techniques(include_subtechniques=False)
        self.assertGreaterEqual(len(techniques), 10, "Must contain core parent techniques")
        self.assertTrue(all(isinstance(t, AttackTechnique) and not t.is_subtechnique for t in techniques))

        subtechniques = [t for t in mitre_service.get_techniques(include_subtechniques=True) if t.is_subtechnique]
        self.assertGreaterEqual(len(subtechniques), 4, "Must contain sub-techniques (e.g. T1059.001)")
        self.assertTrue(all("." in t.id and t.parent_technique_id is not None for t in subtechniques))

        groups = mitre_service.get_groups()
        self.assertGreaterEqual(len(groups), 5, "Must contain major threat actor groups")
        self.assertTrue(all(isinstance(g, AttackGroup) for g in groups))
        self.assertTrue(any(g.id == "G0016" and "Cozy Bear" in g.aliases for g in groups))

        software = mitre_service.get_software_list()
        self.assertGreaterEqual(len(software), 4, "Must contain software tools and malware")
        self.assertTrue(all(isinstance(s, AttackSoftware) for s in software))
        self.assertTrue(any(s.id == "S0154" and s.name == "Cobalt Strike" for s in software))

        mitigations = mitre_service.get_mitigations()
        self.assertGreaterEqual(len(mitigations), 5, "Must contain defensive mitigations")
        self.assertTrue(all(isinstance(m, AttackMitigation) for m in mitigations))

        data_sources = mitre_service.get_data_sources()
        self.assertGreaterEqual(len(data_sources), 5, "Must contain detection telemetry data sources")
        self.assertTrue(all(isinstance(d, AttackDataSource) for d in data_sources))

    def test_threat_actor_uses_technique_relationship(self):
        """Validate mandated relationship: Threat Actor -> uses -> Technique."""
        edges = mitre_service.get_relationships(relationship="uses")
        self.assertGreaterEqual(len(edges), 10)
        self.assertTrue(all(e.source_type == "group" and e.target_type == "technique" for e in edges))

        # Check APT29 (G0016) uses T1190 or T1059.001
        apt29_uses = mitre_service.get_relationships(source_id="G0016", relationship="uses")
        used_tids = {e.target_id for e in apt29_uses}
        self.assertIn("T1190", used_tids)
        self.assertIn("T1059.001", used_tids)

    def test_malware_implements_technique_relationship(self):
        """Validate mandated relationship: Malware -> implements -> Technique."""
        edges = mitre_service.get_relationships(relationship="implements")
        self.assertGreaterEqual(len(edges), 8)
        self.assertTrue(all(e.source_type == "software" and e.target_type == "technique" for e in edges))

        # Check Cobalt Strike (S0154) implements T1055 or T1059.001
        cs_implements = mitre_service.get_relationships(source_id="S0154", relationship="implements")
        cs_tids = {e.target_id for e in cs_implements}
        self.assertIn("T1055", cs_tids)
        self.assertIn("T1059.001", cs_tids)

        # Check Akira (S0650) implements T1486 (Data Encrypted for Impact)
        akira_implements = mitre_service.get_relationships(source_id="S0650", relationship="implements")
        akira_tids = {e.target_id for e in akira_implements}
        self.assertIn("T1486", akira_tids)

    def test_technique_belongs_to_tactic_relationship(self):
        """Validate mandated relationship: Technique -> belongs_to -> Tactic."""
        edges = mitre_service.get_relationships(relationship="belongs_to")
        self.assertGreaterEqual(len(edges), 10)
        self.assertTrue(all(e.source_type == "technique" and e.target_type == "tactic" for e in edges))

        # T1190 belongs to TA0001 (Initial Access)
        t1190_rel = mitre_service.get_relationships(source_id="T1190", relationship="belongs_to")
        self.assertTrue(any(e.target_id == "TA0001" for e in t1190_rel))

        # T1486 belongs to TA0040 (Impact)
        t1486_rel = mitre_service.get_relationships(source_id="T1486", relationship="belongs_to")
        self.assertTrue(any(e.target_id == "TA0040" for e in t1486_rel))

    def test_technique_detected_by_datasource_relationship(self):
        """Validate mandated relationship: Technique -> detected_by -> Data Source."""
        edges = mitre_service.get_relationships(relationship="detected_by")
        self.assertGreaterEqual(len(edges), 10)
        self.assertTrue(all(e.source_type == "technique" and e.target_type == "data_source" for e in edges))

        # T1059 detected by DS0015 (Command Execution)
        t1059_detected = mitre_service.get_relationships(source_id="T1059", relationship="detected_by")
        self.assertTrue(any(e.target_id == "DS0015" for e in t1059_detected))

    def test_mitigation_mitigates_technique_relationship(self):
        """Validate mitigation relationship: Mitigation -> mitigates -> Technique."""
        edges = mitre_service.get_relationships(relationship="mitigates")
        self.assertGreaterEqual(len(edges), 5)
        self.assertTrue(all(e.source_type == "mitigation" and e.target_type == "technique" for e in edges))

        # M1036 (MFA) mitigates T1078 (Valid Accounts)
        m1036_rel = mitre_service.get_relationships(source_id="M1036", relationship="mitigates")
        self.assertTrue(any(e.target_id == "T1078" for e in m1036_rel))

    def test_enterprise_matrix_hierarchy_assembly(self):
        """Confirm full matrix tree: 14 ordered tactics containing parent techniques and nested sub-techniques."""
        matrix = mitre_service.get_matrix()
        self.assertEqual(len(matrix), 14)

        tactic_names = [col["tactic"].name for col in matrix]
        self.assertEqual(tactic_names[0], "Reconnaissance")
        self.assertEqual(tactic_names[2], "Initial Access")
        self.assertEqual(tactic_names[3], "Execution")
        self.assertEqual(tactic_names[-1], "Impact")

        # Confirm nested sub-techniques under parent techniques
        exec_col = next(c for c in matrix if c["tactic"].id == "TA0002")
        t1059_item = next(item for item in exec_col["techniques"] if item["technique"].id == "T1059")
        sub_ids = [s.id for s in t1059_item["subtechniques"]]
        self.assertIn("T1059.001", sub_ids)
        self.assertIn("T1059.003", sub_ids)

    def test_technique_detail_graph_aggregation(self):
        """Confirm get_technique aggregates parent tactic, subtechniques, threat actors, malware, and detections."""
        t1059_detail = mitre_service.get_technique("T1059")
        self.assertIsNotNone(t1059_detail)
        self.assertEqual(t1059_detail["tactic"].name, "Execution")
        self.assertGreaterEqual(len(t1059_detail["subtechniques"]), 2)
        self.assertTrue(any(g.id == "G0016" for g in t1059_detail["threat_actors"]))  # APT29
        self.assertTrue(any(s.id == "S0154" for s in t1059_detail["software"]))  # Cobalt Strike
        self.assertTrue(any(d.id == "DS0015" for d in t1059_detail["data_sources"]))  # Command Execution

    def test_alias_and_entity_correlation(self):
        """Confirm threat actor and malware aliases resolve to canonical ATT&CK IDs."""
        cozy_bear = mitre_service.correlate_entity("threat_actor", "Cozy Bear")
        self.assertIsNotNone(cozy_bear)
        self.assertEqual(cozy_bear["id"], "G0016")
        self.assertEqual(cozy_bear["canonical_name"], "APT29")

        beacon = mitre_service.correlate_entity("software", "Beacon")
        self.assertIsNotNone(beacon)
        self.assertEqual(beacon["id"], "S0154")
        self.assertEqual(beacon["canonical_name"], "Cobalt Strike")

    def test_database_models_and_synchronization(self):
        """Confirm MITRE ATT&CK models can be seeded and queried via SQLAlchemy session."""
        counts = mitre_service.seed_database(self.db)
        self.assertEqual(counts["tactics"], 14)
        self.assertGreaterEqual(counts["techniques"], 10)
        self.assertGreaterEqual(counts["groups"], 5)
        self.assertGreaterEqual(counts["software"], 4)
        self.assertGreaterEqual(counts["relationships"], 30)

        # Query database directly
        db_tactics = self.db.query(MitreTacticModel).order_by(MitreTacticModel.sort_order).all()
        self.assertEqual(len(db_tactics), 14)
        self.assertEqual(db_tactics[0].external_id, "TA0043")

        db_relationships = (
            self.db.query(MitreRelationshipModel)
            .filter(MitreRelationshipModel.relationship == "uses")
            .all()
        )
        self.assertGreaterEqual(len(db_relationships), 10)

    def test_api_mitre_endpoints(self):
        """Verify all MITRE ATT&CK REST endpoints return 200 OK and valid schemas."""
        client = self.client

        # 1. Tactics
        resp = client.get("/api/v1/mitre/tactics")
        self.assertEqual(resp.status_code, 200)
        tactics_data = resp.json()
        self.assertEqual(len(tactics_data), 14)

        # 2. Matrix
        resp = client.get("/api/v1/mitre/matrix")
        self.assertEqual(resp.status_code, 200)
        matrix_data = resp.json()
        self.assertEqual(matrix_data["total_tactics"], 14)
        self.assertGreaterEqual(matrix_data["total_techniques"], 15)

        # 3. Techniques list
        resp = client.get("/api/v1/mitre/techniques?tactic_id=TA0001")
        self.assertEqual(resp.status_code, 200)
        t1_techs = resp.json()
        self.assertTrue(any(t["id"] == "T1190" for t in t1_techs))

        # 4. Technique detail
        resp = client.get("/api/v1/mitre/techniques/T1190")
        self.assertEqual(resp.status_code, 200)
        detail = resp.json()
        self.assertEqual(detail["technique"]["id"], "T1190")
        self.assertEqual(detail["tactic"]["id"], "TA0001")
        self.assertTrue(len(detail["threat_actors"]) > 0)
        self.assertTrue(len(detail["data_sources"]) > 0)

        # 5. Threat groups
        resp = client.get("/api/v1/mitre/groups")
        self.assertEqual(resp.status_code, 200)
        groups = resp.json()
        self.assertTrue(any(g["id"] == "G0016" for g in groups))

        # 6. Software
        resp = client.get("/api/v1/mitre/software")
        self.assertEqual(resp.status_code, 200)
        sw = resp.json()
        self.assertTrue(any(s["id"] == "S0154" for s in sw))

        # 7. Relationships
        resp = client.get("/api/v1/mitre/relationships?relationship=uses")
        self.assertEqual(resp.status_code, 200)
        rels = resp.json()
        self.assertTrue(all(r["relationship"] == "uses" for r in rels))


if __name__ == "__main__":
    unittest.main()
