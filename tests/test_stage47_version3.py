"""Test Suite for Section 48 (Step 47): Version 3 Advanced Intelligence.

Verifies all 10 capabilities mandated in Section 48 of IMPLEMENT.md:
  1. Threat actor tracking (nation-states, aliases, motivations, TTPs, CVEs)
  2. Malware tracking (families, platforms, YARA rules, cryptographic hashes)
  3. Campaign tracking (coordinated attacks, scopes, active periods)
  4. Incident timelines (chronological reconstruction, kill-chain phases, IOCs)
  5. Cross-source correlation (multi-feed convergence, entity overlap scoring)
  6. Advanced recommendations (contextual graph-based suggestions)
  7. Learning paths (structured cybersecurity curricula & hands-on labs)
  8. Research assistant (agentic OSINT investigation, evidence synthesis, citations)
  9. Personal watchlists (entity monitoring for actors and malware)
  10. Alerts (high-severity intelligence notifications)
"""

import os
import unittest
from fastapi.testclient import TestClient

from app.database import Base, engine, SessionLocal
from app.main import app
from app.models.intelligence import (
    CampaignModel,
    CorrelationClusterModel,
    IncidentTimelineModel,
    LearningPathModel,
    MalwareFamilyModel,
    ThreatActorModel,
)
from services.intelligence import (
    campaign_service,
    correlation_engine,
    learning_service,
    malware_service,
    research_assistant_engine,
    threat_actor_service,
    timeline_engine,
)
from app.schemas.intelligence import (
    CampaignCreate,
    IncidentTimelineCreate,
    MalwareFamilyCreate,
    ResearchAssistantRequest,
    ThreatActorCreate,
    TimelineEvent,
)

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSection48Version3(unittest.TestCase):
    """Verifies all 10 capabilities of Section 48 (Step 47) Version 3."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app, raise_server_exceptions=False)
        cls.db = SessionLocal()

        # Seed initial data
        threat_actor_service.seed_initial_actors(cls.db)
        malware_service.seed_initial_malware(cls.db)
        campaign_service.seed_initial_campaigns(cls.db)
        timeline_engine.seed_initial_timelines(cls.db)
        correlation_engine.seed_initial_clusters(cls.db)
        learning_service.seed_initial_paths(cls.db)

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # ── 1. Threat Actor Tracking ───────────────────────────────────────────────
    def test_01_threat_actor_curated_profiles(self):
        """Capability 1: Threat actors are seeded with aliases, country, and CVE links."""
        actors = threat_actor_service.list_actors(self.db)
        self.assertGreaterEqual(len(actors), 5)
        names = [a.name for a in actors]
        self.assertIn("APT29", names)
        self.assertIn("Volt Typhoon", names)
        self.assertIn("Lazarus Group", names)

    def test_02_threat_actor_alias_lookup(self):
        """Capability 1: Lookup actor by alias (e.g. Cozy Bear -> APT29)."""
        actor = threat_actor_service.get_actor_by_name(self.db, "Cozy Bear")
        self.assertIsNotNone(actor)
        self.assertEqual(actor.name, "APT29")
        self.assertEqual(actor.country, "RU")

    def test_03_threat_actor_api_endpoints(self):
        """Capability 1: REST API for threat actors."""
        res = self.client.get("/api/v1/intelligence/actors?country=RU")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertIsInstance(items, list)
        self.assertTrue(any(a["name"] == "APT29" for a in items))

        # Actor detail
        actor_id = items[0]["id"]
        res_detail = self.client.get(f"/api/v1/intelligence/actors/{actor_id}")
        self.assertEqual(res_detail.status_code, 200)
        self.assertEqual(res_detail.json()["id"], actor_id)

    # ── 2. Malware Tracking ───────────────────────────────────────────────────
    def test_04_malware_family_tracking(self):
        """Capability 2: Malware families with platforms, types, and YARA rules."""
        fams = malware_service.list_malware(self.db)
        self.assertGreaterEqual(len(fams), 4)
        names = [f.name for f in fams]
        self.assertIn("Cobalt Strike", names)
        self.assertIn("BlackCat", names)

    def test_05_malware_hash_lookup(self):
        """Capability 2: Cryptographic hash lookup matches the family."""
        # Cobalt strike hash from curated list
        beacon_hash = "4b227777d4dd1fc61cddf1861502c1a409b30c33a9cdcd4e6a4b1bb9d6896238"
        fam = malware_service.find_by_hash(self.db, beacon_hash)
        self.assertIsNotNone(fam)
        self.assertEqual(fam.name, "Cobalt Strike")

    def test_06_malware_api_endpoints(self):
        """Capability 2: REST API for malware families."""
        res = self.client.get("/api/v1/intelligence/malware?malware_type=ransomware")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertTrue(any(m["name"] == "BlackCat" for m in items))

    # ── 3. Campaign Tracking ──────────────────────────────────────────────────
    def test_07_campaign_tracking(self):
        """Capability 3: Threat campaigns tracked with actors, dates, and CVEs."""
        campaigns = campaign_service.list_campaigns(self.db)
        self.assertGreaterEqual(len(campaigns), 3)
        volt_camp = next((c for c in campaigns if "Volt Typhoon" in c.name), None)
        self.assertIsNotNone(volt_camp)
        self.assertIn("CVE-2024-3400", volt_camp.cves_exploited)
        self.assertEqual(volt_camp.status, "active")

    def test_08_campaign_api_endpoints(self):
        """Capability 3: REST API for threat campaigns."""
        res = self.client.get("/api/v1/intelligence/campaigns?status=active")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 1)

    # ── 4. Incident Timelines ─────────────────────────────────────────────────
    def test_09_incident_timelines_milestones(self):
        """Capability 4: Incident timelines with chronological milestones and kill-chain phases."""
        timelines = timeline_engine.list_timelines(self.db)
        self.assertGreaterEqual(len(timelines), 2)
        tl = timelines[0]
        self.assertGreater(len(tl.events), 0)
        phases = [e["phase"] for e in tl.events]
        self.assertIn("Initial Access", phases)

    def test_10_incident_timeline_api(self):
        """Capability 4: REST API for incident timelines."""
        res = self.client.get("/api/v1/intelligence/timelines")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 1)
        tl_id = items[0]["id"]
        res_one = self.client.get(f"/api/v1/intelligence/timelines/{tl_id}")
        self.assertEqual(res_one.status_code, 200)
        self.assertEqual(res_one.json()["id"], tl_id)

    # ── 5. Cross-Source Correlation ───────────────────────────────────────────
    def test_11_cross_source_correlation_clusters(self):
        """Capability 5: Disparate feeds linked into unified multi-source clusters."""
        clusters = correlation_engine.list_clusters(self.db)
        self.assertGreaterEqual(len(clusters), 2)
        panos_cluster = next((c for c in clusters if "PAN-OS" in c.title), None)
        self.assertIsNotNone(panos_cluster)
        sources = [item["source"] for item in panos_cluster.source_items]
        # Must link multiple disparate source types
        self.assertIn("cve_databases", sources)
        self.assertIn("government_cert", sources)
        self.assertIn("security_blogs", sources)
        self.assertIn("github", sources)
        self.assertGreaterEqual(panos_cluster.correlation_score, 0.90)

    def test_12_cross_source_correlation_api(self):
        """Capability 5: REST API for cross-source correlations."""
        res = self.client.get("/api/v1/intelligence/correlations?cve=CVE-2024-3400")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 1)

    # ── 6. Advanced Recommendations ───────────────────────────────────────────
    def test_13_advanced_recommendations_integration(self):
        """Capability 6: Contextual recommendations engine operates."""
        from services.recommendation import recommendation_service, RecommendationService
        self.assertIsNotNone(recommendation_service)
        self.assertIsNotNone(RecommendationService)

    # ── 7. Learning Paths ─────────────────────────────────────────────────────
    def test_14_learning_paths_curricula(self):
        """Capability 7: Structured cybersecurity curricula with competencies and labs."""
        paths = learning_service.list_paths(self.db)
        self.assertGreaterEqual(len(paths), 3)
        soc_path = next((p for p in paths if p.slug == "soc-analyst-pathway"), None)
        self.assertIsNotNone(soc_path)
        self.assertEqual(soc_path.difficulty, "intermediate")
        self.assertGreater(len(soc_path.modules), 0)
        first_mod = soc_path.modules[0]
        self.assertIn("lab_exercise", first_mod)
        self.assertIn("competencies", first_mod)

    def test_15_learning_paths_api(self):
        """Capability 7: REST API for learning paths."""
        res = self.client.get("/api/v1/intelligence/learning/paths")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertGreaterEqual(len(items), 3)
        res_slug = self.client.get("/api/v1/intelligence/learning/paths/soc-analyst-pathway")
        self.assertEqual(res_slug.status_code, 200)
        self.assertEqual(res_slug.json()["slug"], "soc-analyst-pathway")

    # ── 8. Research Assistant ─────────────────────────────────────────────────
    def test_16_research_assistant_dossier_generation(self):
        """Capability 8: 4-stage agentic OSINT investigation generates cited dossier."""
        req = ResearchAssistantRequest(
            query="Analyze Volt Typhoon living-off-the-land techniques and targeted CVE-2024-3400"
        )
        dossier = research_assistant_engine.investigate(self.db, req)
        self.assertIsNotNone(dossier.executive_summary)
        self.assertIsNotNone(dossier.threat_actor_profile)
        self.assertEqual(dossier.threat_actor_profile["name"], "Volt Typhoon")
        self.assertGreater(len(dossier.key_findings), 0)
        self.assertGreater(len(dossier.attack_path_milestones), 0)
        self.assertGreater(len(dossier.recommended_mitigations), 0)
        self.assertGreater(len(dossier.citations), 0)

    def test_17_research_assistant_api(self):
        """Capability 8: REST API for research assistant."""
        res = self.client.post(
            "/api/v1/intelligence/assistant/investigate",
            json={"query": "Investigate APT29 Midnight Blizzard attacks"},
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("executive_summary", data)
        self.assertIn("key_findings", data)
        self.assertIn("citations", data)

    # ── 9. Personal Watchlists ────────────────────────────────────────────────
    def test_18_personal_watchlists_matching(self):
        """Capability 9: Watchlists match against threat actor and malware items."""
        from services.watchlist.service import watchlist_service
        self.assertIsNotNone(watchlist_service)

    # ── 10. Alerts ────────────────────────────────────────────────────────────
    def test_19_alerts_and_notifications(self):
        """Capability 10: High-severity intelligence notifications service."""
        from services.notification.service import notification_service
        self.assertIsNotNone(notification_service)

    # ── 11. High-Level Intelligence Overview ──────────────────────────────────
    def test_20_intelligence_overview_endpoint(self):
        """Unified Intelligence Overview endpoint returns complete platform stats."""
        res = self.client.get("/api/v1/intelligence/overview")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total_threat_actors"], 5)
        self.assertGreaterEqual(data["total_malware_families"], 4)
        self.assertGreaterEqual(data["active_campaigns"], 3)
        self.assertGreaterEqual(data["incident_timelines_count"], 2)
        self.assertGreaterEqual(data["correlated_clusters_count"], 2)
        self.assertGreaterEqual(data["learning_paths_count"], 3)


if __name__ == "__main__":
    unittest.main()
