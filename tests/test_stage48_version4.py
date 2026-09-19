"""Test Suite for Section 49 (Step 48): Version 4 Scale Architecture.

Verifies all 9 scale capabilities mandated in Section 49 of IMPLEMENT.md:
  1. Distributed ingestion (partitioning, consistent hashing, backpressure, worker failover)
  2. Connector marketplace (manifest validation, install/uninstall lifecycle, catalog search)
  3. Multi-region deployment (datacenter topology, geo-routing resolver, disaster recovery failover)
  4. Advanced caching (L1/L2 multi-tier caching, tag invalidation, XFetch stampede protection)
  5. Large-scale search (ILM policies: Hot/Warm/Cold/Frozen, federated multi-cluster search)
  6. Advanced graph analytics (PageRank centrality, community clusters, blast radius traversal)
  7. Model routing (SLA constraints, task-aware routing, circuit breakers, fallback cascade)
  8. Automated evaluation (golden test benchmarks, precision/recall/F1 metrics, drift detection)
  9. Source quality learning (dynamic Bayesian reputation updates, source quality tiers)
"""

import os
import sys
import time
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient

from app.database import Base, SessionLocal, engine
from app.main import app
from app.models.scale import (
    BenchmarkRunModel,
    MarketplaceConnectorModel,
    RegionNodeModel,
    SourceReputationModel,
)
from app.schemas.scale import (
    BackpressureUpdateRequest,
    BlastRadiusRequest,
    CacheInvalidateRequest,
    EvaluationTriggerRequest,
    FailoverRequest,
    FederatedSearchRequest,
    GeoRouteRequest,
    MarketplacePublishRequest,
    ModelRouteRequest,
    ReputationUpdateRequest,
)
from services.scale import (
    advanced_cache,
    auto_evaluation,
    connector_marketplace,
    distributed_ingestion,
    graph_analytics,
    large_scale_search,
    model_router,
    multi_region,
    source_quality_learning,
)


class TestSection49Version4Scale(unittest.TestCase):
    """Unit and integration test suite for Version 4 Scale Architecture."""

    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app, raise_server_exceptions=False)
        cls.db = SessionLocal()

        # Seed initial state
        connector_marketplace.seed_marketplace(cls.db)
        multi_region.seed_regions(cls.db)
        auto_evaluation.seed_benchmarks(cls.db)
        source_quality_learning.seed_source_reputations(cls.db)

        # Ensure all region nodes are healthy at start of test run
        for n in cls.db.query(RegionNodeModel).all():
            n.status = "healthy"
            n.role = "primary" if n.region_code == "us-east-1" else "replica"
        cls.db.commit()

        # Ensure workers are seeded with fresh timestamps
        distributed_ingestion._seed_workers()

    @classmethod
    def tearDownClass(cls):
        cls.db.close()

    # ── 1. Distributed Ingestion & Backpressure ───────────────────────────────
    def test_01_distributed_ingestion_partitions(self):
        """Capability 1: Partitions are initialized and tracked."""
        status = distributed_ingestion.get_status()
        self.assertGreaterEqual(status.active_workers_count, 4)
        self.assertEqual(len(status.partitions), 4)
        self.assertGreaterEqual(status.partitions[0].current_throughput_eps, 40.0)

    def test_02_distributed_ingestion_consistent_hashing(self):
        """Capability 1: Deterministic source-to-worker hash distribution."""
        w1 = distributed_ingestion.assign_source_to_worker("https://cisa.gov/rss.xml")
        w2 = distributed_ingestion.assign_source_to_worker("https://cisa.gov/rss.xml")
        self.assertEqual(w1, w2, "Same source URL must map to the same worker deterministically")

        w3 = distributed_ingestion.assign_source_to_worker("https://nvd.nist.gov/feeds/json/cve.json")
        self.assertTrue(w3.startswith("worker-node-"))

    def test_03_distributed_ingestion_backpressure_throttling(self):
        """Capability 1: Ingestion rate throttles dynamically on queue depth."""
        # Low queue depth -> no throttle (1.0)
        rate_low = distributed_ingestion.update_queue_depth(50)
        self.assertEqual(rate_low, 1.0)

        # High queue depth exceeding high_watermark -> throttle engaged
        rate_high = distributed_ingestion.update_queue_depth(650)
        self.assertLess(rate_high, 1.0)
        self.assertGreaterEqual(rate_high, 0.2)

        # Reset
        distributed_ingestion.update_queue_depth(120)

    def test_04_distributed_ingestion_heartbeat_and_eviction(self):
        """Capability 1: Worker heartbeat renewal and dead-worker eviction."""
        distributed_ingestion.register_heartbeat("worker-node-01", throughput_eps=52.0)
        w = distributed_ingestion._workers["worker-node-01"]
        self.assertEqual(w["current_throughput_eps"], 52.0)
        self.assertEqual(w["status"], "active")

        # Evict workers with expired heartbeats
        w["heartbeat_timestamp"] = time.time() - 45.0
        evicted = distributed_ingestion.evict_dead_workers(timeout_seconds=30.0)
        self.assertGreaterEqual(evicted, 1)
        self.assertEqual(w["status"], "draining")

        # Re-seed all workers so subsequent tests have full worker pool
        distributed_ingestion._seed_workers()

    def test_05_distributed_ingestion_rest_endpoints(self):
        """Capability 1: Ingestion status and backpressure REST API endpoints."""
        res = self.client.get("/api/v1/scale/ingestion/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("queue_depth", data)
        self.assertIn("ingestion_rate_multiplier", data)

        res_post = self.client.post("/api/v1/scale/ingestion/backpressure", json={"target_rate_multiplier": 0.75})
        self.assertEqual(res_post.status_code, 200)
        self.assertEqual(res_post.json()["ingestion_rate_multiplier"], 0.75)

    # ── 2. Connector Marketplace ──────────────────────────────────────────────
    def test_06_marketplace_curated_catalog(self):
        """Capability 2: Curated community marketplace catalog."""
        items = connector_marketplace.list_marketplace_connectors(self.db)
        self.assertGreaterEqual(len(items), 5)
        slugs = [i.slug for i in items]
        self.assertIn("shodan-osint-connector", slugs)
        self.assertIn("greynoise-analyzer", slugs)
        self.assertIn("virustotal-v3-feed", slugs)

    def test_07_marketplace_manifest_validation(self):
        """Capability 2: Manifest format and permission validation."""
        valid_manifest = {
            "name": "Custom Threat Connector",
            "slug": "custom-threat-connector",
            "author": "SecOps",
            "category": "threat_intel",
            "description": "Custom connector",
            "permissions": ["network:outbound"],
            "allowed_domains": ["example.com"],
            "entry_point": "custom.Connector",
        }
        res = connector_marketplace.validate_manifest(valid_manifest)
        self.assertEqual(res.name, "Custom Threat Connector")

        invalid_manifest = {"name": "Broken"}
        with self.assertRaises(Exception):
            connector_marketplace.validate_manifest(invalid_manifest)

    def test_08_marketplace_install_uninstall_lifecycle(self):
        """Capability 2: Install and uninstall community connector lifecycle."""
        item = connector_marketplace.list_marketplace_connectors(self.db)[0]
        initial_downloads = item.downloads_count

        # Install
        installed = connector_marketplace.toggle_install_connector(self.db, item.id, install=True)
        self.assertTrue(installed.is_installed)
        self.assertEqual(installed.downloads_count, initial_downloads + 1)

        # Uninstall
        uninstalled = connector_marketplace.toggle_install_connector(self.db, item.id, install=False)
        self.assertFalse(uninstalled.is_installed)

    def test_09_marketplace_publish_and_search_endpoints(self):
        """Capability 2: REST endpoints for marketplace catalog and installation."""
        res = self.client.get("/api/v1/scale/marketplace?search=shodan")
        self.assertEqual(res.status_code, 200)
        items = res.json()
        self.assertTrue(any("shodan" in i["slug"] for i in items))

        # Test install endpoint
        target_id = items[0]["id"]
        res_inst = self.client.post(f"/api/v1/scale/marketplace/install/{target_id}")
        self.assertEqual(res_inst.status_code, 200)
        self.assertTrue(res_inst.json()["is_installed"])

    # ── 3. Multi-Region Deployment ────────────────────────────────────────────
    def test_10_multi_region_topology_and_health(self):
        """Capability 3: Multi-datacenter cluster topology."""
        nodes = multi_region.list_region_nodes(self.db)
        self.assertEqual(len(nodes), 3)
        codes = [n.region_code for n in nodes]
        self.assertIn("us-east-1", codes)
        self.assertIn("eu-central-1", codes)
        self.assertIn("ap-southeast-1", codes)

        primary = next(n for n in nodes if n.role == "primary")
        self.assertEqual(primary.region_code, "us-east-1")

    def test_11_multi_region_geo_routing_resolver(self):
        """Capability 3: Latency-aware geo-routing resolution."""
        # Preferred region
        req_pref = GeoRouteRequest(preferred_region="eu-central-1")
        route_eu = multi_region.resolve_geo_route(self.db, req_pref)
        self.assertEqual(route_eu.routed_region, "eu-central-1")

        # IP-based routing
        req_us = GeoRouteRequest(client_ip="198.51.100.22")
        route_us = multi_region.resolve_geo_route(self.db, req_us)
        self.assertEqual(route_us.routed_region, "us-east-1")

    def test_12_multi_region_failover_simulation(self):
        """Capability 3: Disaster recovery failover promotion."""
        req = FailoverRequest(failed_region="us-east-1", target_primary_region="eu-central-1")
        res = self.client.post("/api/v1/scale/multi-region/failover", json=req.model_dump())
        self.assertEqual(res.status_code, 200)
        nodes = res.json()
        eu_node = next(n for n in nodes if n["region_code"] == "eu-central-1")
        us_node = next(n for n in nodes if n["region_code"] == "us-east-1")
        self.assertEqual(eu_node["role"], "primary")
        self.assertEqual(us_node["status"], "offline")

        # Restore all to healthy
        for n in self.db.query(RegionNodeModel).all():
            n.status = "healthy"
            n.role = "primary" if n.region_code == "us-east-1" else "replica"
        self.db.commit()

    # ── 4. Advanced Multi-Tier Caching ─────────────────────────────────────────
    def test_13_advanced_caching_l1_l2_tiering(self):
        """Capability 4: L1 Memory and L2 Distributed cache tiering."""
        test_key = "osint:cve:CVE-2024-3400"
        test_val = {"severity": "CRITICAL", "cvss": 10.0}

        advanced_cache.set(test_key, test_val, ttl_seconds=60, tags=["cve", "palo_alto"])
        cached_val = advanced_cache.get(test_key)
        self.assertEqual(cached_val, test_val)

        stats = advanced_cache.get_stats()
        self.assertGreaterEqual(stats.l1_stats.hits, 1)

    def test_14_advanced_caching_tag_invalidation(self):
        """Capability 4: Tag-based cache invalidation across all tiers."""
        k1 = "threat:actor:apt29"
        k2 = "threat:campaign:solarwinds"
        advanced_cache.set(k1, {"actor": "APT29"}, ttl_seconds=120, tags=["tag:apt29"])
        advanced_cache.set(k2, {"campaign": "SolarWinds"}, ttl_seconds=120, tags=["tag:apt29"])

        self.assertIsNotNone(advanced_cache.get(k1))
        self.assertIsNotNone(advanced_cache.get(k2))

        # Invalidate by tag
        res = advanced_cache.invalidate_by_tags(["tag:apt29"])
        self.assertGreaterEqual(res.invalidated_keys_count, 2)
        self.assertIsNone(advanced_cache.get(k1))
        self.assertIsNone(advanced_cache.get(k2))

    def test_15_advanced_caching_stampede_protection(self):
        """Capability 4: Probabilistic early expiration (XFetch) to prevent stampedes."""
        # Check that XFetch calculation runs cleanly
        should_recompute = advanced_cache._should_recompute_early(
            now=time.time(), exp=time.time() + 0.1, delta=1.0
        )
        self.assertIsInstance(should_recompute, bool)

    # ── 5. Large-Scale Search & ILM ───────────────────────────────────────────
    def test_16_large_scale_search_ilm_policies(self):
        """Capability 5: Time-series index lifecycle tiers (Hot, Warm, Cold, Frozen)."""
        policies = large_scale_search.get_ilm_policies()
        self.assertEqual(len(policies), 4)
        tiers = [p.tier for p in policies]
        self.assertEqual(tiers, ["Hot", "Warm", "Cold", "Frozen"])
        self.assertEqual(policies[0].compression, "LZ4")
        self.assertEqual(policies[3].retention_days, 365)

    def test_17_large_scale_search_federated_multi_cluster(self):
        """Capability 5: Multi-cluster federated search execution."""
        req = FederatedSearchRequest(query="CVE-2023-4966", regions=["us-east-1", "eu-central-1"])
        res = large_scale_search.execute_federated_search(req)
        self.assertEqual(res.query, "CVE-2023-4966")
        self.assertGreaterEqual(res.total_hits, 1)
        self.assertTrue(all(r.region_origin in ["us-east-1", "eu-central-1"] for r in res.results))

    # ── 6. Advanced Graph Analytics ───────────────────────────────────────────
    def test_18_graph_analytics_centrality_rankings(self):
        """Capability 6: PageRank and Degree Centrality threat node rankings."""
        rankings = graph_analytics.get_centrality_rankings()
        self.assertGreaterEqual(len(rankings), 5)
        top_node = rankings[0]
        self.assertEqual(top_node.rank, 1)
        self.assertGreaterEqual(top_node.score, 0.9)

    def test_19_graph_analytics_community_detection(self):
        """Capability 6: Louvain community modularity clustering."""
        communities = graph_analytics.get_community_clusters()
        self.assertGreaterEqual(len(communities), 3)
        c1 = communities[0]
        self.assertIn("Volt Typhoon", c1.dominant_actors)
        self.assertGreaterEqual(c1.cohesion_score, 0.85)

    def test_20_graph_analytics_blast_radius_simulation(self):
        """Capability 6: Multi-hop breach blast radius impact traversal."""
        req = BlastRadiusRequest(target_entity="CVE-2023-4966", max_hops=2)
        res = graph_analytics.calculate_blast_radius(req)
        self.assertEqual(res.target_entity, "CVE-2023-4966")
        self.assertGreaterEqual(res.total_impacted_nodes, 20)
        self.assertGreaterEqual(res.impact_score, 90.0)
        self.assertIn("Financial Services", res.impacted_sectors)
        self.assertGreaterEqual(len(res.attack_paths), 1)

    # ── 7. Model Routing ──────────────────────────────────────────────────────
    def test_21_model_routing_sla_and_task_routes(self):
        """Capability 7: Task-aware model routes and SLA configurations."""
        routes = model_router.get_model_routes()
        self.assertEqual(len(routes), 4)
        task_types = [r.task_type for r in routes]
        self.assertIn("classification", task_types)
        self.assertIn("entity_extraction", task_types)
        self.assertIn("deep_research", task_types)

    def test_22_model_routing_circuit_breaker_and_latency_priority(self):
        """Capability 7: Latency-priority routing and fallback execution."""
        # Ultra-low latency priority
        req_latency = ModelRouteRequest(task_type="classification", prompt="Test prompt", latency_priority=True)
        res_lat = model_router.route_query(req_latency)
        self.assertTrue("Local" in res_lat.provider or "Edge" in res_lat.provider)
        self.assertLess(res_lat.latency_ms, 50.0)

        # Standard deep research
        req_deep = ModelRouteRequest(task_type="deep_research", prompt="Investigate APT29")
        res_deep = model_router.route_query(req_deep)
        self.assertEqual(res_deep.selected_model, "cloud-reasoning-deep-v3")

    # ── 8. Automated Evaluation ───────────────────────────────────────────────
    def test_23_automated_evaluation_benchmarks(self):
        """Capability 8: Automated test benchmark suites with precision/recall/F1."""
        runs = auto_evaluation.list_benchmark_runs(self.db)
        self.assertGreaterEqual(len(runs), 3)
        ner_run = next(r for r in runs if "NER" in r.suite_name)
        self.assertGreaterEqual(ner_run.precision_score, 0.95)
        self.assertGreaterEqual(ner_run.f1_score, 0.93)
        self.assertFalse(ner_run.drift_detected)

        # Trigger new benchmark run
        req = EvaluationTriggerRequest(suite_name="Advisory Taxonomy Classification", sample_count=60)
        new_run = auto_evaluation.run_evaluation_suite(self.db, req)
        self.assertGreaterEqual(new_run.f1_score, 0.90)

    # ── 9. Source Quality Learning ────────────────────────────────────────────
    def test_24_source_quality_learning_bayesian_updates(self):
        """Capability 9: Dynamic Bayesian source quality and reputation adaptation."""
        sources = source_quality_learning.list_source_reputations(self.db)
        self.assertGreaterEqual(len(sources), 5)
        cisa = next(s for s in sources if "CISA" in s.source_name)
        self.assertEqual(cisa.tier, "gold")
        self.assertGreaterEqual(cisa.reputation_score, 95.0)

        # Submit positive corroboration feedback
        req_pos = ReputationUpdateRequest(
            source_name="CISA Cybersecurity Advisories & KEV",
            is_corroborated=True,
            had_false_positive=False,
            latency_ms=110.0,
        )
        updated = source_quality_learning.update_source_reputation(self.db, req_pos)
        self.assertGreaterEqual(updated.reputation_score, 95.0)

    # ── 10. Global Scale Overview Endpoint ────────────────────────────────────
    def test_25_scale_global_overview_endpoint(self):
        """Global: REST API /api/v1/scale/overview aggregation."""
        res = self.client.get("/api/v1/scale/overview")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertGreaterEqual(data["total_workers_active"], 4)
        self.assertGreaterEqual(data["marketplace_connectors_count"], 5)
        self.assertGreaterEqual(data["active_regions_count"], 3)
        self.assertGreaterEqual(data["average_benchmark_f1"], 0.90)


if __name__ == "__main__":
    unittest.main()
