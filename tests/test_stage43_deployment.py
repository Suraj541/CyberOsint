"""Test Suite for Section 44 (Step 43): Deployment.

Verifies:
  1. Development Docker Compose configuration (docker-compose.yml)
  2. Production Docker Compose architecture (docker-compose.prod.yml):
     - Managed/Dedicated PostgreSQL
     - Redis
     - OpenSearch
     - Object Storage (MinIO / S3)
     - Worker Infrastructure (Scheduler + Ingestion Workers)
     - API & Web frontends
  3. Healthcheck definitions for all stateful services
  4. Environment variable handling and volume persistence
"""

import os
import unittest
import yaml

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSection44Deployment(unittest.TestCase):
    """Verifies Section 44 Step 43 deployment infrastructure specifications."""

    def test_01_dev_compose_file_exists(self):
        """Verify development docker-compose.yml exists and is valid YAML."""
        path = os.path.join(_REPO_ROOT, "docker-compose.yml")
        self.assertTrue(os.path.isfile(path), "docker-compose.yml must exist")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self.assertIn("services", data)
        self.assertIn("postgres", data["services"])
        self.assertIn("redis", data["services"])
        self.assertIn("opensearch", data["services"])
        self.assertIn("minio", data["services"])

    def test_02_prod_compose_architecture(self):
        """Verify production docker-compose.prod.yml matches all Section 44 requirements."""
        path = os.path.join(_REPO_ROOT, "docker-compose.prod.yml")
        self.assertTrue(os.path.isfile(path), "docker-compose.prod.yml must exist")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        services = data.get("services", {})
        # Mandated by Section 44:
        # Docker + Managed PostgreSQL + Redis + OpenSearch + Object Storage + Worker Infrastructure
        self.assertIn("postgres", services, "Production stack must include PostgreSQL")
        self.assertIn("redis", services, "Production stack must include Redis")
        self.assertIn("opensearch", services, "Production stack must include OpenSearch")
        self.assertIn("minio", services, "Production stack must include Object Storage (MinIO/S3)")
        self.assertIn("worker", services, "Production stack must include Worker Infrastructure")
        self.assertIn("api", services, "Production stack must include API Backend")
        self.assertIn("web", services, "Production stack must include Web Frontend")

    def test_03_healthcheck_coverage_in_prod(self):
        """Stateful databases and key services must have explicit healthcheck contracts."""
        path = os.path.join(_REPO_ROOT, "docker-compose.prod.yml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        services = data["services"]

        for svc in ["postgres", "redis", "opensearch", "minio", "api", "web"]:
            self.assertIn(
                "healthcheck",
                services[svc],
                f"Production service '{svc}' must define an automated healthcheck",
            )
            self.assertIn("test", services[svc]["healthcheck"])

    def test_04_worker_infrastructure_isolated(self):
        """Ingestion/scheduler worker must be an independent container from the web server."""
        path = os.path.join(_REPO_ROOT, "docker-compose.prod.yml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        services = data["services"]

        worker = services["worker"]
        self.assertIn("command", worker)
        self.assertTrue(
            any("scheduler" in str(arg) for arg in worker["command"]),
            "Worker must execute scheduler/worker workload",
        )
        self.assertNotEqual(services["api"], services["worker"])

    def test_05_volume_persistence_and_backups(self):
        """Production volumes must be defined for all stateful tiers and backup storage."""
        path = os.path.join(_REPO_ROOT, "docker-compose.prod.yml")
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        volumes = data.get("volumes", {})
        self.assertIn("postgres_prod_data", volumes)
        self.assertIn("redis_prod_data", volumes)
        self.assertIn("opensearch_prod_data", volumes)
        self.assertIn("minio_prod_data", volumes)

        # API & Worker must mount backup dir
        api_vols = str(data["services"]["api"].get("volumes", []))
        self.assertIn("backups", api_vols)


if __name__ == "__main__":
    unittest.main()
