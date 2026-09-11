"""
Stage 1: Repository Structure & Docker Baseline Verification Tests
Ensures all foundational assets, Git repository state, Docker compose configurations,
environment templates, and security invariants strictly comply with IMPLEMENT.md Step 1.
"""

import os
import subprocess
import unittest
from pathlib import Path
import yaml


class TestStage1RepositoryBaseline(unittest.TestCase):
    """Test suite validating complete implementation of Stage 1 (Step 1)."""

    @classmethod
    def setUpClass(cls):
        # Locate the cyber-osint root directory
        cls.repo_root = Path(__file__).resolve().parent.parent

    def test_stage1_required_files_exist(self):
        """Confirm all 8 mandated files for Step 1 exist and are non-empty."""
        required_files = [
            "README.md",
            "PLAN.md",
            "IMPLEMENT.md",
            "SECURITY.md",
            "LICENSE",
            ".gitignore",
            ".env.example",
            "docker-compose.yml",
        ]

        for filename in required_files:
            file_path = self.repo_root / filename
            self.assertTrue(
                file_path.exists(),
                f"Missing mandated file from Step 1: {filename}",
            )
            self.assertGreater(
                file_path.stat().st_size,
                0,
                f"File {filename} is unexpectedly empty",
            )

    def test_git_repository_initialized(self):
        """Confirm that git is initialized inside cyber-osint."""
        git_dir = self.repo_root / ".git"
        self.assertTrue(git_dir.exists(), "Git directory (.git) not found in cyber-osint")

        # Verify git status command succeeds
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "true")

    def test_env_example_required_variables(self):
        """Verify .env.example contains all required environment variables."""
        env_file = self.repo_root / ".env.example"
        content = env_file.read_text(encoding="utf-8")

        required_keys = [
            "ENVIRONMENT",
            "POSTGRES_HOST",
            "POSTGRES_PORT",
            "POSTGRES_DB",
            "POSTGRES_USER",
            "POSTGRES_PASSWORD",
            "DATABASE_URL",
            "REDIS_HOST",
            "REDIS_PORT",
            "REDIS_URL",
            "API_HOST",
            "API_PORT",
            "SECRET_KEY",
            "CORS_ORIGINS",
            "INGESTION_CONCURRENCY",
            "SSRF_PROTECTION_ENABLED",
        ]

        for key in required_keys:
            self.assertIn(
                f"{key}=",
                content,
                f"Required configuration key {key} is missing in .env.example",
            )

    def test_docker_compose_syntax_and_services(self):
        """Parse docker-compose.yml and verify services, healthchecks, networks, and volumes."""
        compose_file = self.repo_root / "docker-compose.yml"
        self.assertTrue(compose_file.exists(), "docker-compose.yml not found")

        with open(compose_file, "r", encoding="utf-8") as f:
            compose = yaml.safe_load(f)

        self.assertIn("services", compose)
        self.assertIn("volumes", compose)
        self.assertIn("networks", compose)

        services = compose["services"]

        # Validate PostgreSQL service
        self.assertIn("postgres", services)
        pg = services["postgres"]
        self.assertIn("image", pg)
        self.assertTrue(pg["image"].startswith("postgres:"))
        self.assertEqual(pg.get("container_name"), "cyber-osint-postgres")
        self.assertIn("healthcheck", pg)
        self.assertIn("test", pg["healthcheck"])
        self.assertIn("volumes", pg)
        self.assertTrue(any("postgres_data" in v for v in pg["volumes"]))
        self.assertIn("cyber_osint_network", pg["networks"])

        # Validate Redis service
        self.assertIn("redis", services)
        redis = services["redis"]
        self.assertIn("image", redis)
        self.assertTrue(redis["image"].startswith("redis:"))
        self.assertEqual(redis.get("container_name"), "cyber-osint-redis")
        self.assertIn("healthcheck", redis)
        self.assertIn("test", redis["healthcheck"])
        self.assertIn("volumes", redis)
        self.assertTrue(any("redis_data" in v for v in redis["volumes"]))
        self.assertIn("cyber_osint_network", redis["networks"])

        # Validate volumes and networks
        self.assertIn("postgres_data", compose["volumes"])
        self.assertIn("redis_data", compose["volumes"])
        self.assertIn("cyber_osint_network", compose["networks"])

    def test_gitignore_contains_critical_patterns(self):
        """Verify .gitignore properly protects secrets, environments, and caches."""
        gitignore_file = self.repo_root / ".gitignore"
        content = gitignore_file.read_text(encoding="utf-8")

        critical_patterns = [
            ".env",
            "__pycache__",
            ".venv",
            "*.db",
            "node_modules",
            "*.log",
        ]

        for pattern in critical_patterns:
            self.assertIn(
                pattern,
                content,
                f"Critical pattern '{pattern}' missing from .gitignore",
            )

    def test_security_policy_content(self):
        """Verify SECURITY.md defines vulnerability disclosure and strict OSINT scope rules."""
        security_file = self.repo_root / "SECURITY.md"
        content = security_file.read_text(encoding="utf-8")

        # Must mention vulnerability reporting
        self.assertIn("Vulnerability Reporting", content)
        # Must enforce strict OSINT scope
        self.assertIn("Strict OSINT Scope", content)
        # Must prohibit auth bypass and credential theft
        self.assertIn("authentication", content.lower())
        self.assertIn("credential", content.lower())
        # Must enforce SSRF protection and sandboxing
        self.assertIn("SSRF", content)


if __name__ == "__main__":
    unittest.main()
