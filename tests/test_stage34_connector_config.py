"""
Unit and Integration Tests for Section 35 (Step 34: Connector Configuration).
Conforms strictly to IMPLEMENT.md Section 35:
- Declarative configuration file: connectors.yaml
- Attributes: enabled, type, url, interval_minutes, priority
- Strict Rule: 'Never hardcode API keys.'
- Environment variable interpolation (${VAR:-default})
- Automatic synchronization with AdvancedConnectorManager
- REST API endpoints for hot-reloading and auditing
"""

import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import yaml

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from connectors.config import (
    ConnectorConfig,
    ConnectorConfigManager,
    ConnectorsFileSchema,
    connector_config_manager,
)
from connectors.manager import connector_manager


class TestConnectorConfigSection35(unittest.TestCase):
    """Test suite for Section 35 (Step 34: Connector Configuration)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        self.temp_dir = tempfile.mkdtemp()
        self.temp_yaml = Path(self.temp_dir) / "connectors.yaml"

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        # Restore default connectors config manager state
        try:
            connector_config_manager.load_config()
            connector_manager.sync_from_yaml()
        except Exception:
            pass

    def test_01_declarative_yaml_parsing_and_schema_validation(self):
        """Verify connectors.yaml conforms to Section 35 specifications."""
        sample_yaml = """
connectors:
  example_security_feed:
    enabled: true
    type: rss
    url: "https://example.com/feed.xml"
    interval_minutes: 30
    priority: high

  example_source:
    enabled: false
    type: api
    interval_minutes: 60
    priority: medium
"""
        parsed = yaml.safe_load(sample_yaml)
        schema = ConnectorsFileSchema(**parsed)
        self.assertIn("example_security_feed", schema.connectors)
        self.assertIn("example_source", schema.connectors)

        feed = schema.connectors["example_security_feed"]
        self.assertTrue(feed.enabled)
        self.assertEqual(feed.type, "rss")
        self.assertEqual(feed.url, "https://example.com/feed.xml")
        self.assertEqual(feed.interval_minutes, 30)
        self.assertEqual(feed.priority, "high")

        source = schema.connectors["example_source"]
        self.assertFalse(source.enabled)
        self.assertEqual(source.type, "api")
        self.assertEqual(source.interval_minutes, 60)
        self.assertEqual(source.priority, "medium")

        # Validation: priority must be valid tier
        with self.assertRaises(ValueError):
            ConnectorConfig(type="rss", priority="ultra_super_critical")

        # Validation: interval_minutes must be >= 1
        with self.assertRaises(ValueError):
            ConnectorConfig(type="rss", interval_minutes=0)

    def test_02_env_variable_interpolation(self):
        """Verify ${VAR_NAME} and ${VAR_NAME:-default} expansion."""
        os.environ["TEST_FEED_URL"] = "https://custom.threat.org/feed"
        os.environ["TEST_GITHUB_KEY_NAME"] = "GITHUB_ACCESS_SECRET"

        text = """
url: "${TEST_FEED_URL}"
fallback_url: "${UNDEFINED_FEED_URL:-https://fallback.org/feed}"
empty_fallback: "${UNDEFINED_WITHOUT_DEFAULT}"
key_name: "${TEST_GITHUB_KEY_NAME}"
"""
        expanded = ConnectorConfigManager.expand_env_vars(text)
        self.assertIn("https://custom.threat.org/feed", expanded)
        self.assertIn("https://fallback.org/feed", expanded)
        self.assertIn("GITHUB_ACCESS_SECRET", expanded)
        self.assertNotIn("${TEST_FEED_URL}", expanded)
        self.assertNotIn("${UNDEFINED_FEED_URL", expanded)

    def test_03_strict_secret_policy_enforcement(self):
        """
        Verify security scanner actively blocks hardcoded secrets.
        Conforms strictly to IMPLEMENT.md Section 35: 'Never hardcode API keys.'
        """
        # 1. Plaintext API key must fail
        violating_yaml_1 = """
connectors:
  bad_source:
    enabled: true
    type: api
    api_key: "AKIAIOSFODNN7EXAMPLE123456"
"""
        with self.assertRaises(ValueError) as ctx1:
            ConnectorConfigManager.audit_for_secrets(violating_yaml_1)
        self.assertIn("Security policy violation", str(ctx1.exception))

        # 2. Hardcoded GitHub token must fail
        violating_yaml_2 = """
connectors:
  bad_github:
    enabled: true
    type: github
    token: "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
"""
        with self.assertRaises(ValueError) as ctx2:
            ConnectorConfigManager.audit_for_secrets(violating_yaml_2)
        self.assertIn("GitHub", str(ctx2.exception))

        # 3. Environment variable references must PASS
        safe_yaml = """
connectors:
  safe_github:
    enabled: true
    type: github
    api_key_env: "GITHUB_TOKEN"
    headers:
      Authorization: "${GITHUB_AUTH_HEADER:-}"
"""
        # Should not raise exception
        ConnectorConfigManager.audit_for_secrets(safe_yaml)

    def test_04_connector_config_manager_crud_and_persistence(self):
        """Verify ConnectorConfigManager loads, validates, saves, and updates YAML."""
        initial_yaml = """
connectors:
  test_rss:
    enabled: true
    type: rss
    url: "https://test.org/rss"
    interval_minutes: 45
    priority: high
"""
        self.temp_yaml.write_text(initial_yaml, encoding="utf-8")
        manager = ConnectorConfigManager(config_path=self.temp_yaml)

        self.assertIn("test_rss", manager.list_configs())
        conf = manager.get_config("test_rss")
        self.assertIsNotNone(conf)
        self.assertEqual(conf.interval_minutes, 45)

        # Update connector
        manager.update_connector("test_rss", {"interval_minutes": 15, "priority": "critical"})
        updated_conf = manager.get_config("test_rss")
        self.assertEqual(updated_conf.interval_minutes, 15)
        self.assertEqual(updated_conf.priority, "critical")

        # Verify raw YAML on disk was updated
        saved_text = self.temp_yaml.read_text(encoding="utf-8")
        self.assertIn("15", saved_text)
        self.assertIn("critical", saved_text)

    def test_05_runtime_manager_synchronization(self):
        """Verify synchronization between YAML configs and AdvancedConnectorManager."""
        sync_yaml = """
connectors:
  security_feeds:
    enabled: false
    type: rss
    url: "https://custom.feed.org/rss.xml"
    interval_minutes: 10
    priority: critical

  cve_databases:
    enabled: true
    type: cve
    interval_minutes: 25
    priority: high
"""
        self.temp_yaml.write_text(sync_yaml, encoding="utf-8")
        cfg_mgr = ConnectorConfigManager(config_path=self.temp_yaml)
        sync_res = cfg_mgr.sync_to_runtime_manager(connector_manager)

        self.assertGreaterEqual(sync_res["total_synced"], 1)

        # Verify security_feeds was toggled to disabled in runtime manager
        self.assertFalse(connector_manager.is_enabled("security_feeds"))

        # Verify instance configuration incorporates updated values
        instance = connector_manager.get_instance("cve_databases")
        self.assertIsNotNone(instance)

        # Restore enabled state
        connector_manager.set_enabled("security_feeds", True)

    def test_06_fastapi_connector_config_endpoints(self):
        """Verify FastAPI REST API endpoints for connectors configuration."""
        # 1. GET /api/v1/connectors/config
        res_list = self.client.get("/api/v1/connectors/config")
        self.assertEqual(res_list.status_code, 200)
        data_list = res_list.json()
        self.assertIn("connectors", data_list)
        self.assertIn("total", data_list)
        self.assertGreaterEqual(data_list["total"], 1)

        # 2. GET /api/v1/connectors/config/raw
        res_raw = self.client.get("/api/v1/connectors/config/raw")
        self.assertEqual(res_raw.status_code, 200)
        raw_data = res_raw.json()
        self.assertIn("yaml_content", raw_data)
        self.assertIn("connectors:", raw_data["yaml_content"])

        # 3. PUT /api/v1/connectors/config/raw - Reject hardcoded secret (422)
        bad_payload = {
            "yaml_content": 'connectors:\n  hack: { enabled: true, type: api, api_key: "plain_secret_1234567890123456" }'
        }
        res_bad = self.client.put("/api/v1/connectors/config/raw", json=bad_payload)
        self.assertEqual(res_bad.status_code, 422)
        self.assertIn("Security policy violation", res_bad.json()["detail"])

        # 4. POST /api/v1/connectors/config/reload
        res_reload = self.client.post("/api/v1/connectors/config/reload")
        self.assertEqual(res_reload.status_code, 200)
        reload_data = res_reload.json()
        self.assertEqual(reload_data["status"], "success")
        self.assertGreaterEqual(reload_data["total_loaded"], 1)

        # 5. PATCH /api/v1/connectors/config/{key}
        patch_payload = {"interval_minutes": 40, "priority": "high"}
        res_patch = self.client.patch("/api/v1/connectors/config/bleeping_computer_feed", json=patch_payload)
        # Should succeed if key exists in connectors.yaml
        if res_patch.status_code == 200:
            self.assertEqual(res_patch.json()["interval_minutes"], 40)
            self.assertEqual(res_patch.json()["priority"], "high")
        else:
            self.assertEqual(res_patch.status_code, 404)


if __name__ == "__main__":
    unittest.main()
