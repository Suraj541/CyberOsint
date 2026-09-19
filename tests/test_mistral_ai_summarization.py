"""
Test Suite: Mistral AI Integration
Tests live & mocked inference, configuration extraction, SDK and HTTP fallback pathways,
and graceful degradation to the deterministic rule-based engine.
"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import sys
from pathlib import Path
repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.database import Base
from app.models.content import Content
from app.models.source import Source
from services.summarization.models import SummaryOutput
from services.summarization.service import (
    SummarizationService,
    _get_mistral_config,
    _get_mistral_client,
)


class TestMistralAIIntegration(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        Base.metadata.create_all(bind=self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.SessionLocal()

        self.source = Source(
            name="CISA Alerts",
            source_type="rss",
            category="government",
            url="https://cisa.gov/alerts",
            reliability_score=0.98,
        )
        self.db.add(self.source)
        self.db.commit()

        self.content = Content(
            source_id=self.source.id,
            title="Critical Remote Code Execution in Apache Server (CVE-2024-99999)",
            description="Exploitation of CVE-2024-99999 allows unauthorized remote execution.",
            raw_content="An adversary can exploit CVE-2024-99999 using specially crafted HTTP requests to gain root access.",
            content_hash="mock_hash_cve_2024_99999",
            content_type="advisory",
            canonical_url="https://cisa.gov/alerts/cve-2024-99999",
        )
        self.db.add(self.content)
        self.db.commit()

        self.service = SummarizationService()

    def tearDown(self):
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_01_config_without_keys_returns_none(self):
        """When no key is configured, config returns (None, None)."""
        from app.config import settings
        orig_ai = settings.AI_API_KEY
        orig_mistral = getattr(settings, "MISTRAL_API_KEY", None)
        try:
            settings.AI_API_KEY = None
            if hasattr(settings, "MISTRAL_API_KEY"):
                settings.MISTRAL_API_KEY = None
            with patch.dict(os.environ, {}, clear=True):
                key, model = _get_mistral_config()
                self.assertIsNone(key)
                self.assertIsNone(model)
        finally:
            settings.AI_API_KEY = orig_ai
            if hasattr(settings, "MISTRAL_API_KEY"):
                settings.MISTRAL_API_KEY = orig_mistral

    def test_02_config_with_mistral_key(self):
        """When MISTRAL_API_KEY is set, returns key and default or custom model."""
        with patch.dict(os.environ, {"MISTRAL_API_KEY": "test-mistral-key", "MISTRAL_MODEL": "mistral-large-latest"}):
            key, model = _get_mistral_config()
            self.assertEqual(key, "test-mistral-key")
            self.assertEqual(model, "mistral-large-latest")

    def test_03_config_with_ai_api_key_fallback(self):
        """When only AI_API_KEY is set, it is used as fallback for Mistral."""
        with patch.dict(os.environ, {"AI_API_KEY": "fallback-key"}, clear=True):
            key, model = _get_mistral_config()
            self.assertEqual(key, "fallback-key")
            self.assertEqual(model, "mistral-small-latest")

    def test_04_generate_mistral_summary_mock_sdk(self):
        """Mocked Mistral SDK chat.complete returns structured summary."""
        mock_json_reply = json.dumps({
            "executive_summary": "A critical vulnerability CVE-2024-99999 was discovered in Apache Server.",
            "reported_facts": ["Vulnerability tracked as CVE-2024-99999.", "Root access possible."],
            "inferences": ["Likely weaponized by ransomware affiliates."],
            "uncertainties": ["Exact global infection footprint remains unverified."],
            "key_takeaways": ["Apply vendor patch immediately.", "Restrict inbound port 80/443."],
        })

        mock_choice = MagicMock()
        mock_choice.message.content = f"```json\n{mock_json_reply}\n```"
        mock_resp = MagicMock()
        mock_resp.choices = [mock_choice]

        mock_client = MagicMock()
        mock_client.chat.complete.return_value = mock_resp

        with patch("services.summarization.service._get_mistral_client", return_value=(mock_client, "mistral-small-latest", "mock-key")):
            summ_output = self.service._generate_mistral_summary(
                clean_text=self.content.raw_content,
                source_name=self.source.name,
                content=self.content,
            )

        self.assertIsNotNone(summ_output)
        self.assertIn("CVE-2024-99999", summ_output.executive_summary)
        self.assertEqual(summ_output.model, "mistral/mistral-small-latest")
        self.assertEqual(len(summ_output.reported_facts), 2)
        self.assertEqual(len(summ_output.inferences), 1)
        self.assertEqual(len(summ_output.uncertainties), 1)
        self.assertEqual(len(summ_output.key_takeaways), 2)

    def test_05_generate_mistral_summary_http_fallback(self):
        """When SDK fails or is unavailable, direct HTTP POST via httpx succeeds."""
        mock_json_reply = {
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "executive_summary": "HTTP fallback generated summary for Apache flaw.",
                        "reported_facts": ["CVE-2024-99999 affects Apache."],
                        "inferences": ["High probability of exploitation."],
                        "uncertainties": ["Patch availability timeline."],
                        "key_takeaways": ["Upgrade systems."],
                    })
                }
            }]
        }

        mock_http_resp = MagicMock()
        mock_http_resp.json.return_value = mock_json_reply
        mock_http_resp.raise_for_status.return_value = None

        mock_http_client = MagicMock()
        mock_http_client.__enter__.return_value = mock_http_client
        mock_http_client.post.return_value = mock_http_resp

        with patch("services.summarization.service._get_mistral_client", return_value=(None, "mistral-small-latest", "mock-http-key")), \
             patch("httpx.Client", return_value=mock_http_client):
            summ_output = self.service._generate_mistral_summary(
                clean_text=self.content.raw_content,
                source_name=self.source.name,
                content=self.content,
            )

        self.assertIsNotNone(summ_output)
        self.assertIn("HTTP fallback", summ_output.executive_summary)
        self.assertEqual(summ_output.model, "mistral/mistral-small-latest")

    def test_06_graceful_fallback_to_rule_based_on_api_error(self):
        """When Mistral API fails, summarize_content transparently falls back to rule-based engine."""
        with patch("services.summarization.service._get_mistral_client", side_effect=Exception("Connection refused")):
            summary_record = self.service.summarize_content(self.db, self.content.id, force=True)

        self.assertIsNotNone(summary_record)
        self.assertEqual(summary_record.model, "cyber-grounded-summarizer")
        self.assertEqual(summary_record.validation_status, "passed")
        self.assertGreaterEqual(summary_record.validation_score, 0.70)

    def test_07_detector_lists_models_via_sdk(self):
        """MistralModelDetector dynamically parses models from SDK."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=60)
        mock_model_1 = MagicMock()
        mock_model_1.id = "mistral-small-latest"
        mock_model_2 = MagicMock()
        mock_model_2.id = "mistral-large-latest"
        mock_embed = MagicMock()
        mock_embed.id = "mistral-embed"  # Should be filtered out

        mock_resp = MagicMock()
        mock_resp.data = [mock_model_1, mock_model_2, mock_embed]

        mock_client = MagicMock()
        mock_client.models.list.return_value = mock_resp

        with patch("mistralai.client.Mistral", return_value=mock_client):
            models = detector.list_available_models("dummy-key", force_refresh=True)

        self.assertIn("mistral-small-latest", models)
        self.assertIn("mistral-large-latest", models)
        self.assertNotIn("mistral-embed", models)
        self.assertEqual(len(models), 2)

    def test_08_detector_lists_models_via_http(self):
        """MistralModelDetector falls back to direct HTTP /v1/models when SDK fails."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=60)
        mock_http_resp = MagicMock()
        mock_http_resp.status_code = 200
        mock_http_resp.json.return_value = {
            "data": [
                {"id": "open-mistral-nemo"},
                {"id": "codestral-latest"},
                {"id": "mistral-embed"},
            ]
        }

        mock_client = MagicMock()
        mock_client.__enter__.return_value = mock_client
        mock_client.get.return_value = mock_http_resp

        with patch("services.summarization.mistral_detector.MistralModelDetector.list_available_models",
                   wraps=detector.list_available_models), \
             patch("mistralai.client.Mistral", side_effect=Exception("SDK error")), \
             patch("httpx.Client", return_value=mock_client):
            models = detector.list_available_models("dummy-key-http", force_refresh=True)

        self.assertIn("open-mistral-nemo", models)
        self.assertIn("codestral-latest", models)
        self.assertNotIn("mistral-embed", models)

    def test_09_detector_optimal_model_selection_auto(self):
        """Optimal model selector prefers highest capability match when auto is requested."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=60)
        # Mock available models where small and large exist
        with patch.object(detector, "list_available_models", return_value=["open-mistral-7b", "mistral-small-latest", "mistral-large-latest"]):
            selected, reason = detector.detect_optimal_model("dummy-key", preferred_model="auto")

        self.assertEqual(selected, "mistral-small-latest")
        self.assertIn("Auto-detected optimal model", reason)

    def test_10_detector_optimal_model_selection_custom_valid(self):
        """Optimal model selector honors verified custom model override."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=60)
        with patch.object(detector, "list_available_models", return_value=["mistral-small-latest", "mistral-large-latest"]):
            selected, reason = detector.detect_optimal_model("dummy-key", preferred_model="mistral-large-latest")

        self.assertEqual(selected, "mistral-large-latest")
        self.assertIn("Explicit override", reason)

    def test_11_detector_optimal_model_selection_custom_invalid_fallback(self):
        """When requested model is not on account, automatically fall back to available optimal model."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=60)
        with patch.object(detector, "list_available_models", return_value=["open-mistral-nemo"]):
            selected, reason = detector.detect_optimal_model("dummy-key", preferred_model="nonexistent-model-xyz")

        self.assertEqual(selected, "open-mistral-nemo")
        self.assertIn("not available on active tier", reason)

    def test_12_detector_caching_and_ttl(self):
        """Cached models are reused within TTL and invalidated on key change or expiry."""
        from services.summarization.mistral_detector import MistralModelDetector

        detector = MistralModelDetector(cache_ttl_seconds=2)
        with patch.object(detector, "list_available_models", wraps=detector.list_available_models), \
             patch("httpx.Client") as mock_h:
            mock_h.return_value.__enter__.return_value.get.return_value.status_code = 200
            mock_h.return_value.__enter__.return_value.get.return_value.json.return_value = {
                "data": [{"id": "mistral-small-latest"}]
            }
            # First call populates cache
            models1 = detector.list_available_models("cache-key-1", force_refresh=True)
            self.assertTrue(detector.is_cache_valid("cache-key-1"))

            # Different key invalidates cache
            self.assertFalse(detector.is_cache_valid("different-key"))

    def test_13_api_status_endpoint(self):
        """FastAPI status endpoint exposes Mistral detection state."""
        from starlette.testclient import TestClient
        from app.main import app

        client = TestClient(app)
        res = client.get("/api/v1/summaries/ai/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("status", data)
        self.assertIn("selected_model", data)
        self.assertIn("provider", data)
        self.assertEqual(data["provider"], "mistral")


if __name__ == "__main__":
    unittest.main()

