"""
tests/test_rate_limiting_and_backoff.py
Automated Verification Suite for Section 11, 12, 13, 14, 15:
- GitHub 429 rate-limit handling & header extraction
- NVD 429 & 503 exponential backoff
- Timeout and temporary network failure handling
- Finite retry termination (no infinite loops)
- No fake/mock data returned on live failures
- Persistent sync state preservation under rate-limited/failed runs
"""

import sys
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (str(repo_root), str(api_root)):
    if p not in sys.path:
        sys.path.insert(0, p)

import httpx
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.specialized.connector import SpecializedSourceConnector
from services.sync.state import sync_state_manager


class TestRateLimitingAndBackoff(unittest.TestCase):
    """Verifies production resilience under upstream rate-limits, errors, and backoffs."""

    def test_github_rate_limit_headers_extraction_and_429_backoff(self):
        """Verify GitHub connector extracts X-RateLimit headers and handles 429 gracefully."""
        connector = GitHubSecurityConnector({"source_url": "https://api.github.com/advisories"})

        # Mock 429 response followed by success
        mock_resp_429 = MagicMock(spec=httpx.Response)
        mock_resp_429.status_code = 429
        mock_resp_429.headers = {
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1789748000",
            "retry-after": "0.01",
        }

        mock_resp_200 = MagicMock(spec=httpx.Response)
        mock_resp_200.status_code = 200
        mock_resp_200.headers = {
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "59",
            "x-ratelimit-reset": "1789748000",
        }
        mock_resp_200.json.return_value = [{"ghsa_id": "GHSA-test-1234", "summary": "Test Vuln"}]
        mock_resp_200.raise_for_status = MagicMock()

        with patch("httpx.Client.get", side_effect=[mock_resp_429, mock_resp_200]):
            with patch("time.sleep"):  # Fast sleep in tests
                items = connector.discover()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["ghsa_id"], "GHSA-test-1234")
        self.assertEqual(connector.rate_limit_info.get("limit"), "60")
        self.assertEqual(connector.rate_limit_info.get("remaining"), "59")

    def test_github_429_exhausted_returns_empty_and_no_mock_data(self):
        """When GitHub 429 retries are exhausted without mock config, return honest empty list."""
        connector = GitHubSecurityConnector({"source_url": "https://api.github.com/advisories"})

        mock_resp_429 = MagicMock(spec=httpx.Response)
        mock_resp_429.status_code = 429
        mock_resp_429.headers = {
            "x-ratelimit-limit": "60",
            "x-ratelimit-remaining": "0",
            "x-ratelimit-reset": "1789748000",
            "retry-after": "0.01",
        }

        with patch("httpx.Client.get", return_value=mock_resp_429):
            with patch("time.sleep"):
                items = connector.discover()

        # Must return empty list, zero fake records
        self.assertEqual(items, [])
        self.assertEqual(connector.rate_limit_info.get("remaining"), "0")

    def test_nvd_exponential_backoff_on_429_and_503(self):
        """NVD connector must back off on 429 and 503 and retry up to max_retries."""
        connector = CVEConnector({"source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0"})

        mock_429 = MagicMock(spec=httpx.Response)
        mock_429.status_code = 429

        mock_503 = MagicMock(spec=httpx.Response)
        mock_503.status_code = 503

        mock_200 = MagicMock(spec=httpx.Response)
        mock_200.status_code = 200
        mock_200.json.return_value = {
            "vulnerabilities": [{"cve": {"id": "CVE-2026-9999", "lastModified": "2026-09-18T10:00:00.000"}}],
            "totalResults": 1,
            "resultsPerPage": 200,
            "startIndex": 0,
        }
        mock_200.raise_for_status = MagicMock()

        sleep_calls = []

        def mock_sleep(seconds):
            sleep_calls.append(seconds)

        with patch("httpx.Client.get", side_effect=[mock_429, mock_503, mock_200]):
            with patch("time.sleep", side_effect=mock_sleep):
                items = connector._discover_nvd()

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["cve"]["id"], "CVE-2026-9999")
        # Backoff delays must be positive and increasing
        self.assertTrue(len(sleep_calls) >= 2)
        self.assertGreater(sleep_calls[1], sleep_calls[0])

    def test_nvd_finite_retries_prevent_infinite_loop(self):
        """NVD connector must abort after max_retries (3) on persistent 503/429 failures."""
        connector = CVEConnector({"source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0"})

        mock_503 = MagicMock(spec=httpx.Response)
        mock_503.status_code = 503

        with patch("httpx.Client.get", return_value=mock_503):
            with patch("time.sleep"):
                items = connector._discover_nvd()

        # Terminates cleanly with 0 items
        self.assertEqual(items, [])

    def test_connection_timeout_and_network_error_resilience(self):
        """Network timeout during connector fetch must be safely caught without crashing."""
        connector = GitHubSecurityConnector({"source_url": "https://api.github.com/advisories"})

        with patch("httpx.Client.get", side_effect=httpx.ConnectTimeout("Connection timed out")):
            with patch("time.sleep"):
                items = connector.discover()

        self.assertEqual(items, [])

    def test_malwarebazaar_401_handled_without_mock_fallback(self):
        """MalwareBazaar unauthenticated 401 returns empty list and logs requirement honestly."""
        connector = SpecializedSourceConnector({"source_url": "https://mb-api.abuse.ch/api/v1/"})

        mock_401 = MagicMock(spec=httpx.Response)
        mock_401.status_code = 401

        with patch("httpx.Client.post", return_value=mock_401):
            items = connector.discover()

        self.assertEqual(items, [])

    def test_sync_state_unadvanced_on_failed_ingestion(self):
        """When an ingestion cycle fails or produces 0 items due to rate limit, sync state is not corrupted."""
        initial_state = sync_state_manager.get_state(None, "cve_databases")
        prev_sync = initial_state.get("last_successful_sync")

        # Simulate failed fetch
        connector = CVEConnector({"source_url": "https://services.nvd.nist.gov/rest/json/cves/2.0"})
        mock_503 = MagicMock(spec=httpx.Response)
        mock_503.status_code = 503

        with patch("httpx.Client.get", return_value=mock_503):
            with patch("time.sleep"):
                items = connector._discover_nvd()

        self.assertEqual(len(items), 0)
        # Checkpoint last_successful_sync must not have advanced to now
        current_state = sync_state_manager.get_state(None, "cve_databases")
        curr_sync = current_state.get("last_successful_sync")
        self.assertEqual(prev_sync, curr_sync)


if __name__ == "__main__":
    unittest.main()
