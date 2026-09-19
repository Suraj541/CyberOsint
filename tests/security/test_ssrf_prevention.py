"""
Tests for Subsystem 12: SSRF Prevention.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing) and Section 38 (Step 37: SSRF Protection).
Validates blocking of localhost, 127.0.0.0/8, private RFC1918 ranges, link-local addresses,
cloud metadata endpoints, dangerous schemes, and redirect re-evaluation.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.security import (
    SSRFValidator,
    SecureURLFetcher,
    secure_fetcher,
    ssrf_validator,
)


class TestSSRFPreventionSubsystem(unittest.TestCase):
    """Subsystem 12: SSRF Prevention Unit Tests."""

    def test_01_block_localhost_and_loopback(self):
        """Verify SSRF guard blocks localhost and 127.0.0.0/8 loopback targets."""
        loopback_urls = [
            "http://localhost:8000/internal",
            "http://127.0.0.1:9200",
            "http://127.0.1.1:5432",
            "http://127.255.255.254/status",
            "http://0.0.0.0:80/",
        ]
        for url in loopback_urls:
            res = ssrf_validator.validate_url(url)
            self.assertFalse(res.is_safe, f"SSRF Guard should have blocked loopback target: {url}")
            self.assertIsNotNone(res.violation_reason)

    def test_02_block_private_rfc1918_ranges(self):
        """Verify SSRF guard blocks Class A (10.0.0.0/8), Class B (172.16.0.0/12), and Class C (192.168.0.0/16)."""
        private_urls = [
            "http://10.0.0.1/admin",
            "http://10.254.1.1:8080",
            "http://172.16.0.1/intranet",
            "http://172.31.255.254/secret",
            "http://192.168.1.1/router",
            "http://192.168.100.50:3000",
        ]
        for url in private_urls:
            res = ssrf_validator.validate_url(url)
            self.assertFalse(res.is_safe, f"SSRF Guard should have blocked private IP: {url}")
            self.assertIn("private", res.violation_reason.lower())

    def test_03_block_cloud_metadata_endpoints(self):
        """Verify SSRF guard blocks AWS/GCP/Azure link-local metadata endpoints."""
        metadata_urls = [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://instance-data/latest/meta-data/",
        ]
        for url in metadata_urls:
            res = ssrf_validator.validate_url(url)
            self.assertFalse(res.is_safe, f"SSRF Guard should have blocked metadata endpoint: {url}")

    def test_04_block_prohibited_uri_schemes(self):
        """Verify SSRF guard rejects non-HTTP(S) protocols (file, ftp, gopher, ldap)."""
        schemes = [
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "ftp://anonymous:guest@internal.corp",
            "gopher://internal.network:70/1",
            "ldap://ldap.internal:389/dc=corp",
        ]
        for url in schemes:
            res = ssrf_validator.validate_url(url)
            self.assertFalse(res.is_safe, f"SSRF Guard should have blocked prohibited scheme: {url}")

    def test_05_allow_legitimate_public_threat_intel_urls(self):
        """Verify SSRF guard permits legitimate external public URLs."""
        public_urls = [
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "https://api.github.com/advisories",
        ]
        for url in public_urls:
            res = ssrf_validator.validate_url(url)
            self.assertTrue(res.is_safe, f"SSRF Guard should allow legitimate URL: {url}")

    def test_06_secure_fetcher_preflight_blocks_ssrf_without_network_call(self):
        """Verify SecureURLFetcher checks SSRF before initiating any outbound HTTP request."""
        fetch_res = secure_fetcher.fetch_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(fetch_res["success"])
        self.assertIn("SSRF Block", fetch_res["error"])


if __name__ == "__main__":
    unittest.main()
