"""
Unit and Integration Tests for Section 38 (Step 37: SSRF Protection).
Conforms strictly to IMPLEMENT.md Section 38:
- The platform will eventually fetch thousands of URLs.
- The fetcher must block:
  1. localhost
  2. 127.0.0.0/8
  3. Private IP ranges (RFC 1918)
  4. Link-local addresses
  5. Cloud metadata endpoints
  6. Internal DNS targets
  7. Internal services
- Validate the destination before every request.
- Do not trust the hostname alone.
- Re-check redirects.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from services.security import (
    DISALLOWED_HOSTS,
    DISALLOWED_NETWORKS,
    INTERNAL_DOMAIN_SUFFIXES,
    SENSITIVE_INTERNAL_PORTS,
    SSRFRedirectChainResult,
    SSRFRedirectHop,
    SSRFSecurityError,
    SSRFValidationResult,
    SSRFValidator,
    SecureURLFetcher,
    audit_logger,
    secure_fetcher,
    ssrf_validator,
)


class TestSSRFProtectionSection38(unittest.TestCase):
    """Rigorous test suite for Section 38 Step 37 (SSRF Protection)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        self.validator = SSRFValidator()
        self.fetcher = SecureURLFetcher(timeout=5.0, max_redirects=3)

    # -------------------------------------------------------------------------
    # Rule 1 & 2: Localhost & 127.0.0.0/8 Loopback Range Block
    # -------------------------------------------------------------------------
    def test_01_block_localhost_and_loopback_ips(self):
        """Mandate 1 & 2: Block localhost, 127.0.0.0/8, and IPv6 loopback ::1."""
        test_urls = [
            "http://localhost/",
            "http://localhost:8080/api",
            "http://localhost.localdomain/secret",
            "http://127.0.0.1/",
            "http://127.0.0.2:8000/health",
            "http://127.255.255.254/admin",
            "http://127.127.127.127:3000/metrics",
            "http://[::1]/",
            "http://[::1]:8080/status",
        ]
        for url in test_urls:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_safe, f"Expected {url} to be blocked as loopback/localhost.")
            self.assertIsNotNone(res.violation_reason)
            self.assertTrue(
                any(kw in res.violation_reason.lower() for kw in ["loopback", "localhost", "blocked", "restricted"]),
                f"Unexpected violation reason for {url}: {res.violation_reason}",
            )

            # Secure fetcher must refuse to fetch
            with self.assertRaises(SSRFSecurityError):
                self.fetcher.fetch(url)

    # -------------------------------------------------------------------------
    # Rule 3: Private IP Ranges (RFC 1918 & IPv6 ULA & Carrier Grade NAT)
    # -------------------------------------------------------------------------
    def test_02_block_private_ip_ranges(self):
        """Mandate 3: Block RFC 1918 (10/8, 172.16/12, 192.168/16), IPv6 ULA, CGNAT."""
        private_urls = [
            # 10.0.0.0/8
            "http://10.0.0.1/status",
            "http://10.254.12.34:80/data",
            # 172.16.0.0/12
            "http://172.16.0.1/config",
            "http://172.20.10.5/api",
            "http://172.31.255.254/admin",
            # 192.168.0.0/16
            "http://192.168.1.1/router",
            "http://192.168.100.200:8080/",
            # IPv6 ULA fc00::/7
            "http://[fc00::1]/",
            "http://[fd12:3456:789a::1]/nodes",
            # RFC 6598 Carrier Grade NAT (100.64.0.0/10)
            "http://100.64.0.1/service",
            "http://100.127.255.254/gateway",
        ]
        for url in private_urls:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_safe, f"Expected private URL {url} to be blocked.")
            self.assertIsNotNone(res.violation_reason)
            self.assertTrue(
                any(kw in res.violation_reason.lower() for kw in ["private", "restricted", "rfc"]),
                f"Reason for {url}: {res.violation_reason}",
            )

            # fetch_url must report failure with SSRF Block
            fetch_res = self.fetcher.fetch_url(url)
            self.assertFalse(fetch_res["success"])
            self.assertIn("SSRF Block", fetch_res["error"])

    # -------------------------------------------------------------------------
    # Rule 4 & 5: Link-Local Addresses & Cloud Metadata Endpoints
    # -------------------------------------------------------------------------
    def test_03_block_link_local_and_cloud_metadata(self):
        """Mandate 4 & 5: Block Link-local (169.254.0.0/16, fe80::/10) & Cloud IMDS."""
        metadata_urls = [
            # AWS / GCP / Azure / DigitalOcean / OCI IMDS IPv4
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://169.254.1.1/internal",
            # Alibaba Cloud IMDS
            "http://100.100.100.200/latest/meta-data/",
            # AWS IMDS IPv6
            "http://[fd00:ec2::254]/latest/meta-data/",
            # Link-Local IPv6
            "http://[fe80::1]/",
            "http://[fe80::dead:beef]/",
            # Domain-based metadata targets
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.azure.com/instance",
            "http://instance-data/latest/meta-data/",
        ]
        for url in metadata_urls:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_safe, f"Expected cloud metadata / link-local {url} to be blocked.")
            self.assertIsNotNone(res.violation_reason)
            self.assertTrue(
                any(kw in res.violation_reason.lower() for kw in ["link-local", "cloud metadata", "blocked", "restricted"]),
                f"Reason for {url}: {res.violation_reason}",
            )

    # -------------------------------------------------------------------------
    # Rule 6: Internal DNS Targets (.local, .internal, .lan, .corp, etc.)
    # -------------------------------------------------------------------------
    def test_04_block_internal_dns_targets(self):
        """Mandate 6: Block internal DNS suffixes (.local, .internal, .lan, .corp, .home, .arpa, .priv, .intra, .intranet)."""
        internal_dns_urls = [
            "http://auth-service.local/login",
            "http://database-cluster.internal/query",
            "http://router.lan/admin",
            "http://active-directory.corp/users",
            "http://storage-nas.home/backups",
            "http://1.0.0.127.in-addr.arpa/ptr",
            "http://secrets-vault.priv/v1/secret",
            "http://admin-portal.intra/dashboard",
            "http://wiki.intranet/confidential",
        ]
        for url in internal_dns_urls:
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_safe, f"Expected internal DNS target {url} to be blocked.")
            self.assertIn("Internal DNS target", res.violation_reason)

    # -------------------------------------------------------------------------
    # Rule 7: Internal Services (Sensitive Daemon Ports)
    # -------------------------------------------------------------------------
    def test_05_block_internal_services_sensitive_ports(self):
        """Mandate 7: Block sensitive internal service daemon ports (5432, 6379, 9200, 8000, 2375, etc.)."""
        # We test with a public IP representation
        public_ip = "93.184.216.34"  # example.com public IP
        sensitive_ports = [
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (9200, "OpenSearch / Elasticsearch"),
            (8000, "Internal dev/API"),
            (2375, "Docker daemon"),
            (2376, "Docker daemon TLS"),
            (2379, "etcd"),
            (8500, "Consul"),
            (8200, "Vault"),
            (10250, "Kubelet"),
        ]
        for port, service_name in sensitive_ports:
            url = f"http://{public_ip}:{port}/api"
            res = self.validator.validate_url(url)
            self.assertFalse(res.is_safe, f"Expected port {port} ({service_name}) to be blocked.")
            self.assertIn("sensitive internal service daemon", res.violation_reason)

    # -------------------------------------------------------------------------
    # Principle: "Do not trust the hostname alone" & DNS Resolution Validation
    # -------------------------------------------------------------------------
    def test_06_do_not_trust_hostname_alone_dns_rebinding(self):
        """
        'Do not trust the hostname alone.'
        Simulate DNS rebinding or internal domain resolving to a private/loopback IP address.
        """
        # 1. Hostname looks innocent ("innocent-domain.com") but resolves to 127.0.0.1
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
            ]
            res = self.validator.validate_url("https://innocent-domain.com/feed")
            self.assertFalse(res.is_safe)
            self.assertIn("127.0.0.1", res.resolved_ips)
            self.assertIn("Loopback address disallowed", res.violation_reason)

        # 2. Hostname resolves to multiple IPs, one is public but another is private 10.0.1.5
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.1.5", 80)),
            ]
            res = self.validator.validate_url("https://dual-homed-target.com/api")
            self.assertFalse(res.is_safe)
            self.assertEqual(len(res.resolved_ips), 2)
            self.assertIn("Private internal network disallowed: 10.0.1.5", res.violation_reason)

        # 3. Hostname resolves to IPv4-mapped IPv6 NAT64 loopback
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("64:ff9b::127.0.0.1", 80, 0, 0))
            ]
            res = self.validator.validate_url("https://nat64-bypass.org/endpoint")
            self.assertFalse(res.is_safe)
            self.assertIn("Loopback address disallowed", res.violation_reason)

    # -------------------------------------------------------------------------
    # Principle: "Re-check redirects"
    # -------------------------------------------------------------------------
    def test_07_recheck_redirects_blocks_metadata_pivot(self):
        """
        'Re-check redirects.'
        Hop 0 is an allowed public site, which returns 302 redirecting to 169.254.169.254.
        The fetcher MUST NOT blindly follow; it must evaluate Hop 1 and block it immediately.
        """
        # Mock initial DNS resolution for safe site
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
            ]

            # Mock httpx response for Hop 0
            mock_resp = MagicMock()
            mock_resp.status_code = 302
            mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}
            mock_resp.content = b""

            with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
                chain = self.fetcher.fetch_with_redirect_validation("https://safe-blog.com/feed")

                # The request to safe-blog.com was executed once
                mock_get.assert_called_once_with("https://safe-blog.com/feed", headers={"User-Agent": self.fetcher.user_agent})

                # Result must be marked unsafe
                self.assertFalse(chain.is_safe)
                self.assertEqual(chain.total_hops, 2)
                self.assertEqual(len(chain.hops), 2)

                # Hop 0: Safe URL -> 302
                hop0 = chain.hops[0]
                self.assertEqual(hop0.hop_index, 0)
                self.assertEqual(hop0.status_code, 302)
                self.assertEqual(hop0.location_target, "http://169.254.169.254/latest/meta-data/")
                self.assertTrue(hop0.is_safe)

                # Hop 1: Cloud metadata -> Blocked before connection
                hop1 = chain.hops[1]
                self.assertEqual(hop1.hop_index, 1)
                self.assertEqual(hop1.status_code, 0)  # Never connected!
                self.assertFalse(hop1.is_safe)
                self.assertIn("cloud metadata", hop1.violation_reason.lower())
                self.assertIn("hop #1", chain.violation_reason)

    def test_08_recheck_redirects_relative_safe_flow(self):
        """
        'Re-check redirects.'
        Hop 0 is safe URL returning 301 to relative path '/articles/cyber-news'.
        Hop 1 is correctly resolved to full URL and fetched successfully.
        """
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
            ]

            resp_hop0 = MagicMock()
            resp_hop0.status_code = 301
            resp_hop0.headers = {"Location": "/articles/cyber-news"}
            resp_hop0.content = b""

            resp_hop1 = MagicMock()
            resp_hop1.status_code = 200
            resp_hop1.headers = {}
            resp_hop1.content = b'{"news": "Cyber OSINT alert"}'

            with patch("httpx.Client.get", side_effect=[resp_hop0, resp_hop1]) as mock_get:
                chain = self.fetcher.fetch_with_redirect_validation("https://safe-news.org/rss")

                self.assertTrue(chain.is_safe)
                self.assertEqual(chain.total_hops, 2)
                self.assertEqual(chain.final_url, "https://safe-news.org/articles/cyber-news")
                self.assertEqual(chain.content, b'{"news": "Cyber OSINT alert"}')
                self.assertEqual(len(chain.hops), 2)
                self.assertEqual(chain.hops[0].location_target, "https://safe-news.org/articles/cyber-news")
                self.assertEqual(chain.hops[1].status_code, 200)

    def test_09_recheck_redirects_max_redirects_loop_protection(self):
        """Redirect loop hitting max_redirects limit terminates safely."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
            ]

            # Cyclic redirect: A -> B -> A -> B...
            resp_a = MagicMock(status_code=302, headers={"Location": "https://site.org/b"})
            resp_b = MagicMock(status_code=302, headers={"Location": "https://site.org/a"})

            with patch("httpx.Client.get", side_effect=[resp_a, resp_b, resp_a, resp_b]):
                chain = self.fetcher.fetch_with_redirect_validation("https://site.org/a", max_redirects=2)

                self.assertFalse(chain.is_safe)
                self.assertIn("Exceeded maximum allowed redirect hops", chain.violation_reason)

    # -------------------------------------------------------------------------
    # FastAPI REST API Endpoints: /api/v1/security/validate-url and validate-redirects
    # -------------------------------------------------------------------------
    def test_10_api_validate_url_endpoint(self):
        """Verify POST /api/v1/security/validate-url blocks SSRF targets and logs audit events."""
        # 1. Validate blocked URL
        response = self.client.post(
            "/api/v1/security/validate-url",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertFalse(data["is_safe"])
        self.assertIn("cloud metadata", data["violation_reason"].lower())

        # 2. Check that audit logger captured the SSRF block
        events = audit_logger.get_recent_events(limit=5, event_type="ssrf_blocked")
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].status, "blocked")
        self.assertIn("169.254.169.254", events[0].resource)

    def test_11_api_validate_redirects_endpoint(self):
        """Verify POST /api/v1/security/validate-redirects endpoint with simulated chain."""
        with patch("socket.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
            ]

            mock_resp = MagicMock()
            mock_resp.status_code = 302
            mock_resp.headers = {"Location": "http://127.0.0.1:5432/status"}
            mock_resp.content = b""

            with patch("httpx.Client.get", return_value=mock_resp):
                response = self.client.post(
                    "/api/v1/security/validate-redirects",
                    json={"url": "https://threat-intel-feed.com/redirect", "max_redirects": 3},
                )
                self.assertEqual(response.status_code, 200)
                data = response.json()

                self.assertFalse(data["is_safe"])
                self.assertEqual(data["total_hops"], 2)
                self.assertIn("SSRF violation at hop #1", data["violation_reason"])
                self.assertEqual(len(data["hops"]), 2)
                self.assertFalse(data["hops"][1]["is_safe"])

                # Check audit log for ssrf_redirect_blocked
                redirect_events = audit_logger.get_recent_events(limit=5, event_type="ssrf_redirect_blocked")
                self.assertTrue(len(redirect_events) >= 1)
                self.assertEqual(redirect_events[0].status, "blocked")


if __name__ == "__main__":
    unittest.main()
