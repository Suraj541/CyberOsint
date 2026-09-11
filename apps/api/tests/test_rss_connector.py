"""
RSS Connector & SSRF Preflight Test Suite
Verifies RSS 2.0 / Atom feed discovery, normalization, date parsing,
and strict Server-Side Request Forgery (SSRF) boundary protections.
"""

import sys
import unittest
from pathlib import Path

# Ensure apps/api and cyber-osint root are in sys.path
api_root = Path(__file__).resolve().parent.parent
repo_root = api_root.parent.parent
for path in (str(api_root), str(repo_root)):
    if path not in sys.path:
        sys.path.insert(0, path)

from connectors.base import BaseConnector, NormalizedItem
from connectors.registry import connector_registry
from connectors.rss.connector import RSSConnector
from connectors.security import SSRFSecurityError, is_ip_allowed, validate_url_for_ssrf

SAMPLE_RSS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Cybersecurity News Wire</title>
    <link>https://cyber-news.local</link>
    <description>Latest breaking security advisories and vulnerability reports.</description>
    <language>en-us</language>
    <item>
      <title>Critical Zero-Day Flaw in OpenSSH (CVE-2024-6387) Analyzed</title>
      <link>https://cyber-news.local/articles/cve-2024-6387-regresshion</link>
      <description><![CDATA[Security researchers publish deep-dive analysis of signal handler race condition in OpenSSH server.]]></description>
      <author>researcher@cyber-news.local</author>
      <pubDate>Mon, 01 Jul 2024 10:00:00 +0000</pubDate>
      <guid>https://cyber-news.local/articles/cve-2024-6387-regresshion</guid>
      <category>Vulnerabilities</category>
    </item>
    <item>
      <title>Ransomware Gang Disrupts Healthcare Network</title>
      <link>https://cyber-news.local/articles/ransomware-healthcare-outage</link>
      <description>Hospital services redirect ambulances following ransomware attack.</description>
      <author>Threat Desk</author>
      <pubDate>Tue, 02 Jul 2024 14:15:00 +0000</pubDate>
      <guid>https://cyber-news.local/articles/ransomware-healthcare-outage</guid>
      <category>Ransomware</category>
    </item>
  </channel>
</rss>
"""

SAMPLE_ATOM_XML = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>CISA Vulnerability Summary Feed</title>
  <link href="https://cisa.gov/feeds/vulnerabilities"/>
  <updated>2026-09-11T18:00:00Z</updated>
  <id>urn:uuid:60a76c80-d399-11d9-b93C-0003939e0af6</id>
  <entry>
    <title>CISA Adds Known Exploited Vulnerability to Catalog</title>
    <link href="https://cisa.gov/known-exploited-vulnerabilities/additions/cve-2026-1111"/>
    <id>urn:uuid:1225c695-cfb8-4ebb-aaaa-80da344efa6a</id>
    <updated>2026-09-11T18:30:00Z</updated>
    <summary>CISA has added one new vulnerability to its Known Exploited Vulnerabilities Catalog.</summary>
    <author>
      <name>CISA Cybersecurity Division</name>
    </author>
  </entry>
</feed>
"""


class TestRSSConnectorAndSSRF(unittest.TestCase):
    """Test suite validating Step 7 / Stage 5 RSS Connector and SSRF safeguards."""

    def test_ssrf_blocks_loopback_and_metadata(self):
        """Confirm SSRF validator rejects localhost, RFC 1918, link-local, and cloud metadata."""
        blocked_urls = [
            "http://127.0.0.1/feed.xml",
            "http://127.0.0.1:8000/internal",
            "http://localhost:5432/",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/internal-feed",
            "http://172.16.0.5/admin.rss",
            "http://192.168.1.1/feed.xml",
            "http://0.0.0.0:8080/test",
            "ftp://example.com/feed.xml",  # Unsupported scheme
            "gopher://example.com/feed",   # Dangerous scheme
        ]

        for url in blocked_urls:
            with self.assertRaises(SSRFSecurityError, msg=f"Should have blocked SSRF URL: {url}"):
                validate_url_for_ssrf(url)

    def test_ssrf_ip_filtering_rules(self):
        """Confirm IP validation helper correctly evaluates public vs prohibited IPs."""
        self.assertFalse(is_ip_allowed("127.0.0.1"))
        self.assertFalse(is_ip_allowed("10.10.10.10"))
        self.assertFalse(is_ip_allowed("192.168.0.1"))
        self.assertFalse(is_ip_allowed("169.254.169.254"))
        self.assertFalse(is_ip_allowed("::1"))
        self.assertFalse(is_ip_allowed("0.0.0.0"))

        # Public routable IPs (Quad9, Cloudflare) must be allowed
        self.assertTrue(is_ip_allowed("9.9.9.9"))
        self.assertTrue(is_ip_allowed("1.1.1.1"))

    def test_rss_connector_auto_registered(self):
        """Confirm RSSConnector is registered in connector_registry under 'rss' and 'feed'."""
        self.assertTrue(connector_registry.has("rss"))
        self.assertTrue(connector_registry.has("feed"))
        self.assertTrue(connector_registry.has("atom"))

        connector = connector_registry.create("rss", {"name": "Test Feed"})
        self.assertIsInstance(connector, RSSConnector)
        self.assertIsInstance(connector, BaseConnector)

    def test_rss2_feed_parsing_and_normalization(self):
        """Confirm RSSConnector correctly parses RSS 2.0 XML into NormalizedItem."""
        connector = RSSConnector({
            "name": "Cyber News Wire",
            "url": "https://cyber-news.local/feed.xml",
            "feed_content": SAMPLE_RSS_XML,
            "content_type": "article",
        })

        # Discover
        entries = connector.discover()
        self.assertEqual(len(entries), 2)

        # Pipeline execution
        items = connector.run_pipeline()
        self.assertEqual(len(items), 2)

        # Validate first normalized item
        item1 = items[0]
        self.assertIsInstance(item1, NormalizedItem)
        self.assertEqual(item1.title, "Critical Zero-Day Flaw in OpenSSH (CVE-2024-6387) Analyzed")
        self.assertEqual(item1.url, "https://cyber-news.local/articles/cve-2024-6387-regresshion")
        self.assertIn("race condition in OpenSSH", item1.description)
        self.assertEqual(item1.source, "Cyber News Wire")
        self.assertEqual(item1.content_type, "article")
        self.assertIsNotNone(item1.published_at)
        self.assertIn("2024-07-01", item1.published_at)
        self.assertIn("Vulnerabilities", item1.metadata["tags"])

        # Validate second normalized item
        item2 = items[1]
        self.assertEqual(item2.title, "Ransomware Gang Disrupts Healthcare Network")
        self.assertIn("healthcare-outage", item2.url)
        self.assertIn("Ransomware", item2.metadata["tags"])

    def test_atom_feed_parsing_and_normalization(self):
        """Confirm RSSConnector correctly parses Atom 1.0 XML into NormalizedItem."""
        connector = RSSConnector({
            "name": "CISA KEV Feed",
            "url": "https://cisa.gov/feeds/vulnerabilities",
            "feed_content": SAMPLE_ATOM_XML,
            "content_type": "advisory",
        })

        items = connector.run_pipeline()
        self.assertEqual(len(items), 1)

        item = items[0]
        self.assertEqual(item.title, "CISA Adds Known Exploited Vulnerability to Catalog")
        self.assertIn("cve-2026-1111", item.url)
        self.assertEqual(item.source, "CISA KEV Feed")
        self.assertEqual(item.content_type, "advisory")
        self.assertEqual(item.author, "CISA Cybersecurity Division")
        self.assertIn("2026-09-11", item.published_at)

    def test_rss_health_check_in_memory(self):
        """Confirm RSSConnector health_check evaluates feed structure."""
        connector = RSSConnector({
            "name": "Health Test Feed",
            "feed_content": SAMPLE_RSS_XML,
        })
        health = connector.health_check()
        self.assertEqual(health.status, "ok")
        self.assertEqual(health.details.get("entries_count"), 2)

    def test_rss_health_check_blocks_ssrf(self):
        """Confirm RSSConnector health_check refuses and flags prohibited SSRF addresses."""
        connector = RSSConnector({
            "name": "Malicious Private Feed",
            "url": "http://127.0.0.1:8080/feed.xml",
        })
        health = connector.health_check()
        self.assertEqual(health.status, "failing")
        self.assertIn("SSRF", health.error_message)


if __name__ == "__main__":
    unittest.main()
