"""
Unit Tests for Section 32 (Step 31: Build Watchlists)
Verifies:
1. All 10 mandated watchlist target types: CVE, Product, Vendor, Threat Actor, Malware, Technology, Topic, Researcher, Tool, Keyword.
2. Database models: Watchlist and WatchlistItem with cascade delete and serialization.
3. Multi-criteria matching engine with severity threshold enforcement.
4. Watchlist service CRUD operations and feed generation.
5. FastAPI REST API endpoints (/watchlists, /items, /feed, /match-test).
"""

import sys
import unittest
import uuid
from pathlib import Path

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app
from services.watchlist import (
    WatchlistItemCreateDTO,
    WatchlistItemDTO,
    WatchlistItemType,
    watchlist_matcher,
    watchlist_service,
)


class TestWatchlistsSection32(unittest.TestCase):
    """Test suite for Section 32 (Step 31: Build Watchlists)."""

    def setUp(self):
        self.client = TestClient(app)
        self.session_id = "test_session_sec32"

    def test_01_all_ten_mandated_item_types(self):
        """Verify that all 10 mandated item types exist in the enum."""
        expected_types = {
            "cve",
            "product",
            "vendor",
            "threat_actor",
            "malware",
            "technology",
            "topic",
            "researcher",
            "tool",
            "keyword",
        }
        actual_types = {t.value for t in WatchlistItemType}
        self.assertEqual(actual_types, expected_types)

    def test_02_watchlist_matcher_cve_and_severity(self):
        """Verify CVE matching and severity threshold filtering."""
        cve_item = WatchlistItemDTO(
            id=1,
            watchlist_id=1,
            item_type="cve",
            item_value="CVE-2024-3400",
            severity_threshold="CRITICAL",
        )

        critical_cve_content = {
            "title": "Critical RCE Flaw in PAN-OS (CVE-2024-3400)",
            "description": "Zero-day vulnerability actively exploited",
            "summary": "Immediate patching recommended",
            "severity": "CRITICAL",
            "entities": [{"entity_type": "cve", "name": "CVE-2024-3400"}],
        }

        low_cve_content = {
            "title": "Minor advisory referencing CVE-2024-3400",
            "description": "Information disclosure in test environment",
            "summary": "Low risk",
            "severity": "LOW",
            "entities": [{"entity_type": "cve", "name": "CVE-2024-3400"}],
        }

        # Critical content should match
        match_crit = watchlist_matcher.match_item(cve_item, critical_cve_content, "Critical Watchlist")
        self.assertIsNotNone(match_crit)
        self.assertEqual(match_crit.item_value, "CVE-2024-3400")

        # Low content should be rejected by severity threshold
        match_low = watchlist_matcher.match_item(cve_item, low_cve_content, "Critical Watchlist")
        self.assertIsNone(match_low)

    def test_03_watchlist_matcher_remaining_nine_types(self):
        """Verify matching across Product, Vendor, Threat Actor, Malware, Technology, Topic, Researcher, Tool, Keyword."""
        test_content = {
            "title": "Jann Horn Discloses Runc Container Breakout Exploited by LockBit in Kubernetes",
            "description": "Palo Alto Networks issues advisory on Falco rules detecting LockBit 3.0 exfiltration",
            "summary": "Zero-day vulnerability exploitation using automated privilege escalation scripts",
            "source": "Palo Alto Networks Threat Intel",
            "author": "Jann Horn",
            "category": "Zero-Day Vulnerabilities",
            "severity": "HIGH",
            "tags": ["kubernetes", "container security", "privilege escalation"],
            "entities": [
                {"entity_type": "vendor", "name": "Palo Alto Networks"},
                {"entity_type": "product", "name": "PAN-OS"},
                {"entity_type": "threat_actor", "name": "LockBit"},
                {"entity_type": "malware", "name": "LockBit 3.0"},
                {"entity_type": "technology", "name": "Kubernetes"},
                {"entity_type": "tool", "name": "Falco"},
                {"entity_type": "researcher", "name": "Jann Horn"},
            ],
        }

        items_to_test = [
            ("product", "PAN-OS"),
            ("vendor", "Palo Alto Networks"),
            ("threat_actor", "LockBit"),
            ("malware", "LockBit 3.0"),
            ("technology", "Kubernetes"),
            ("topic", "Zero-Day Vulnerabilities"),
            ("researcher", "Jann Horn"),
            ("tool", "Falco"),
            ("keyword", "privilege escalation"),
        ]

        for i, (itype, ival) in enumerate(items_to_test, start=10):
            item_dto = WatchlistItemDTO(
                id=i,
                watchlist_id=1,
                item_type=itype,
                item_value=ival,
            )
            hit = watchlist_matcher.match_item(item_dto, test_content, "Test Watchlist")
            self.assertIsNotNone(hit, f"Expected match for item type: {itype} with value: {ival}")
            self.assertEqual(hit.item_type, itype)

    def test_04_watchlist_service_crud_lifecycle(self):
        """Test creating, reading, updating, item management, and deleting watchlists."""
        session = "session_crud_test"

        # 1. Create
        created = watchlist_service.create_watchlist(
            session_id=session,
            name="Cloud Perimeter Sentinel",
            description="Perimeter gateways and VPN targets",
            notification_channel="webhook",
            items=[
                WatchlistItemCreateDTO(item_type=WatchlistItemType.VENDOR, item_value="Cisco"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.PRODUCT, item_value="AnyConnect"),
            ],
        )
        self.assertEqual(created.name, "Cloud Perimeter Sentinel")
        self.assertEqual(created.item_count, 2)
        wl_id = created.id

        # 2. Add Item
        added_item = watchlist_service.add_item(
            watchlist_id=wl_id,
            item_type="keyword",
            item_value="unauthenticated rce",
            severity_threshold="CRITICAL",
        )
        self.assertIsNotNone(added_item)
        self.assertEqual(added_item.item_value, "unauthenticated rce")

        # 3. Read
        fetched = watchlist_service.get_watchlist(wl_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.item_count, 3)

        # 4. Update
        updated = watchlist_service.update_watchlist(
            watchlist_id=wl_id,
            name="Cloud Perimeter Sentinel (Updated)",
            is_active=False,
        )
        self.assertEqual(updated.name, "Cloud Perimeter Sentinel (Updated)")
        self.assertFalse(updated.is_active)

        # 5. Remove item
        removed = watchlist_service.remove_item(added_item.id)
        self.assertTrue(removed)
        after_remove = watchlist_service.get_watchlist(wl_id)
        self.assertEqual(after_remove.item_count, 2)

        # 6. Delete Watchlist
        deleted = watchlist_service.delete_watchlist(wl_id)
        self.assertTrue(deleted)
        self.assertIsNone(watchlist_service.get_watchlist(wl_id))

    def test_05_watchlist_feed_generation(self):
        """Test feed generation for a watchlist containing multiple watched targets."""
        session = "session_feed_test"
        wl = watchlist_service.create_watchlist(
            session_id=session,
            name="Edge Gateway Surveillance",
            items=[
                WatchlistItemCreateDTO(item_type=WatchlistItemType.CVE, item_value="CVE-2024-3400"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.PRODUCT, item_value="PAN-OS"),
            ],
        )

        feed = watchlist_service.get_watchlist_feed(wl.id, limit=10)
        self.assertGreater(feed.total_matches, 0)
        top_match = feed.items[0]
        self.assertTrue(any(hit.item_value == "CVE-2024-3400" for hit in top_match.matched_items))

    def test_06_fastapi_rest_endpoints(self):
        """Verify all FastAPI REST endpoints for Section 32."""
        session = f"api_test_session_wl_{uuid.uuid4().hex[:8]}"

        # 1. GET /api/v1/watchlists (lists auto-seeded default watchlists)
        res_list = self.client.get(f"/api/v1/watchlists?session_id={session}")
        self.assertEqual(res_list.status_code, 200)
        data = res_list.json()
        self.assertGreaterEqual(len(data), 3)
        self.assertTrue(any("Zero-Day" in w["name"] for w in data))

        # 2. POST /api/v1/watchlists
        res_create = self.client.post(
            "/api/v1/watchlists",
            json={
                "session_id": session,
                "name": "API Testing Watchlist",
                "description": "Test watchlist created via REST",
                "notification_channel": "email",
                "items": [
                    {"item_type": "tool", "item_value": "Nuclei", "severity_threshold": "HIGH"},
                    {"item_type": "keyword", "item_value": "zero-click"},
                ],
            },
        )
        self.assertEqual(res_create.status_code, 201)
        created_wl = res_create.json()
        wl_id = created_wl["id"]
        self.assertEqual(created_wl["item_count"], 2)

        # 3. GET /api/v1/watchlists/{id}
        res_get = self.client.get(f"/api/v1/watchlists/{wl_id}")
        self.assertEqual(res_get.status_code, 200)
        self.assertEqual(res_get.json()["name"], "API Testing Watchlist")

        # 4. PUT /api/v1/watchlists/{id}
        res_put = self.client.put(
            f"/api/v1/watchlists/{wl_id}",
            json={"name": "API Testing Watchlist (Renamed)", "is_active": True},
        )
        self.assertEqual(res_put.status_code, 200)
        self.assertEqual(res_put.json()["name"], "API Testing Watchlist (Renamed)")

        # 5. POST /api/v1/watchlists/{id}/items
        res_add_item = self.client.post(
            f"/api/v1/watchlists/{wl_id}/items",
            json={"item_type": "researcher", "item_value": "Tavis Ormandy"},
        )
        self.assertEqual(res_add_item.status_code, 201)
        item_id = res_add_item.json()["id"]

        # 6. GET /api/v1/watchlists/{id}/feed
        res_feed = self.client.get(f"/api/v1/watchlists/{wl_id}/feed")
        self.assertEqual(res_feed.status_code, 200)
        self.assertIn("items", res_feed.json())

        # 7. POST /api/v1/watchlists/match-test
        res_test = self.client.post(
            f"/api/v1/watchlists/match-test?watchlist_id={wl_id}",
            json={
                "title": "Critical zero-click vulnerability analyzed by Nuclei scanner",
                "description": "Exploit payloads detected",
            },
        )
        self.assertEqual(res_test.status_code, 200)
        hits = res_test.json()
        self.assertGreater(len(hits), 0)

        # 8. DELETE /api/v1/watchlists/{id}/items/{item_id}
        res_del_item = self.client.delete(f"/api/v1/watchlists/{wl_id}/items/{item_id}")
        self.assertEqual(res_del_item.status_code, 200)

        # 9. DELETE /api/v1/watchlists/{id}
        res_del_wl = self.client.delete(f"/api/v1/watchlists/{wl_id}")
        self.assertEqual(res_del_wl.status_code, 200)


if __name__ == "__main__":
    unittest.main()
