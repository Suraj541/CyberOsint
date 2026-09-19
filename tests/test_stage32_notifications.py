"""
Unit Tests for Section 33 (Step 32: Build Notifications)
Verifies:
1. Multi-factor importance scoring engine and level classification.
2. Importance threshold enforcement: suppressing non-critical articles to prevent alert fatigue.
3. Multi-channel dispatchers: Web, Email, Push, and Webhook (with HMAC-SHA256 signature).
4. End-to-end 5-stage pipeline: New Content -> Match Watchlists -> Calculate Importance -> Create Notification -> Send.
5. Database models: Notification and NotificationChannelConfig with metadata serialization.
6. FastAPI REST API endpoints (/notifications, /summary, /channels, /pipeline/run, /read, /mark-all-read).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from app.database import SessionLocal, engine, Base
import app.models
from app.models.content import Content
from app.models.notification import Notification, NotificationChannelConfig
from app.models.watchlist import Watchlist, WatchlistItem
from services.notification import (
    DEFAULT_CHANNEL_THRESHOLDS,
    EmailDispatcher,
    ImportanceCalculator,
    ImportanceLevel,
    NotificationChannel,
    NotificationDTO,
    NotificationPipeline,
    NotificationStatus,
    PushDispatcher,
    WebDispatcher,
    WebhookDispatcher,
    dispatcher_registry,
    importance_calculator,
    notification_pipeline,
    notification_service,
)
from services.watchlist.models import WatchlistItemDTO, WatchlistItemType


class TestNotificationsSection33(unittest.TestCase):
    """Test suite for Section 33 (Step 32: Build Notifications)."""

    def setUp(self):
        Base.metadata.create_all(bind=engine)
        self.client = TestClient(fastapi_app)
        self.session_id = "test_session_sec33_notif"
        self.db = SessionLocal()

    def tearDown(self):
        # Cleanup test entities
        try:
            self.db.query(Notification).filter(Notification.session_id == self.session_id).delete()
            self.db.query(NotificationChannelConfig).filter(NotificationChannelConfig.session_id == self.session_id).delete()
            wl_records = self.db.query(Watchlist).filter(Watchlist.session_id == self.session_id).all()
            wl_ids = [w.id for w in wl_records]
            if wl_ids:
                self.db.query(WatchlistItem).filter(WatchlistItem.watchlist_id.in_(wl_ids)).delete(synchronize_session=False)
            self.db.query(Watchlist).filter(Watchlist.session_id == self.session_id).delete()
            self.db.commit()
        except Exception:
            self.db.rollback()
        finally:
            self.db.close()

    def test_01_importance_calculator_critical_and_low(self):
        """Verify importance score calculation across critical weaponized vs low generic content."""
        # 1. Critical Weaponized Item
        critical_content = {
            "title": "Unauthenticated Remote Code Execution in GlobalProtect (CVE-2024-3400)",
            "description": "Zero-day vulnerability actively exploited in the wild with public PoC.",
            "summary": "Threat actors deploying webshells. CISA added to KEV catalog.",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "source": "CISA",
            "tags": ["zero-day", "kev", "cisa", "actively exploited"],
            "entities": [{"entity_type": "cve", "name": "CVE-2024-3400"}],
        }
        matched_items = [
            {"item_type": "cve", "item_value": "CVE-2024-3400"},
            {"item_type": "threat_actor", "item_value": "APT29"},
        ]

        crit_res = importance_calculator.calculate(
            content_dict=critical_content,
            matched_items=matched_items,
            source_quality_score=0.95,
            threshold_override=0.45,
        )

        self.assertGreaterEqual(crit_res.score, 0.85)
        self.assertEqual(crit_res.level, ImportanceLevel.CRITICAL)
        self.assertTrue(crit_res.exceeds_threshold)
        self.assertIn("severity_factor", crit_res.factors)
        self.assertEqual(crit_res.factors["severity_factor"], 1.0)
        self.assertGreaterEqual(crit_res.factors["exploit_factor"], 0.8)

        # 2. Low Generic Item
        low_content = {
            "title": "Minor formatting update to documentation readme",
            "description": "Fixed spelling mistakes in contributing guidelines.",
            "summary": "No security impact.",
            "severity": "LOW",
            "cvss_score": 1.0,
            "source": "Blog",
            "tags": ["docs"],
            "entities": [],
        }
        low_res = importance_calculator.calculate(
            content_dict=low_content,
            matched_items=[],
            source_quality_score=0.4,
            threshold_override=0.45,
        )
        self.assertLess(low_res.score, 0.45)
        self.assertFalse(low_res.exceeds_threshold)

    def test_02_importance_threshold_gate(self):
        """Verify that items scoring below importance threshold are suppressed."""
        # Content that scores ~0.35 (below 0.50 threshold)
        med_low_content = {
            "title": "Minor vendor notice regarding interface updates",
            "description": "Informational update about deprecated configuration keys.",
            "summary": "No active vulnerabilities reported.",
            "severity": "LOW",
            "cvss_score": 2.0,
            "source": "Vendor Forums",
            "tags": ["config"],
            "entities": [],
        }

        calc = ImportanceCalculator(default_threshold=0.60)
        res = calc.calculate(med_low_content, matched_items=[])
        self.assertFalse(res.exceeds_threshold)

        # Verify channel gate filtering
        self.assertTrue(calc.should_send(NotificationChannel.WEB, score=0.40, channel_threshold_override=0.35))
        self.assertFalse(calc.should_send(NotificationChannel.EMAIL, score=0.65, channel_threshold_override=0.70))
        self.assertTrue(calc.should_send(NotificationChannel.EMAIL, score=0.85, channel_threshold_override=0.70))

    def test_03_multi_channel_dispatchers(self):
        """Verify Web, Email, Push, and Webhook dispatchers."""
        test_dto = NotificationDTO(
            id=1234,
            session_id=self.session_id,
            watchlist_id=1,
            watchlist_name="Edge Firewalls",
            title="Critical FortiOS Vulnerability (CVE-2024-21762)",
            body="Out-of-bound write in FortiOS allows unauthenticated RCE via crafted HTTP requests.",
            summary="CISA urges immediate patch application.",
            importance_score=0.92,
            importance_level="CRITICAL",
            channel="web",
            status="pending",
            content_url="https://cisa.gov/advisories/aa24-038a",
            metadata={"matched_items": [{"item_type": "cve", "item_value": "CVE-2024-21762"}]},
        )

        # 1. Web Dispatcher
        web_res = WebDispatcher().dispatch(test_dto)
        self.assertEqual(web_res["status"], NotificationStatus.DELIVERED.value)
        self.assertEqual(web_res["channel"], "web")

        # 2. Email Dispatcher
        email_res = EmailDispatcher().dispatch(test_dto, destination="soc-lead@cyber-osint.local")
        self.assertEqual(email_res["status"], NotificationStatus.DELIVERED.value)
        self.assertEqual(email_res["destination"], "soc-lead@cyber-osint.local")
        self.assertIn("CRITICAL", email_res["subject"])

        # 3. Push Dispatcher
        push_res = PushDispatcher().dispatch(test_dto, destination="browser_client_endpoint")
        self.assertEqual(push_res["status"], NotificationStatus.DELIVERED.value)
        self.assertEqual(push_res["priority"], "high")

        # 4. Webhook Dispatcher with HMAC Signature
        webhook_res = WebhookDispatcher().dispatch(
            test_dto,
            destination="https://mock-siem.local/alerts",
            secret_token="test_secret_hmac_12345",
        )
        self.assertEqual(webhook_res["status"], NotificationStatus.DELIVERED.value)
        self.assertIn("signature", webhook_res)
        self.assertTrue(webhook_res["signature"].startswith("sha256="))
        self.assertEqual(webhook_res["payload_preview"]["importance_level"], "CRITICAL")

    def test_04_five_stage_notification_pipeline(self):
        """
        Verify complete 5-stage pipeline:
        New Content -> Match Watchlists -> Calculate Importance -> Create Notification -> Send
        """
        # Setup active test watchlist with CVE and vendor targets
        wl = Watchlist(
            session_id=self.session_id,
            name="Critical Zero-Days Watchlist",
            description="High urgency monitored perimeter",
            is_active=True,
            notification_channel="web",
        )
        self.db.add(wl)
        self.db.flush()

        item1 = WatchlistItem(
            watchlist_id=wl.id,
            item_type="cve",
            item_value="CVE-2024-3400",
            notify_on_match=True,
        )
        item2 = WatchlistItem(
            watchlist_id=wl.id,
            item_type="vendor",
            item_value="Palo Alto Networks",
            notify_on_match=True,
        )
        self.db.add_all([item1, item2])
        self.db.commit()

        # Input content
        content_payload = {
            "title": "Exploitation of Palo Alto Networks PAN-OS GlobalProtect (CVE-2024-3400)",
            "description": "Adversaries actively chaining command injection on edge appliances.",
            "summary": "Full compromise of internal gateways reported.",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "source": "CISA",
            "canonical_url": "https://cisa.gov/advisory/panos",
            "category": "Vulnerabilities",
            "tags": ["zero-day", "kev", "cisa"],
            "entities": [
                {"entity_type": "cve", "name": "CVE-2024-3400"},
                {"entity_type": "vendor", "name": "Palo Alto Networks"},
            ],
        }

        # Run pipeline
        res = notification_pipeline.process_content(
            db=self.db,
            content_or_dict=content_payload,
            session_id=self.session_id,
            force_dispatch=True,
        )

        self.assertEqual(res.status, "completed")
        self.assertGreaterEqual(res.matched_items_count, 2)
        self.assertGreaterEqual(res.importance.score, 0.85)
        self.assertEqual(res.importance.level, ImportanceLevel.CRITICAL)
        self.assertGreater(len(res.notifications_created), 0)
        self.assertGreater(len(res.dispatch_results), 0)

        # Verify persisted in database
        saved_notif = (
            self.db.query(Notification)
            .filter(Notification.session_id == self.session_id)
            .first()
        )
        self.assertIsNotNone(saved_notif)
        self.assertEqual(saved_notif.importance_level, "CRITICAL")
        self.assertFalse(saved_notif.is_read)

    def test_05_notification_service_crud_and_summary(self):
        """Verify notification service listing, marking read, summary, and channel configs."""
        # Create test notifications
        n1 = Notification(
            session_id=self.session_id,
            title="Alert 1",
            body="Body 1",
            importance_score=0.90,
            importance_level="CRITICAL",
            channel="web",
            status="delivered",
            is_read=False,
        )
        n2 = Notification(
            session_id=self.session_id,
            title="Alert 2",
            body="Body 2",
            importance_score=0.75,
            importance_level="HIGH",
            channel="webhook",
            status="delivered",
            is_read=False,
        )
        self.db.add_all([n1, n2])
        self.db.commit()

        # List
        notifs = notification_service.list_notifications(self.db, session_id=self.session_id)
        self.assertEqual(len(notifs), 2)

        # Mark read
        updated = notification_service.mark_as_read(self.db, notification_id=n1.id, is_read=True)
        self.assertIsNotNone(updated)
        self.assertTrue(updated.is_read)

        # Summary
        summary = notification_service.get_summary(self.db, session_id=self.session_id)
        self.assertEqual(summary["total_count"], 2)
        self.assertEqual(summary["unread_count"], 1)
        self.assertEqual(summary["critical_count"], 1)

        # Mark all read
        marked = notification_service.mark_all_as_read(self.db, session_id=self.session_id)
        self.assertEqual(marked, 1)

        summary2 = notification_service.get_summary(self.db, session_id=self.session_id)
        self.assertEqual(summary2["unread_count"], 0)

        # Delete
        self.assertTrue(notification_service.delete_notification(self.db, n1.id))
        self.assertIsNone(notification_service.get_notification(self.db, n1.id))

    def test_06_fastapi_rest_endpoints(self):
        """Verify FastAPI REST API endpoints for /api/v1/notifications."""
        # 1. Create notification directly in DB
        test_n = Notification(
            session_id=self.session_id,
            title="REST API Test Alert",
            body="Testing endpoints.",
            importance_score=0.88,
            importance_level="HIGH",
            channel="web",
            status="delivered",
            is_read=False,
        )
        self.db.add(test_n)
        self.db.commit()

        # 2. GET /notifications
        resp = self.client.get(f"/api/v1/notifications?session_id={self.session_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreaterEqual(len(data), 1)
        self.assertEqual(data[0]["title"], "REST API Test Alert")

        # 3. GET /notifications/summary
        resp_sum = self.client.get(f"/api/v1/notifications/summary?session_id={self.session_id}")
        self.assertEqual(resp_sum.status_code, 200)
        sum_data = resp_sum.json()
        self.assertGreaterEqual(sum_data["total_count"], 1)

        # 4. PATCH /notifications/{id}/read
        resp_patch = self.client.patch(f"/api/v1/notifications/{test_n.id}/read?is_read=true")
        self.assertEqual(resp_patch.status_code, 200)
        self.assertTrue(resp_patch.json()["is_read"])

        # 5. POST /notifications/channels
        resp_ch = self.client.post(
            "/api/v1/notifications/channels",
            json={
                "session_id": self.session_id,
                "channel_type": "webhook",
                "destination": "https://siem-test.corp/endpoint",
                "min_importance_threshold": 0.65,
                "secret_token": "secret_abc123",
                "description": "Integration Test Webhook",
            },
        )
        self.assertEqual(resp_ch.status_code, 200)
        self.assertEqual(resp_ch.json()["channel_type"], "webhook")

        # 6. GET /notifications/channels
        resp_ch_list = self.client.get(f"/api/v1/notifications/channels?session_id={self.session_id}")
        self.assertEqual(resp_ch_list.status_code, 200)
        self.assertGreaterEqual(len(resp_ch_list.json()), 1)

        # 7. POST /notifications/channels/test
        resp_probe = self.client.post(
            "/api/v1/notifications/channels/test",
            json={"channel": "web", "destination": "in_app"},
        )
        self.assertEqual(resp_probe.status_code, 200)
        self.assertEqual(resp_probe.json()["status"], "delivered")

        # 8. POST /notifications/pipeline/run
        resp_sim = self.client.post(
            "/api/v1/notifications/pipeline/run",
            json={
                "session_id": self.session_id,
                "content_payload": {
                    "title": "Probe Content",
                    "description": "Test description",
                    "severity": "HIGH",
                    "cvss_score": 8.5,
                    "tags": ["test"],
                },
                "force_dispatch": True,
            },
        )
        self.assertEqual(resp_sim.status_code, 200)
        self.assertIn("importance", resp_sim.json())

        # 9. POST /notifications/mark-all-read
        resp_mar = self.client.post(f"/api/v1/notifications/mark-all-read?session_id={self.session_id}")
        self.assertEqual(resp_mar.status_code, 200)

        # 10. DELETE /notifications/{id}
        resp_del = self.client.delete(f"/api/v1/notifications/{test_n.id}")
        self.assertEqual(resp_del.status_code, 200)


if __name__ == "__main__":
    unittest.main()
