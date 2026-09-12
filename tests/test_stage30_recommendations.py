"""
Unit Tests for Section 31 (Step 30: Build Recommendations)
Verifies:
1. Topic Correlation Graph and canonical expansion (Kubernetes Security -> Container, Docker, Cloud, K8s Detection, Runtime).
2. Technical Difficulty Classification and alignment scoring.
3. Multi-Factor Scoring (Interests, Saved, Searches, Viewed penalty, Entities, Quality, Recency).
4. Recommendation Service (Profiles, Interactions, Content-Type filters, Saved items).
5. FastAPI Endpoints (/recommendations, /interactions, /profile, /topics, /saved).
"""

import sys
import unittest
from pathlib import Path

# Add project root and apps/api to path
ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app
from services.recommendation import (
    DifficultyClassifier,
    TopicGraph,
    difficulty_classifier,
    recommendation_scorer,
    recommendation_service,
    topic_graph,
)


class TestRecommendationsSection31(unittest.TestCase):
    """Test suite for Section 31 (Step 30: Build Recommendations)."""

    def setUp(self):
        self.client = TestClient(app)
        self.session_id = "test_session_sec31"

    def test_01_canonical_topic_correlation_kubernetes(self):
        """
        Verify the canonical example from IMPLEMENT.md Section 31:
        User reads: Kubernetes Security
        Recommend: Container Security, Docker Security, Cloud Security, Kubernetes Threat Detection, Runtime Security
        """
        results = topic_graph.get_related_topics("Kubernetes Security", limit=5)
        topics = [r.topic for r in results]
        expected = [
            "Container Security",
            "Docker Security",
            "Cloud Security",
            "Kubernetes Threat Detection",
            "Runtime Security",
        ]
        self.assertEqual(topics, expected)
        for r in results:
            self.assertGreater(r.score, 0.0)
            self.assertIn("Correlated with Kubernetes Security", r.reason)

    def test_02_topic_graph_aliases_and_fuzzy_normalization(self):
        """Verify alias and fuzzy matching for topic graph."""
        res_k8s = topic_graph.get_related_topics("k8s", limit=3)
        self.assertGreater(len(res_k8s), 0)
        self.assertEqual(res_k8s[0].topic, "Container Security")

        res_ransom = topic_graph.get_related_topics("ransomware", limit=3)
        topics_ransom = [r.topic for r in res_ransom]
        self.assertIn("Malware Analysis", topics_ransom)

    def test_03_difficulty_classifier_and_alignment(self):
        """Verify content technical depth classification and skill alignment."""
        beginner_level = difficulty_classifier.classify(
            title="Introduction to Cloud Security Fundamentals",
            content_type="article",
            text_sample="A gentle beginner overview of basic cloud principles",
        )
        self.assertEqual(beginner_level, "beginner")

        expert_level = difficulty_classifier.classify(
            title="Kernel Space Hypervisor Escape via ROP Chain",
            content_type="research",
            text_sample="Analysis of memory corruption primitive and ASLR bypass",
        )
        self.assertEqual(expert_level, "expert")

        # Alignment scores
        score_exact = difficulty_classifier.score_alignment("expert", "expert")
        score_close = difficulty_classifier.score_alignment("expert", "advanced")
        score_far = difficulty_classifier.score_alignment("expert", "beginner")

        self.assertEqual(score_exact, 1.0)
        self.assertEqual(score_close, 0.70)
        self.assertEqual(score_far, 0.10)

    def test_04_multi_factor_scoring_interests_and_views(self):
        """Verify multi-factor scoring boosts interest matches and penalizes consumed views."""
        k8s_candidate = {
            "id": 901,
            "title": "Kubernetes Security Hardening Guide",
            "description": "Pod security standards and cluster defense",
            "summary": "Container isolation guide",
            "content_type": "article",
            "tags": ["kubernetes security", "cloud"],
            "entities": ["Kubernetes"],
            "quality_score": 0.95,
            "quality_tier": "TIER_1_AUTHORITATIVE",
        }

        unrelated_candidate = {
            "id": 902,
            "title": "Legacy Firmware Patch Notes",
            "description": "Minor bugfixes for embedded router",
            "summary": "",
            "content_type": "article",
            "tags": ["firmware", "iot"],
            "entities": ["Router"],
            "quality_score": 0.60,
            "quality_tier": "TIER_3",
        }

        scored_k8s = recommendation_scorer.score_candidate(
            candidate=k8s_candidate,
            user_interests=["Kubernetes Security"],
            user_difficulty="intermediate",
            saved_ids=set(),
            saved_tags=set(),
            saved_entities=set(),
            viewed_ids=set(),
            viewed_tags=set(),
            viewed_entities=set(),
            search_queries=[],
        )

        scored_unrelated = recommendation_scorer.score_candidate(
            candidate=unrelated_candidate,
            user_interests=["Kubernetes Security"],
            user_difficulty="intermediate",
            saved_ids=set(),
            saved_tags=set(),
            saved_entities=set(),
            viewed_ids=set(),
            viewed_tags=set(),
            viewed_entities=set(),
            search_queries=[],
        )

        self.assertGreater(scored_k8s.score, scored_unrelated.score)
        self.assertTrue(any("Kubernetes Security" in r for r in scored_k8s.match_reasons))

        # Test viewed penalty
        scored_viewed = recommendation_scorer.score_candidate(
            candidate=k8s_candidate,
            user_interests=["Kubernetes Security"],
            user_difficulty="intermediate",
            saved_ids=set(),
            saved_tags=set(),
            saved_entities=set(),
            viewed_ids={901},
            viewed_tags=set(),
            viewed_entities=set(),
            search_queries=[],
        )
        self.assertLess(scored_viewed.score, scored_k8s.score)

    def test_05_recommendation_service_interactions_and_profile(self):
        """Test interaction logging, bookmarks, and profile management."""
        session = "session_test_5"
        # 1. Update profile
        prof = recommendation_service.update_profile(
            session_id=session,
            interests=["Cloud Security", "Docker Security"],
            difficulty_level="advanced",
            preferred_types=["article", "tool"],
        )
        self.assertEqual(prof.difficulty_level, "advanced")
        self.assertIn("Cloud Security", prof.interests)

        # 2. Record view and save interactions
        recommendation_service.record_interaction(
            session_id=session,
            interaction_type="view",
            content_id=1001,
        )
        recommendation_service.record_interaction(
            session_id=session,
            interaction_type="save",
            content_id=1002,
        )
        recommendation_service.record_interaction(
            session_id=session,
            interaction_type="search",
            search_query="container runtime security",
        )

        refreshed_prof = recommendation_service.get_or_create_profile(session_id=session)
        self.assertGreaterEqual(refreshed_prof.viewed_count, 1)
        self.assertGreaterEqual(refreshed_prof.saved_count, 1)

        # 3. Retrieve saved items
        saved_items = recommendation_service.get_saved_content(session_id=session)
        self.assertTrue(any(i.content_id == 1002 for i in saved_items))

    def test_06_content_type_filtering(self):
        """Verify recommendations filtering across Articles, Videos, Research, Tools, Courses, Documents."""
        session = "session_types_test"
        recommendation_service.update_profile(
            session_id=session,
            interests=["Kubernetes Security"],
            difficulty_level="intermediate",
        )

        for c_type in ["articles", "videos", "research", "tools", "courses", "documents"]:
            feed = recommendation_service.get_recommendations(
                session_id=session,
                content_type=c_type,
                limit=5,
            )
            self.assertGreater(len(feed.items), 0, f"Expected items for content type: {c_type}")

    def test_07_rest_api_endpoints(self):
        """Verify all FastAPI REST endpoints for Section 31."""
        session = "api_test_session"

        # 1. GET /recommendations
        res = self.client.get(f"/api/v1/recommendations?session_id={session}&limit=5")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("items", data)
        self.assertIn("suggested_topics", data)
        self.assertIn("profile_summary", data)
        self.assertGreater(len(data["items"]), 0)

        # 2. POST /recommendations/interactions
        res_inter = self.client.post(
            "/api/v1/recommendations/interactions",
            json={
                "session_id": session,
                "interaction_type": "view",
                "content_id": 1005,
                "metadata": {"source_page": "dashboard"},
            },
        )
        self.assertEqual(res_inter.status_code, 201)
        self.assertEqual(res_inter.json()["status"], "success")

        # 3. GET /recommendations/profile & PUT /recommendations/profile
        res_prof = self.client.get(f"/api/v1/recommendations/profile?session_id={session}")
        self.assertEqual(res_prof.status_code, 200)

        res_update = self.client.put(
            "/api/v1/recommendations/profile",
            json={
                "session_id": session,
                "interests": ["Kubernetes Security", "Zero-Day Vulnerabilities"],
                "difficulty_level": "expert",
            },
        )
        self.assertEqual(res_update.status_code, 200)
        self.assertEqual(res_update.json()["difficulty_level"], "expert")

        # 4. GET /recommendations/topics (Canonical example)
        res_topics = self.client.get("/api/v1/recommendations/topics?topic=Kubernetes+Security&limit=5")
        self.assertEqual(res_topics.status_code, 200)
        topic_names = [t["topic"] for t in res_topics.json()]
        self.assertEqual(
            topic_names,
            [
                "Container Security",
                "Docker Security",
                "Cloud Security",
                "Kubernetes Threat Detection",
                "Runtime Security",
            ],
        )

        # 5. GET /recommendations/saved
        # First save an item
        self.client.post(
            "/api/v1/recommendations/interactions",
            json={
                "session_id": session,
                "interaction_type": "save",
                "content_id": 1008,
            },
        )
        res_saved = self.client.get(f"/api/v1/recommendations/saved?session_id={session}")
        self.assertEqual(res_saved.status_code, 200)
        saved_data = res_saved.json()
        self.assertTrue(any(i["content_id"] == 1008 for i in saved_data))


if __name__ == "__main__":
    unittest.main()
