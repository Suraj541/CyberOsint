"""
Cybersecurity Taxonomy Tests
Tests all 16 canonical categories, stable category IDs, subcategories,
tag resolution, CWE mapping, keyword matching, and /api/v1/taxonomy REST endpoints.
Conforms strictly to IMPLEMENT.md Section 14 specifications.
"""

import unittest
from fastapi.testclient import TestClient

from app.main import app
from packages.taxonomy import (
    CategoryId,
    get_all_categories,
    get_category,
    match_keywords,
    resolve_cwe,
    resolve_tag,
    taxonomy_registry,
)


class TestTaxonomy(unittest.TestCase):
    """Test suite for the 16 cybersecurity categories and taxonomy registry."""

    def setUp(self):
        self.client = TestClient(app)

    def test_sixteen_mandated_categories_exist_with_stable_ids(self):
        """Confirm exactly 16 standard categories are defined with stable snake_case IDs."""
        expected_ids = [
            "application_security",
            "cloud_security",
            "network_security",
            "malware",
            "threat_intelligence",
            "digital_forensics",
            "incident_response",
            "osint",
            "cryptography",
            "identity",
            "mobile",
            "iot",
            "ics",
            "ai_security",
            "devsecops",
            "vulnerability_management",
        ]

        all_cats = get_all_categories()
        self.assertEqual(len(all_cats), 16)

        cat_ids = [c.id for c in all_cats]
        for exp_id in expected_ids:
            self.assertIn(exp_id, cat_ids, f"Category ID '{exp_id}' missing from taxonomy")
            cat = get_category(exp_id)
            self.assertIsNotNone(cat)
            self.assertEqual(cat.id, exp_id)
            self.assertTrue(len(cat.name) > 0)
            self.assertTrue(len(cat.description) > 0)
            self.assertTrue(len(cat.subcategories) > 0, f"Category '{exp_id}' has no subcategories")

    def test_category_subcategories_and_hierarchy(self):
        """Confirm subcategories have unique IDs and informative descriptors."""
        for cat in get_all_categories():
            sub_ids = cat.subcategory_ids
            # Subcategory IDs must be unique within a category
            self.assertEqual(len(sub_ids), len(set(sub_ids)))
            for sub in cat.subcategories:
                self.assertTrue(sub.id.islower())
                self.assertTrue(len(sub.name) > 0)
                self.assertTrue(len(sub.description) > 0)

    def test_tag_resolution(self):
        """Confirm resolve_tag maps raw tags, aliases, and buzzwords to canonical categories."""
        test_cases = [
            ("ransomware", "malware", "ransomware"),
            ("k8s", "cloud_security", "kubernetes_security"),
            ("owasp", "application_security", "web_security"),
            ("xss", "application_security", "web_security"),
            ("sqli", "application_security", "injection_attacks"),
            ("ddos", "network_security", "ddos_protection"),
            ("wireshark", "digital_forensics", "network_forensics"),
            ("shodan", "osint", "domain_recon"),
            ("active-directory", "identity", "active_directory"),
            ("zero-day", "vulnerability_management", "zero_day_research"),
            ("cve", "vulnerability_management", "cve_intelligence"),
            ("prompt-injection", "ai_security", "llm_jailbreaks"),
            ("sast", "devsecops", "code_analysis"),
            ("scada", "ics", "scada_plc"),
        ]

        for tag, expected_cat, expected_sub in test_cases:
            match = resolve_tag(tag)
            self.assertIsNotNone(match, f"Failed to resolve tag: '{tag}'")
            self.assertEqual(match["category_id"], expected_cat)
            if expected_sub:
                self.assertEqual(match["subcategory_id"], expected_sub)

    def test_cwe_resolution(self):
        """Confirm resolve_cwe maps Common Weakness Enumeration IDs to taxonomy categories."""
        cwe_cases = [
            ("CWE-79", "application_security", "web_security"),         # XSS
            ("CWE-89", "application_security", "injection_attacks"),    # SQLi
            ("89", "application_security", "injection_attacks"),        # Plain number
            ("CWE-122", "application_security", "memory_safety"),       # Heap buffer overflow
            ("CWE-327", "cryptography", "crypto_flaws"),                 # Broken crypto
            ("CWE-798", "identity", "credential_theft"),                 # Hardcoded credentials
            ("CWE-400", "network_security", "ddos_protection"),          # Resource consumption
        ]

        for cwe_input, expected_cat, expected_sub in cwe_cases:
            match = resolve_cwe(cwe_input)
            self.assertIsNotNone(match, f"Failed to resolve CWE: '{cwe_input}'")
            self.assertEqual(match["category_id"], expected_cat)
            if expected_sub:
                self.assertEqual(match["subcategory_id"], expected_sub)

    def test_keyword_matching(self):
        """Confirm match_keywords accurately scores text against category keywords."""
        sample_text = (
            "Researchers detected a new ransomware strain deploying double extortion tactics "
            "and dropping an infostealer payload across Windows servers."
        )
        matches = match_keywords(sample_text)
        self.assertGreater(len(matches), 0)
        top_match = matches[0]
        self.assertEqual(top_match["category_id"], "malware")
        self.assertIn("ransomware", top_match["matched_keywords"])

    def test_taxonomy_rest_endpoints(self):
        """Confirm /api/v1/taxonomy REST endpoints."""
        # 1. List all categories
        resp = self.client.get("/api/v1/taxonomy/categories")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(len(data), 16)
        cat_ids = [c["id"] for c in data]
        self.assertIn("application_security", cat_ids)
        self.assertIn("ai_security", cat_ids)

        # 2. Get specific category
        resp_single = self.client.get("/api/v1/taxonomy/categories/cloud_security")
        self.assertEqual(resp_single.status_code, 200)
        cat_data = resp_single.json()
        self.assertEqual(cat_data["id"], "cloud_security")
        self.assertGreater(len(cat_data["subcategories"]), 0)

        # 404 for unknown category
        resp_404 = self.client.get("/api/v1/taxonomy/categories/unknown_security_domain")
        self.assertEqual(resp_404.status_code, 404)

        # 3. Resolve tag
        resp_tag = self.client.get("/api/v1/taxonomy/resolve-tag?tag=ransomware")
        self.assertEqual(resp_tag.status_code, 200)
        self.assertEqual(resp_tag.json()["category_id"], "malware")

        # 4. Resolve CWE
        resp_cwe = self.client.get("/api/v1/taxonomy/resolve-cwe/CWE-89")
        self.assertEqual(resp_cwe.status_code, 200)
        self.assertEqual(resp_cwe.json()["category_id"], "application_security")

        # 5. Match text
        resp_match = self.client.post(
            "/api/v1/taxonomy/match",
            json={"text": "Investigating a sophisticated prompt injection attack bypassing LLM guardrails."},
        )
        self.assertEqual(resp_match.status_code, 200)
        matches = resp_match.json()
        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0]["category_id"], "ai_security")


if __name__ == "__main__":
    unittest.main()
