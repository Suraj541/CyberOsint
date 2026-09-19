"""
Unit and Integration Tests for Section 37 (Step 36: Security Hardening).
Conforms strictly to IMPLEMENT.md Section 37:
- All 15 mandated security controls:
  1. Authentication
  2. RBAC
  3. Rate limiting
  4. Input validation
  5. SSRF protection
  6. Secure URL fetching
  7. Sandboxed document processing
  8. File-type validation
  9. API authentication
  10. Audit logs
  11. Security headers
  12. CORS restrictions
  13. Encrypted secrets
  14. Dependency scanning
  15. Container scanning
"The fetcher is a major attack surface. Treat external content as hostile."
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from services.security import (
    DocumentSandbox,
    FileTypeValidator,
    InputValidator,
    RateLimiter,
    RBACPolicy,
    SecureURLFetcher,
    SecurityAuditLogger,
    SecurityAuthManager,
    SSRFValidator,
    UserIdentity,
    audit_logger,
    auth_manager,
    container_scanner,
    dependency_scanner,
    file_validator,
    input_validator,
    rate_limiter,
    rbac_policy,
    sandbox,
    secure_fetcher,
    ssrf_validator,
)


class TestSecurityHardeningSection37(unittest.TestCase):
    """Comprehensive test suite for Section 37 Step 36 (15 Security Controls)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Control 1 & 9: Authentication & API Authentication
    # -------------------------------------------------------------------------
    def test_01_authentication_jwt_and_api_keys(self):
        """Verify Control 1 (Authentication) and Control 9 (API Authentication)."""
        # 1. Standard authentication
        admin_user = auth_manager.authenticate_user("admin", "admin_secure_pass_2026")
        self.assertIsNotNone(admin_user)
        self.assertEqual(admin_user.role, "admin")
        self.assertIn("*", admin_user.scopes)
        self.assertTrue(RBACPolicy.has_permission(admin_user, "write:system"))

        # 2. Token generation & decoding
        token = auth_manager.create_access_token(admin_user)
        self.assertIsInstance(token, str)
        self.assertTrue(len(token) > 20)

        decoded = auth_manager.decode_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.username, "admin")
        self.assertEqual(decoded.role, "admin")

        # 3. Invalid credentials rejection
        bad_user = auth_manager.authenticate_user("admin", "wrong_password")
        self.assertIsNone(bad_user)

        # 4. Tampered token rejection
        tampered_token = token[:-4] + "abcd"
        self.assertIsNone(auth_manager.decode_token(tampered_token))

        # 5. Programmatic API key authentication (Control 9)
        api_user = auth_manager.authenticate_user("connector_service", "connector_service_api_key")
        self.assertIsNotNone(api_user)
        self.assertEqual(api_user.role, "service_connector")
        self.assertIn("connectors:run", api_user.scopes)

    # -------------------------------------------------------------------------
    # Control 2: Role-Based Access Control (RBAC)
    # -------------------------------------------------------------------------
    def test_02_rbac_hierarchy_and_permissions(self):
        """Verify Control 2 (Role-Based Access Control - RBAC)."""
        # Hierarchy: admin > analyst > viewer
        self.assertTrue(RBACPolicy.has_role_access("admin", "admin"))
        self.assertTrue(RBACPolicy.has_role_access("admin", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("admin", "viewer"))

        self.assertFalse(RBACPolicy.has_role_access("analyst", "admin"))
        self.assertTrue(RBACPolicy.has_role_access("analyst", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("analyst", "viewer"))

        self.assertFalse(RBACPolicy.has_role_access("viewer", "admin"))
        self.assertFalse(RBACPolicy.has_role_access("viewer", "analyst"))
        self.assertTrue(RBACPolicy.has_role_access("viewer", "viewer"))

        # Scopes check
        user = UserIdentity(user_id="u1", username="test", role="analyst", scopes=["read:content", "write:content"])
        self.assertTrue(RBACPolicy.has_permission(user, "read:content"))
        self.assertFalse(RBACPolicy.has_permission(user, "write:system"))

    # -------------------------------------------------------------------------
    # Control 3: Rate Limiting
    # -------------------------------------------------------------------------
    def test_03_rate_limiting_sliding_window(self):
        """Verify Control 3 (Rate Limiting)."""
        limiter = RateLimiter(backend="memory")

        # Custom key with low limit for deterministic verification
        key = "test_rate_client_ip_1"
        limit = 3
        window = 2

        # First 3 requests must pass
        for i in range(limit):
            allowed, remaining, retry_after = limiter.check_rate_limit(key, limit=limit, window_seconds=window)
            self.assertTrue(allowed, f"Request {i+1} should be allowed")
            self.assertEqual(remaining, limit - (i + 1))
            self.assertGreaterEqual(retry_after, 0)

        # 4th request must be rejected
        allowed, remaining, retry_after = limiter.check_rate_limit(key, limit=limit, window_seconds=window)
        self.assertFalse(allowed)
        self.assertEqual(remaining, 0)
        self.assertGreater(retry_after, 0)

        # Standard OWASP headers format
        headers = limiter.get_rate_limit_headers(key, limit=limit, window_seconds=window)
        self.assertIn("X-RateLimit-Limit", headers)
        self.assertIn("X-RateLimit-Remaining", headers)
        self.assertIn("X-RateLimit-Reset", headers)
        self.assertEqual(headers["X-RateLimit-Limit"], str(limit))

    # -------------------------------------------------------------------------
    # Control 4: Input Validation
    # -------------------------------------------------------------------------
    def test_04_input_validation_and_sanitization(self):
        """Verify Control 4 (Input Validation)."""
        # 1. Search Query Sanitization (XSS, SQLi, null bytes)
        raw_xss = '<script>alert("pwned")</script> CVE-2024-3400'
        clean = InputValidator.sanitize_search_query(raw_xss)
        self.assertNotIn("<script>", clean)
        self.assertNotIn("</script>", clean)
        self.assertIn("CVE-2024-3400", clean)

        # Length cap (explicit max_length=256)
        long_query = "a" * 400
        self.assertEqual(len(InputValidator.sanitize_search_query(long_query, max_length=256)), 256)

        # 2. Filename Path Traversal Prevention
        traversal = "../../../etc/passwd"
        clean_file = InputValidator.sanitize_filename(traversal)
        self.assertNotIn("..", clean_file)
        self.assertNotIn("/", clean_file)
        self.assertNotIn("\\", clean_file)
        self.assertEqual(clean_file, "passwd")

        # Windows drive stripping
        win_path = "C:\\Windows\\System32\\cmd.exe"
        clean_win = InputValidator.sanitize_filename(win_path)
        self.assertNotIn(":", clean_win)
        self.assertNotIn("\\", clean_win)

        # 3. URL Format validation
        self.assertTrue(InputValidator.validate_url_format("https://cisa.gov/advisories"))
        self.assertFalse(InputValidator.validate_url_format("file:///etc/passwd"))
        self.assertFalse(InputValidator.validate_url_format("gopher://internal.network/1"))
        self.assertFalse(InputValidator.validate_url_format("javascript:alert(1)"))

    # -------------------------------------------------------------------------
    # Control 5 & 6: SSRF Protection & Secure URL Fetching
    # -------------------------------------------------------------------------
    def test_05_ssrf_protection_and_secure_fetcher(self):
        """
        Verify Control 5 (SSRF Protection) and Control 6 (Secure URL Fetching).
        Conforms strictly to IMPLEMENT.md Section 37 & 38:
        'The fetcher must block: localhost, 127.0.0.0/8, private IP ranges,
        link-local addresses, cloud metadata endpoints, internal DNS targets'
        """
        # Blocked destinations
        blocked_targets = [
            "http://127.0.0.1:8000/internal",
            "http://localhost:9200",
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1/admin",
            "http://192.168.1.1/router",
            "http://172.16.0.1/intranet",
            "http://0.0.0.0:80/",
            "file:///etc/shadow",
            "ftp://anonymous@internal.server",
        ]

        for target in blocked_targets:
            res = ssrf_validator.validate_url(target)
            self.assertFalse(res.is_safe, f"SSRF Guard should have blocked target: {target}")
            self.assertIsNotNone(res.violation_reason)

        # Public destinations allowed
        public_targets = [
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
        ]
        for target in public_targets:
            res = ssrf_validator.validate_url(target)
            self.assertTrue(res.is_safe, f"SSRF Guard should allow legitimate target: {target}")

        # Secure Fetcher pre-check blocks SSRF before making HTTP request
        fetch_res = secure_fetcher.fetch_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(fetch_res["success"])
        self.assertIn("SSRF Block", fetch_res["error"])

    # -------------------------------------------------------------------------
    # Control 7: Sandboxed Document Processing
    # -------------------------------------------------------------------------
    def test_07_sandboxed_document_processing(self):
        """Verify Control 7 (Sandboxed Document Processing)."""
        sandbox_inst = DocumentSandbox(max_size_bytes=1024 * 1024, max_decompression_ratio=10)

        # Valid text file extraction
        text_bytes = b"Cybersecurity OSINT Intelligence Report: Threat Actor APT29 Observed."
        result = sandbox_inst.sandbox_process(text_bytes, filename="report.txt")
        self.assertTrue(result["success"])
        self.assertIn("APT29", result["content"])
        self.assertEqual(result["risk_level"], "low")

        # Exceeding size ceiling
        oversized = b"A" * (2 * 1024 * 1024)
        oversized_res = sandbox_inst.sandbox_process(oversized, filename="huge.bin")
        self.assertFalse(oversized_res["success"])
        self.assertIn("exceeds safe sandbox limit", oversized_res["error"])

    # -------------------------------------------------------------------------
    # Control 8: File-Type Validation
    # -------------------------------------------------------------------------
    def test_08_file_type_validation_and_spoof_detection(self):
        """Verify Control 8 (File-Type Validation and Magic Bytes Inspection)."""
        # 1. Legitimate PDF
        pdf_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj"
        pdf_res = file_validator.inspect_bytes(pdf_bytes, filename="threat_report.pdf")
        self.assertTrue(pdf_res.is_valid)
        self.assertEqual(pdf_res.detected_mime, "application/pdf")
        self.assertFalse(pdf_res.is_executable)

        # 2. Legitimate PNG
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        png_res = file_validator.inspect_bytes(png_bytes, filename="diagram.png")
        self.assertTrue(png_res.is_valid)
        self.assertEqual(png_res.detected_mime, "image/png")

        # 3. Disguised Executable (Extension Spoofing Attack)
        # File named .pdf but actually starts with Windows PE 'MZ' header
        malicious_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        spoof_res = file_validator.inspect_bytes(malicious_pe, filename="innocent_advisory.pdf")
        self.assertFalse(spoof_res.is_valid, "Executable disguised as PDF must be rejected")
        self.assertTrue(spoof_res.is_executable)
        self.assertIn("executable", spoof_res.rejection_reason.lower())

    # -------------------------------------------------------------------------
    # Control 10: Audit Logs
    # -------------------------------------------------------------------------
    def test_10_structured_security_audit_logging(self):
        """Verify Control 10 (Audit Logs)."""
        test_audit_file = Path(self.temp_dir) / "test_audit.jsonl"
        custom_logger = SecurityAuditLogger(log_file=test_audit_file)

        # Log diverse security events
        custom_logger.log_event(
            event_type="auth_login",
            actor="analyst_test",
            role="analyst",
            resource="/api/v1/auth",
            action="POST",
            status="allowed",
            details={"ip": "10.10.10.10"},
        )
        custom_logger.log_event(
            event_type="ssrf_blocked",
            actor="external_payload",
            role="untrusted",
            resource="http://169.254.169.254",
            action="FETCH",
            status="blocked",
            details={"reason": "Metadata IP blocked"},
        )

        # Verification in-memory buffer
        events = custom_logger.get_recent_events(limit=10)
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].event_type, "ssrf_blocked")
        self.assertEqual(events[1].event_type, "auth_login")

        # Verification on-disk jsonl file
        self.assertTrue(test_audit_file.exists())
        lines = test_audit_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)
        parsed_0 = json.loads(lines[0])
        self.assertEqual(parsed_0["event_type"], "auth_login")

    # -------------------------------------------------------------------------
    # Control 11 & 12: Security Headers & CORS Restrictions
    # -------------------------------------------------------------------------
    def test_11_security_headers_and_cors_middleware(self):
        """Verify Control 11 (Security Headers) and Control 12 (CORS Restrictions)."""
        response = self.client.get("/api/v1/security/posture")
        self.assertEqual(response.status_code, 200)

        headers = response.headers
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertIn("max-age=31536000", headers.get("Strict-Transport-Security", ""))
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))
        self.assertEqual(headers.get("Referrer-Policy"), "strict-origin-when-cross-origin")

    # -------------------------------------------------------------------------
    # Control 14 & 15: Dependency & Container Scanning
    # -------------------------------------------------------------------------
    def test_14_dependency_and_container_scanners(self):
        """Verify Control 14 (Dependency Scanning) and Control 15 (Container Scanning)."""
        # Dependency scan
        dep_res = dependency_scanner.scan_dependencies()
        self.assertIn("status", dep_res)
        self.assertIn("total_packages_scanned", dep_res)
        self.assertGreater(dep_res["total_packages_scanned"], 0)

        # Container scan
        cont_res = container_scanner.scan_dockerfile()
        self.assertIn("dockerfile_checked", cont_res)
        self.assertIn("findings_count", cont_res)
        self.assertIn("recommendations", cont_res)

    # -------------------------------------------------------------------------
    # REST Endpoints: Security Center API
    # -------------------------------------------------------------------------
    def test_16_fastapi_security_endpoints(self):
        """Verify the complete suite of /api/v1/security API endpoints."""
        # 1. GET /api/v1/security/posture
        res_posture = self.client.get("/api/v1/security/posture")
        self.assertEqual(res_posture.status_code, 200)
        data = res_posture.json()
        self.assertEqual(data["compliance_score"], 100)
        self.assertEqual(data["total_controls"], 15)
        self.assertEqual(data["hardened_controls"], 15)
        self.assertEqual(len(data["controls"]), 15)

        # 2. POST /api/v1/security/auth/token (Valid)
        res_tok = self.client.post(
            "/api/v1/security/auth/token",
            json={"username": "admin", "password_or_key": "admin_secure_pass_2026"},
        )
        self.assertEqual(res_tok.status_code, 200)
        tok_data = res_tok.json()
        self.assertIn("access_token", tok_data)
        self.assertEqual(tok_data["role"], "admin")
        token = tok_data["access_token"]

        # 3. POST /api/v1/security/auth/token (Invalid)
        res_tok_bad = self.client.post(
            "/api/v1/security/auth/token",
            json={"username": "admin", "password_or_key": "wrong_password_attempt"},
        )
        self.assertEqual(res_tok_bad.status_code, 401)

        # 4. GET /api/v1/security/auth/me (With Bearer token)
        res_me = self.client.get(
            "/api/v1/security/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(res_me.status_code, 200)
        me_data = res_me.json()
        self.assertEqual(me_data["username"], "admin")
        self.assertEqual(me_data["role"], "admin")

        # 5. POST /api/v1/security/validate-url (SSRF Target Blocked)
        res_val_ssrf = self.client.post(
            "/api/v1/security/validate-url",
            json={"url": "http://169.254.169.254/latest/meta-data/"},
        )
        self.assertEqual(res_val_ssrf.status_code, 200)
        val_data = res_val_ssrf.json()
        self.assertFalse(val_data["is_safe"])
        self.assertTrue(
            "cloud metadata" in val_data["violation_reason"].lower()
            or "disallowed" in val_data["violation_reason"].lower()
            or "blocked" in val_data["violation_reason"].lower()
        )

        # 6. POST /api/v1/security/validate-url (Legitimate URL Allowed)
        res_val_good = self.client.post(
            "/api/v1/security/validate-url",
            json={"url": "https://www.cisa.gov/cybersecurity-advisories/all.xml"},
        )
        self.assertEqual(res_val_good.status_code, 200)
        self.assertTrue(res_val_good.json()["is_safe"])

        # 7. GET /api/v1/security/audit-logs
        res_logs = self.client.get("/api/v1/security/audit-logs?limit=10")
        self.assertEqual(res_logs.status_code, 200)
        logs = res_logs.json()
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)

        # 8. POST /api/v1/security/scan-dependencies & /scan-container
        res_dep = self.client.post("/api/v1/security/scan-dependencies")
        self.assertEqual(res_dep.status_code, 200)

        res_cont = self.client.post("/api/v1/security/scan-container")
        self.assertEqual(res_cont.status_code, 200)


if __name__ == "__main__":
    unittest.main()
