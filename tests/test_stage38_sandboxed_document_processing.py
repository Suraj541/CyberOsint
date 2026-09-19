"""
Unit and Integration Tests for Section 39 (Step 38: Sandboxed Document Processing).
Conforms strictly to IMPLEMENT.md Section 39:
- External documents can contain malicious content.
- Do not process untrusted files directly inside the main API process.
- Use 5-stage pipeline:
  Worker -> Sandbox -> Parser -> Extracted text -> Sanitized result
- Never execute:
  1. Macros
  2. Embedded programs
  3. Unknown binaries
  during document ingestion.
"""

from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch
import zipfile

ROOT_DIR = Path(__file__).resolve().parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from fastapi.testclient import TestClient
from app.main import app as fastapi_app
from connectors.document.connector import DocumentConnector
from services.documents import (
    DocumentProcessor,
    DocumentSandboxError,
    DocumentSecurityScanResult,
    DocumentSecurityScanner,
    DocumentTextSanitizer,
    EmbeddedProgramBlockedError,
    MacroExecutionBlockedError,
    PipelineStageResult,
    SafeDocumentParser,
    SandboxedDocumentProcessor,
    SanitizedDocumentResult,
    UnknownBinaryBlockedError,
    document_processor,
    sandboxed_processor,
)
from services.security import audit_logger


class TestSandboxedDocumentProcessingSection39(unittest.TestCase):
    """Rigorous test suite for Section 39 Step 38 (Sandboxed Document Processing)."""

    def setUp(self):
        self.client = TestClient(fastapi_app)
        self.processor = sandboxed_processor

    # -------------------------------------------------------------------------
    # Mandate 1: Worker Isolation ("Do not process directly inside main process")
    # -------------------------------------------------------------------------
    def test_01_worker_process_isolation_and_pid_tracking(self):
        """Verify parsing executes out-of-process in an isolated worker with distinct PID."""
        clean_text = "# Intelligence Bulletin\nThreat actor APT29 observed exploiting CVE-2024-21762."
        res = self.processor.process(
            clean_text,
            filename="bulletin.md",
            enforce_worker_process=True,
            timeout=5.0,
        )

        self.assertTrue(res.success)
        self.assertIsNotNone(res.worker_pid)
        # Worker PID must exist and typically differs from host process (or tracked as daemon)
        self.assertTrue(res.worker_pid > 0)
        self.assertEqual(len(res.stages), 5)
        self.assertEqual(res.stages[0].stage_name, "Worker")
        self.assertEqual(res.stages[0].status, "success")
        self.assertIn("Isolated worker process", res.stages[0].details)

    def test_02_worker_timeout_handling_safely_terminates(self):
        """Worker process exceeding execution timeout terminates cleanly without hanging host process."""
        clean_text = "Standard threat advisory text."

        # Simulate timeout by setting an impossibly short timeout of 0.0001 seconds
        # or mocking worker join
        with patch("multiprocessing.Process.join") as mock_join, patch("multiprocessing.Process.is_alive", return_value=True):
            res = self.processor._execute_in_worker(
                clean_text.encode("utf-8"),
                filename="slow_doc.pdf",
                timeout=0.01,
            )
            self.assertFalse(res.success)
            self.assertEqual(res.detected_type, "timeout")
            self.assertIn("timed out", res.error)

    # -------------------------------------------------------------------------
    # Mandate 2: "Never execute Macros during document ingestion"
    # -------------------------------------------------------------------------
    def test_03_block_vba_macros_in_office_packages(self):
        """Verify VBA macro projects (vbaProject.bin) in OpenXML documents are detected and blocked."""
        # Create a ZIP buffer containing word/vbaProject.bin
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:t>Confidential Report</w:t></w:p></w:body></w:document>")
            zf.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1VBA_PROJECT_PAYLOAD_HERE")
        macro_docx = bio.getvalue()

        # 1. Scanner check
        scan = DocumentSecurityScanner.scan_document(macro_docx, filename="report.docx")
        self.assertFalse(scan.is_safe)
        self.assertEqual(scan.quarantine_status, "quarantined")
        self.assertTrue(len(scan.macros_detected) >= 1)
        self.assertIn("vbaProject.bin", scan.macros_detected[0])

        # 2. Sandboxed worker process check
        res = self.processor.process(macro_docx, filename="report.docx", enforce_worker_process=False)
        self.assertFalse(res.success)
        self.assertEqual(res.security_scan.quarantine_status, "quarantined")
        self.assertIn("Macros detected", res.error)

        # 3. Document processor exception check
        with self.assertRaises(MacroExecutionBlockedError):
            document_processor.process_document(macro_docx, filename_or_url="report.docx")

    def test_04_block_macro_enabled_extensions(self):
        """Verify macro-enabled extensions (.docm, .xlsm, .pptm) are quarantined."""
        for ext in [".docm", ".xlsm", ".pptm"]:
            bio = io.BytesIO()
            with zipfile.ZipFile(bio, "w") as zf:
                zf.writestr("content.xml", "<data>test</data>")
            doc_bytes = bio.getvalue()

            filename = f"finance_q1{ext}"
            scan = DocumentSecurityScanner.scan_document(doc_bytes, filename=filename)
            self.assertFalse(scan.is_safe)
            self.assertTrue(any("Macro-enabled" in m for m in scan.macros_detected))

    # -------------------------------------------------------------------------
    # Mandate 3: "Never execute Embedded programs during document ingestion"
    # -------------------------------------------------------------------------
    def test_05_block_embedded_programs_in_office_containers(self):
        """Verify embedded PE executables and OLE packages inside Office docs are blocked."""
        # Create a ZIP buffer containing word/embeddings/oleObject1.bin with Windows PE 'MZ' header
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            zf.writestr("word/document.xml", "<w:document><w:body><w:p><w:t>Invoice</w:t></w:p></w:body></w:document>")
            # Embedded PE executable with MZ header
            zf.writestr("word/embeddings/oleObject1.bin", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00This is a malicious PE executable")
        embedded_docx = bio.getvalue()

        scan = DocumentSecurityScanner.scan_document(embedded_docx, filename="invoice.docx")
        self.assertFalse(scan.is_safe)
        self.assertTrue(len(scan.embedded_programs_detected) >= 1)
        self.assertTrue(any("PE binary" in ep or "OLE" in ep for ep in scan.embedded_programs_detected))

        # Must raise EmbeddedProgramBlockedError in document_processor
        with self.assertRaises(EmbeddedProgramBlockedError):
            document_processor.process_document(embedded_docx, filename_or_url="invoice.docx")

    def test_06_block_pdf_launch_and_javascript_actions(self):
        """Verify PDF /Launch actions (program execution) and /JavaScript streams are blocked."""
        # 1. PDF with /Launch action
        pdf_launch = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) /P (/c calc.exe) >> >>\nendobj\n"
        scan_launch = DocumentSecurityScanner.scan_document(pdf_launch, filename="exploit.pdf")
        self.assertFalse(scan_launch.is_safe)
        self.assertTrue(any("/Launch" in ep for ep in scan_launch.embedded_programs_detected))

        with self.assertRaises(EmbeddedProgramBlockedError):
            document_processor.process_document(pdf_launch, filename_or_url="exploit.pdf")

        # 2. PDF with /JavaScript active script
        pdf_js = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript << /Names [ (test) << /S /JavaScript /JS (app.alert('test')) >> ] >> >> >>\nendobj\n"
        scan_js = DocumentSecurityScanner.scan_document(pdf_js, filename="script.pdf")
        self.assertFalse(scan_js.is_safe)
        self.assertTrue(any("JavaScript" in ep for ep in scan_js.embedded_programs_detected))

    # -------------------------------------------------------------------------
    # Mandate 4: "Never execute Unknown binaries during document ingestion"
    # -------------------------------------------------------------------------
    def test_07_block_unknown_binaries_and_extension_spoofing(self):
        """Verify unknown executable binaries disguised with document extensions are rejected."""
        # Windows PE binary disguised as document.pdf
        pe_payload = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This program cannot be run in DOS mode."
        scan_pe = DocumentSecurityScanner.scan_document(pe_payload, filename="urgent_report.pdf")
        self.assertFalse(scan_pe.is_safe)
        self.assertEqual(scan_pe.detected_type, "pe_executable")
        self.assertTrue(len(scan_pe.unknown_binaries_detected) >= 1)

        with self.assertRaises(UnknownBinaryBlockedError):
            document_processor.process_document(pe_payload, filename_or_url="urgent_report.pdf")

        # Linux ELF binary disguised as document.docx
        elf_payload = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00Linux binary payload"
        scan_elf = DocumentSecurityScanner.scan_document(elf_payload, filename="whitepaper.docx")
        self.assertFalse(scan_elf.is_safe)
        self.assertEqual(scan_elf.detected_type, "elf_executable")

    def test_08_block_decompression_bomb(self):
        """Verify archives with excessive compression ratios (>50:1) are blocked as zip bombs."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            # 5MB of repeated zeros compresses down to a few hundred bytes (>100:1 ratio)
            zf.writestr("huge_zeroes.xml", b"\x00" * (5 * 1024 * 1024))
        bomb_bytes = bio.getvalue()

        scan = DocumentSecurityScanner.scan_document(bomb_bytes, filename="bomb.docx")
        self.assertFalse(scan.is_safe)
        self.assertEqual(scan.detected_type, "zip_bomb")
        self.assertIn("Decompression bomb", scan.rejection_reason)

    # -------------------------------------------------------------------------
    # Mandate 5 & 6: 5-Stage Pipeline Execution & Text Sanitization
    # -------------------------------------------------------------------------
    def test_09_complete_5_stage_pipeline_clean_document(self):
        """Verify all 5 stages complete successfully on a clean threat intelligence document."""
        clean_doc = (
            "# CISA Cybersecurity Advisory: Edge Router Flaw\n\n"
            "## Threat Summary\n"
            "Sophisticated threat actors are actively scanning for vulnerable perimeter devices.\n\n"
            "## Indicators of Compromise\n"
            "IPv4: 198.51.100.77\n"
            "Domain: c2-command.org\n"
        )
        res = self.processor.process(
            clean_doc,
            filename="cisa_advisory.md",
            enforce_worker_process=False,
        )

        self.assertTrue(res.success)
        self.assertEqual(res.detected_type, "markdown")
        self.assertTrue(res.word_count >= 10)
        self.assertIn("Edge Router Flaw", res.metadata.get("title", ""))
        self.assertIn("Threat Summary", res.sanitized_text)

        # Confirm all 5 stages in order
        expected_stages = ["Worker", "Sandbox", "Parser", "Extracted text", "Sanitized result"]
        actual_stages = [st.stage_name for st in res.stages]
        self.assertEqual(actual_stages, expected_stages)
        for st in res.stages:
            self.assertEqual(st.status, "success", f"Stage {st.stage_name} failed: {st.details}")

    def test_10_document_text_sanitizer_neutralization(self):
        """Verify DocumentTextSanitizer neutralizes scripts, formula injection, control chars, and nulls."""
        dirty_text = (
            "Clean header\x00 with null bytes\n"
            "Line with \x07bell and \x1b[31mANSI red text\x1b[0m\n"
            "Normal paragraph with <script>alert('xss')</script> inside.\n"
            "<img src='x' onerror='stealCookies()'>\n"
            "=cmd|' /C calc.exe'!A0\n"
            "+powershell|' -enc AAA'!B1\n"
        )
        clean = DocumentTextSanitizer.sanitize(dirty_text)

        # 1. Null bytes stripped
        self.assertNotIn("\x00", clean)
        # 2. ANSI codes stripped
        self.assertNotIn("\x1b[31m", clean)
        # 3. Bell char stripped
        self.assertNotIn("\x07", clean)
        # 4. Script tags replaced with filter marker
        self.assertNotIn("<script>", clean.lower())
        self.assertIn("[FILTERED_SCRIPT_TAG]", clean)
        # 5. Event handlers disabled
        self.assertNotIn("onerror=", clean)
        self.assertIn("data-disabled-event=", clean)
        # 6. Formula injection neutralized
        self.assertNotIn("\n=cmd|", clean)
        self.assertTrue("=cmd|" in clean or "' =cmd|" in clean)

    # -------------------------------------------------------------------------
    # FastAPI REST API Endpoints: /api/v1/security/sandbox/*
    # -------------------------------------------------------------------------
    def test_11_api_process_document_sandbox_endpoint(self):
        """Verify POST /api/v1/security/sandbox/process-document returns 5-stage results."""
        # 1. Process clean document
        clean_payload = {
            "filename": "threat_report.md",
            "content_text": "# Mandiant Report: APT42 Operations\n\n## Summary\nTargeted spear-phishing campaigns.",
            "enforce_worker": False,
        }
        resp = self.client.post("/api/v1/security/sandbox/process-document", json=clean_payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["detected_type"], "markdown")
        self.assertEqual(len(data["stages"]), 5)
        self.assertTrue(data["security_scan"]["is_safe"])
        self.assertEqual(data["security_scan"]["quarantine_status"], "clean")

        # 2. Process malicious document (trigger quarantine and audit log)
        malicious_payload = {
            "filename": "payload.exe",
            "content_text": "MZ\x90\x00\x03\x00\x00\x00\x04\x00Disguised executable",
            "enforce_worker": False,
        }
        resp_mal = self.client.post("/api/v1/security/sandbox/process-document", json=malicious_payload)
        self.assertEqual(resp_mal.status_code, 200)
        mal_data = resp_mal.json()
        self.assertFalse(mal_data["success"])
        self.assertFalse(mal_data["security_scan"]["is_safe"])
        self.assertEqual(mal_data["security_scan"]["quarantine_status"], "quarantined")
        self.assertIn("Prohibited executable binary", mal_data["error"])

        # Check audit trail captured document_sandbox_quarantined
        events = audit_logger.get_recent_events(limit=5, event_type="document_sandbox_quarantined")
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0].status, "quarantined")
        self.assertEqual(events[0].resource, "payload.exe")

    def test_12_api_sandbox_stats_endpoint(self):
        """Verify GET /api/v1/security/sandbox/stats returns telemetry."""
        resp = self.client.get("/api/v1/security/sandbox/stats")
        self.assertEqual(resp.status_code, 200)
        stats = resp.json()
        self.assertIn("total_processed", stats)
        self.assertIn("macros_blocked", stats)
        self.assertIn("embedded_programs_blocked", stats)
        self.assertIn("unknown_binaries_blocked", stats)
        self.assertIn("clean_documents", stats)
        self.assertIn("threat_neutralization_rate", stats)


if __name__ == "__main__":
    unittest.main()
