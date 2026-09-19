"""
Tests for Subsystem 13: File Validation.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing), Section 37, and Section 39.
Validates magic bytes inspection, executable rejection (PE, ELF, Mach-O), extension spoofing
detection, size ceilings, and path traversal sanitization.
"""

from pathlib import Path
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.security import (
    FileTypeValidator,
    InputValidator,
    file_validator,
    input_validator,
)


class TestFileValidationSubsystem(unittest.TestCase):
    """Subsystem 13: File Validation Unit Tests."""

    def test_01_valid_pdf_magic_bytes(self):
        """Verify legitimate PDF files pass magic bytes validation."""
        pdf_bytes = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<<>>\nendobj"
        res = file_validator.inspect_bytes(pdf_bytes, filename="threat_intel_report.pdf")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.detected_mime, "application/pdf")
        self.assertFalse(res.is_executable)

    def test_02_valid_png_and_image_magic_bytes(self):
        """Verify legitimate PNG image bytes pass inspection."""
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        res = file_validator.inspect_bytes(png_bytes, filename="network_diagram.png")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.detected_mime, "image/png")
        self.assertFalse(res.is_executable)

    def test_03_detect_extension_spoofing_windows_pe_executable(self):
        """Verify executable with Windows PE 'MZ' header disguised as .pdf is rejected."""
        malicious_pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"
        res = file_validator.inspect_bytes(malicious_pe, filename="cisa_alert.pdf")
        self.assertFalse(res.is_valid, "Windows PE executable disguised as PDF must be rejected")
        self.assertTrue(res.is_executable)
        self.assertIn("executable", res.rejection_reason.lower())

    def test_04_detect_extension_spoofing_linux_elf_executable(self):
        """Verify Linux ELF executable disguised as plain text/document is rejected."""
        malicious_elf = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        res = file_validator.inspect_bytes(malicious_elf, filename="payload_notes.txt")
        self.assertFalse(res.is_valid, "Linux ELF executable disguised as TXT must be rejected")
        self.assertTrue(res.is_executable)

    def test_05_oversized_file_rejection(self):
        """Verify files exceeding maximum allowed ceiling (25MB) are rejected."""
        oversized_payload = b"%PDF-1.7\n" + (b"A" * (26 * 1024 * 1024))
        res = file_validator.inspect_bytes(oversized_payload, filename="huge_paper.pdf")
        self.assertFalse(res.is_valid)
        self.assertIn("exceeds maximum allowed size", res.rejection_reason.lower())

    def test_06_filename_path_traversal_sanitization(self):
        """Verify filename sanitization eliminates directory traversal, absolute paths, and null bytes."""
        traversal_attempts = [
            ("../../../etc/shadow", "shadow"),
            ("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("/var/log/syslog", "syslog"),
            ("C:\\boot.ini", "boot.ini"),
            ("innocent.pdf\x00.exe", "innocent.pdf.exe"),
        ]
        for dirty, expected_clean in traversal_attempts:
            clean = InputValidator.sanitize_filename(dirty)
            self.assertNotIn("..", clean)
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)
            self.assertEqual(clean, expected_clean)


if __name__ == "__main__":
    unittest.main()
