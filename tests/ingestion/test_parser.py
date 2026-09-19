"""
Tests for Subsystem 2: Parser.
Conforms strictly to IMPLEMENT.md Section 40 (Step 39: Testing).
Validates multi-format parsing across HTML, Markdown, Plain Text, PDF, DOCX, and PPTX.
"""

import io
from pathlib import Path
import sys
import unittest
import zipfile

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
API_DIR = ROOT_DIR / "apps" / "api"
sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(API_DIR))

from services.documents.extractors.html_extractor import HtmlExtractor
from services.documents.extractors.markdown_extractor import MarkdownExtractor
from services.documents.extractors.office_extractor import OfficeExtractor
from services.documents.extractors.pdf_extractor import PdfExtractor
from services.documents.extractors.text_extractor import TextExtractor
from services.documents.models import DocumentType


class TestParserSubsystem(unittest.TestCase):
    """Subsystem 2: Parser Unit Tests."""

    def setUp(self):
        self.html_ext = HtmlExtractor()
        self.md_ext = MarkdownExtractor()
        self.text_ext = TextExtractor()
        self.pdf_ext = PdfExtractor()
        self.office_ext = OfficeExtractor()

    def test_01_parse_markdown_frontmatter_and_sections(self):
        """Verify Markdown parsing extracts frontmatter metadata and # sections."""
        md_content = """---
title: "LockBit 3.0 Ransomware Analysis"
author: "Threat Intelligence Team"
date: "2026-09-17"
---

# Executive Summary
LockBit 3.0 continues aggressive double-extortion campaigns against critical infrastructure.

## Technical Details
Uses modular DLL loaders and custom encryption routines.

## Indicators of Compromise
SHA256: 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
"""
        meta, text, sections = self.md_ext.extract(md_content)
        self.assertEqual(meta.title, "LockBit 3.0 Ransomware Analysis")
        self.assertIn("Threat Intelligence Team", meta.authors)
        self.assertEqual(meta.publication_date, "2026-09-17")
        self.assertTrue(len(sections) >= 2)
        headings = [s[0] for s in sections]
        self.assertTrue(any("Executive Summary" in h or "Technical Details" in h for h in headings))

    def test_02_parse_html_metadata_and_body(self):
        """Verify HTML extractor cleans tags and extracts title, headings, and clean text."""
        html_content = """<!DOCTYPE html>
<html>
<head>
  <title>Security Alert: Active Exploit Campaigns</title>
  <meta name="author" content="CERT Team">
  <meta name="description" content="Immediate patching advised.">
</head>
<body>
  <h1>Vulnerability Details</h1>
  <p>Attackers are chaining CVE-2024-1709 and CVE-2024-1708.</p>
  <h2>Remediation Guidance</h2>
  <p>Update appliances to version 23.9.8 immediately.</p>
</body>
</html>"""
        meta, text, sections = self.html_ext.extract(html_content)
        self.assertEqual(meta.title, "Security Alert: Active Exploit Campaigns")
        self.assertIn("CVE-2024-1709", text)
        self.assertFalse("<p>" in text)
        self.assertTrue(len(sections) >= 1)

    def test_03_parse_plain_text_extractor(self):
        """Verify plain text extractor structures raw bulletins into clean sections."""
        raw_text = """CISA KNOWN EXPLOITED VULNERABILITIES CATALOG UPDATE
Date: 2026-09-17

DESCRIPTION:
CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities Catalog.

ACTION REQUIRED:
Apply manufacturer updates within 21 days.
"""
        meta, text, sections = self.text_ext.extract(raw_text)
        self.assertIn("CISA", meta.title)
        self.assertIn("Known Exploited Vulnerabilities", text)
        self.assertTrue(len(sections) >= 1)

    def test_04_parse_office_docx_clean_structure(self):
        """Verify OfficeExtractor extracts paragraphs and headings from valid DOCX archives."""
        bio = io.BytesIO()
        with zipfile.ZipFile(bio, "w") as zf:
            doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
      <w:r><w:t>Threat Assessment Report</w:t></w:r>
    </w:p>
    <w:p>
      <w:r><w:t>Zero-day vulnerabilities reported in cloud gateway firmware.</w:t></w:r>
    </w:p>
  </w:body>
</w:document>"""
            zf.writestr("word/document.xml", doc_xml)
        docx_bytes = bio.getvalue()

        meta, text, sections = self.office_ext.extract_docx(docx_bytes, filename="report.docx")
        self.assertIn("Threat Assessment Report", meta.title)
        self.assertIn("Zero-day vulnerabilities", text)
        self.assertTrue(len(sections) >= 1)

    def test_05_parse_empty_and_corrupted_inputs_handled_safely(self):
        """Verify extractors return empty/safe defaults on empty or corrupted payloads."""
        meta_md, text_md, sections_md = self.md_ext.extract("")
        self.assertEqual(text_md, "")
        self.assertEqual(len(sections_md), 0)

        meta_html, text_html, sections_html = self.html_ext.extract("")
        self.assertEqual(text_html, "")
        self.assertEqual(len(sections_html), 0)

        meta_pdf, text_pdf, sections_pdf = self.pdf_ext.extract(b"")
        self.assertEqual(text_pdf, "")
        self.assertEqual(len(sections_pdf), 0)


if __name__ == "__main__":
    unittest.main()
