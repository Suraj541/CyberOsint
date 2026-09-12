"""
Stage 24: Document Intelligence Baseline Tests
Validates Section 25 / Step 24 implementation:
- Services package: services/documents/
- Format extractors: PDF, HTML, Markdown, TXT, DOCX, PPTX
- Pipeline: Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings
- Section-preserving semantic chunking
- Copyright-aware retention modes (FULL_TEXT vs METADATA_ONLY)
- Document Connector: connectors/document/ registered in connector_registry
Conforms strictly to IMPLEMENT.md Section 25 specifications.
"""

from datetime import datetime, timezone
import io
from pathlib import Path
import sys
import unittest
import zipfile

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from connectors.base import BaseConnector, NormalizedItem
from connectors.document import DocumentConnector
from connectors.registry import connector_registry
from services.documents import (
    DocumentMetadata,
    DocumentProcessor,
    DocumentResult,
    DocumentSectionChunk,
    DocumentType,
    HtmlExtractor,
    MarkdownExtractor,
    OfficeExtractor,
    PdfExtractor,
    RetentionMode,
    TextExtractor,
    document_processor,
    extract_document,
)


from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import get_db
from app.main import app
from app.models.base import Base


class TestStage24DocumentIntelligence(unittest.TestCase):
    """Test suite validating Section 25 / Step 24 Document Intelligence."""

    def setUp(self):
        """Set up an isolated in-memory SQLite database for test runs."""
        self.engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        self.TestingSessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine,
        )
        Base.metadata.create_all(bind=self.engine)
        self.db = self.TestingSessionLocal()

        def override_get_db():
            db = self.TestingSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        """Clean up in-memory database and dependency overrides."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)
        app.dependency_overrides.clear()

    def test_document_package_structure(self):
        """Confirm all mandated document intelligence packages and modules exist."""
        doc_service_dir = repo_root / "services" / "documents"
        self.assertTrue(doc_service_dir.exists(), "services/documents directory missing")
        for mod in ("__init__.py", "models.py", "processor.py"):
            self.assertTrue((doc_service_dir / mod).exists(), f"services/documents/{mod} missing")

        extractors_dir = doc_service_dir / "extractors"
        self.assertTrue(extractors_dir.exists(), "services/documents/extractors directory missing")
        for ext in ("__init__.py", "html_extractor.py", "markdown_extractor.py", "office_extractor.py", "pdf_extractor.py", "text_extractor.py"):
            self.assertTrue((extractors_dir / ext).exists(), f"services/documents/extractors/{ext} missing")

        doc_conn_dir = repo_root / "connectors" / "document"
        self.assertTrue(doc_conn_dir.exists(), "connectors/document directory missing")
        for cmod in ("__init__.py", "connector.py"):
            self.assertTrue((doc_conn_dir / cmod).exists(), f"connectors/document/{cmod} missing")

    def test_markdown_extractor(self):
        """Confirm MarkdownExtractor parses frontmatter, headings (#, ##), and metadata."""
        sample_md = """---
title: "Advanced Persistent Threat 29 Technical Dossier"
author: "CrowdStrike Intelligence Team"
date: "2024-03-15"
description: "Detailed analysis of Cozy Bear cloud persistence techniques."
---

# Advanced Persistent Threat 29 Technical Dossier

## Executive Summary
Cozy Bear (APT29) has been observed leveraging Microsoft Graph API for stealthy command and control.

## Initial Access & Credential Theft
The threat actors utilized password spraying against Azure AD accounts without multi-factor authentication.
Targeting CVE-2024-3400 for edge appliance penetration.

## Indicators of Compromise
- IP: 198.51.100.42
- Domain: malicious-c2.net
"""
        extractor = MarkdownExtractor()
        meta, full_text, sections = extractor.extract(sample_md)

        self.assertEqual(meta.title, "Advanced Persistent Threat 29 Technical Dossier")
        self.assertIn("CrowdStrike Intelligence Team", meta.authors)
        self.assertEqual(meta.document_type, DocumentType.MARKDOWN)
        self.assertIn("Executive Summary", meta.section_headings)
        self.assertIn("Initial Access & Credential Theft", meta.section_headings)
        self.assertGreaterEqual(len(sections), 3)

    def test_html_extractor(self):
        """Confirm HtmlExtractor parses <title>, meta tags, and <h1..h3> headings."""
        sample_html = """<!DOCTYPE html>
<html>
<head>
    <title>CISA Advisory: Urgent Mitigation of Ivanti Connect Secure Zero-Day</title>
    <meta name="author" content="CISA Cybersecurity Advisory Team" />
    <meta name="article:published_time" content="2024-01-16T12:00:00Z" />
    <meta name="description" content="Technical details regarding active exploitation of CVE-2024-21887." />
</head>
<body>
    <header><nav><a href="/">Home</a></nav></header>
    <h1>CISA Advisory: Urgent Mitigation of Ivanti Connect Secure Zero-Day</h1>
    <h2>Overview</h2>
    <p>Multiple threat groups are actively exploiting auth bypass flaws in Ivanti appliances.</p>
    <h2>Mitigation Steps</h2>
    <p>Apply security patches immediately and review network logs for anomalies.</p>
    <footer>Copyright 2024 CISA. All rights reserved.</footer>
</body>
</html>"""
        extractor = HtmlExtractor()
        meta, full_text, sections = extractor.extract(sample_html)

        self.assertIn("Ivanti Connect Secure", meta.title)
        self.assertIn("CISA Cybersecurity Advisory Team", meta.authors)
        self.assertEqual(meta.document_type, DocumentType.HTML)
        self.assertIn("Overview", meta.section_headings)
        self.assertIn("Mitigation Steps", meta.section_headings)
        self.assertNotIn("Home", full_text)  # Nav should be stripped
        self.assertGreaterEqual(len(sections), 2)

    def test_text_extractor(self):
        """Confirm TextExtractor identifies numbered and uppercase section headings."""
        sample_txt = """NATIONAL CYBERSECURITY STRATEGY IMPLEMENTATION PLAN
Author: Executive Office of the President
Date: 2024-02-01

I. DEFEND CRITICAL INFRASTRUCTURE
Federal agencies must collaborate with private sector operators to defend cloud systems.

II. DISRUPT AND DISMANTLE THREAT ACTORS
Impose real costs on malicious cyber syndicates through coordinated international operations.

III. SHAPE MARKET FORCES TO DRIVE SECURITY
Encourage software bill of materials (SBOM) adoption across enterprise software vendors.
"""
        extractor = TextExtractor()
        meta, full_text, sections = extractor.extract(sample_txt)

        self.assertEqual(meta.title, "NATIONAL CYBERSECURITY STRATEGY IMPLEMENTATION PLAN")
        self.assertIn("Executive Office of the President", meta.authors)
        self.assertEqual(meta.document_type, DocumentType.TXT)
        self.assertTrue(any("CRITICAL INFRASTRUCTURE" in h for h in meta.section_headings))
        self.assertGreaterEqual(len(sections), 3)

    def test_office_docx_extractor(self):
        """Confirm OfficeExtractor extracts metadata and heading styles from DOCX zip package."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            core_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/">
    <dc:title>Ransomware Incident Response Playbook</dc:title>
    <dc:creator>Mandiant Consulting</dc:creator>
    <dcterms:created>2024-03-01T10:00:00Z</dcterms:created>
    <dc:description>Standard operating procedures for ransomware containment.</dc:description>
</cp:coreProperties>"""
            z.writestr("docProps/core.xml", core_xml)

            doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:pPr><w:pStyle w:val="Heading1"/></w:pPr>
            <w:r><w:t>Phase 1: Triage and Isolation</w:t></w:r>
        </w:p>
        <w:p>
            <w:r><w:t>Disconnect affected hosts from VLAN immediately.</w:t></w:r>
        </w:p>
        <w:p>
            <w:pPr><w:pStyle w:val="Heading2"/></w:pPr>
            <w:r><w:t>Phase 2: Evidence Preservation</w:t></w:r>
        </w:p>
        <w:p>
            <w:r><w:t>Capture volatile RAM before powering down systems.</w:t></w:r>
        </w:p>
    </w:body>
</w:document>"""
            z.writestr("word/document.xml", doc_xml)

        docx_bytes = buf.getvalue()
        extractor = OfficeExtractor()
        meta, full_text, sections = extractor.extract_docx(docx_bytes, filename="playbook.docx")

        self.assertEqual(meta.title, "Ransomware Incident Response Playbook")
        self.assertIn("Mandiant Consulting", meta.authors)
        self.assertEqual(meta.document_type, DocumentType.DOCX)
        self.assertIn("Phase 1: Triage and Isolation", meta.section_headings)
        self.assertIn("Phase 2: Evidence Preservation", meta.section_headings)
        self.assertGreaterEqual(len(sections), 2)

    def test_office_pptx_extractor(self):
        """Confirm OfficeExtractor extracts slides and presentation metadata from PPTX zip package."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            core_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Zero Trust Architecture Briefing</dc:title>
    <dc:creator>Cyber Defense Group</dc:creator>
</cp:coreProperties>"""
            z.writestr("docProps/core.xml", core_xml)

            slide1_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
       xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
    <p:cSld>
        <p:spTree>
            <p:sp><p:txBody><a:p><a:r><a:t>Slide 1: Zero Trust Core Principles</a:t></a:r></a:p></p:txBody></p:sp>
            <p:sp><p:txBody><a:p><a:r><a:t>Continuous validation and least privilege.</a:t></a:r></a:p></p:txBody></p:sp>
        </p:spTree>
    </p:cSld>
</p:sld>"""
            z.writestr("ppt/slides/slide1.xml", slide1_xml)

            slide2_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"
       xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">
    <p:cSld>
        <p:spTree>
            <p:sp><p:txBody><a:p><a:r><a:t>Slide 2: Microsegmentation Strategy</a:t></a:r></a:p></p:txBody></p:sp>
            <p:sp><p:txBody><a:p><a:r><a:t>Enforcing software-defined boundaries.</a:t></a:r></a:p></p:txBody></p:sp>
        </p:spTree>
    </p:cSld>
</p:sld>"""
            z.writestr("ppt/slides/slide2.xml", slide2_xml)

        pptx_bytes = buf.getvalue()
        extractor = OfficeExtractor()
        meta, full_text, sections = extractor.extract_pptx(pptx_bytes, filename="zt_briefing.pptx")

        self.assertEqual(meta.title, "Zero Trust Architecture Briefing")
        self.assertEqual(meta.page_count, 2)
        self.assertEqual(meta.document_type, DocumentType.PPTX)
        self.assertIn("Slide 1: Zero Trust Core Principles", meta.section_headings)
        self.assertIn("Slide 2: Microsegmentation Strategy", meta.section_headings)

    def test_pdf_extractor_native_fallback(self):
        """Confirm PdfExtractor extracts title, metadata, and sections from PDF bytes."""
        # Synthetic minimal PDF stream
        pdf_content = b"""%PDF-1.4
1 0 obj
<< /Title (Whitepaper on Memory Safety in Systems Programming)
   /Author (Security Engineering Group)
   /Count 1 >>
endobj
2 0 obj
stream
BT
(Whitepaper on Memory Safety in Systems Programming) Tj
ET
BT
(1. INTRODUCTION) Tj
ET
BT
(Buffer overflows account for over 70 percent of vulnerabilities in C and C++ codebases.) Tj
ET
BT
(2. RUST MEMORY GUARANTEES) Tj
ET
BT
(Rust ownership model eliminates use-after-free and double-free flaws at compile time.) Tj
ET
endstream
endobj
xref
trailer
<< /Root 1 0 R >>
%%EOF"""
        extractor = PdfExtractor()
        meta, full_text, sections = extractor.extract(pdf_content, filename="memory_safety.pdf")

        self.assertIn("Memory Safety", meta.title)
        self.assertEqual(meta.document_type, DocumentType.PDF)
        self.assertIn("1. INTRODUCTION", meta.section_headings)
        self.assertIn("2. RUST MEMORY GUARANTEES", meta.section_headings)
        self.assertGreaterEqual(len(sections), 2)

    def test_document_processor_pipeline_end_to_end(self):
        """
        Validate complete pipeline from IMPLEMENT.md Section 25:
        Document -> Metadata -> Text -> Chunks -> Entities -> Tags -> Embeddings
        """
        sample_doc = """# In-Depth Analysis of Operation Cronos & LockBit 3.0 Ransomware
Author: UK National Crime Agency & CISA
Date: 2024-02-20

## 1. Executive Summary
In February 2024, law enforcement operation compromised LockBit 3.0 infrastructure.
Targeting affiliate malware campaigns exploiting CVE-2023-4966 (Citrix Bleed).

## 2. Cryptographic Architecture
LockBit 3.0 utilizes ChaCha20 symmetric stream cipher and Curve25519 public key wrapping.
Victim files are encrypted using multi-threaded worker pools.

## 3. Threat Actor Infrastructure
Affiliates used Cobalt Strike beacons and PsExec for lateral movement across Windows networks.
Command and control servers resolved via 192.0.2.1 and tor onion services.
"""
        result: DocumentResult = document_processor.process_document(
            content=sample_doc,
            filename_or_url="operation_cronos.md",
            compute_embeddings=True,
        )

        # 1. Metadata
        self.assertIn("Operation Cronos", result.metadata.title)
        self.assertIn("UK National Crime Agency", result.metadata.authors[0])
        self.assertGreater(result.metadata.word_count, 30)

        # 2. Section Chunks preserving headings
        self.assertGreaterEqual(len(result.chunks), 3)
        lead_headings = [c.heading for c in result.chunks]
        self.assertTrue(any("Executive Summary" in h for h in lead_headings))
        self.assertTrue(any("Cryptographic Architecture" in h for h in lead_headings))
        # Ensure chunk text carries section context
        self.assertTrue(any("[1. Executive Summary]" in c.text or "Executive Summary" in c.text for c in result.chunks))

        # 3. Deterministic Entities
        entity_names = [e["name"] for e in result.extracted_entities]
        self.assertTrue(any("CVE-2023-4966" in n for n in entity_names))
        self.assertTrue(any("LockBit" in n for n in entity_names))

        # 4. Taxonomy classification & tags
        self.assertIsNotNone(result.primary_category)
        self.assertIn("document", result.taxonomy_tags)

        # 5. Dense vector embeddings (384 dimensions)
        for chunk in result.chunks:
            self.assertIsNotNone(chunk.embedding)
            self.assertEqual(len(chunk.embedding), 384)

    def test_copyright_retention_policy_enforcement(self):
        """
        Confirm that restricted copyright notice forces METADATA_ONLY retention mode,
        conforming to Section 25: "Do not automatically retain copyrighted documents...
        Where appropriate, retain metadata and source references instead."
        """
        copyrighted_doc = """# Proprietary Commercial Threat Intelligence Report
Author: Private Intelligence Vendor
Date: 2024-03-01

## Executive Summary
This report contains strictly proprietary intelligence on nation-state actors.

## Technical Analysis
Confidential reverse engineering details of zero-day exploits.

Copyright 2024 Vendor Corp. All rights reserved. Proprietary and confidential.
"""
        result = document_processor.process_document(
            content=copyrighted_doc,
            filename_or_url="proprietary_report.md",
            retention_mode=RetentionMode.FULL_TEXT,
        )

        # Confirm policy enforced METADATA_ONLY due to proprietary copyright notice
        self.assertEqual(result.metadata.retention_mode, RetentionMode.METADATA_ONLY)
        result_dict = result.to_dict()
        self.assertIsNone(result_dict["retained_text"])
        # Metadata and abstract remain accessible
        self.assertEqual(result.metadata.title, "Proprietary Commercial Threat Intelligence Report")

    def test_document_connector_normalization_and_registry(self):
        """Confirm DocumentConnector subclasses BaseConnector, is registered, and normalizes properly."""
        self.assertTrue(connector_registry.has("document"))
        self.assertTrue(connector_registry.has("pdf"))
        self.assertTrue(connector_registry.has("whitepaper"))

        sample_doc = """# CISA Advisory: Fortinet FortiOS Out-of-Bounds Write
Author: CISA Alert Team
Date: 2024-02-10

## Vulnerability Overview
CVE-2024-21762 allows unauthenticated remote attackers to execute arbitrary code via HTTP requests.

## Affected Products
FortiOS 7.4, FortiOS 7.2, FortiOS 7.0.
"""
        connector = DocumentConnector({
            "name": "CISA Research Feeds",
            "document_content": sample_doc,
            "filename": "fortinet_advisory.md",
            "url": "https://cisa.gov/advisories/fortinet-cve-2024-21762",
        })
        self.assertIsInstance(connector, BaseConnector)

        discovered = connector.discover()
        self.assertEqual(len(discovered), 1)

        fetched = connector.fetch(discovered[0])
        parsed = connector.parse(fetched)
        normalized: NormalizedItem = connector.normalize(parsed)

        self.assertIn("Fortinet FortiOS", normalized.title)
        self.assertEqual(normalized.content_type, "document")
        self.assertIn("document_metadata", normalized.metadata)
        self.assertEqual(normalized.metadata["document_metadata"]["document_type"], "markdown")
        self.assertGreaterEqual(len(normalized.metadata["document_metadata"]["section_headings"]), 2)

        health = connector.health_check()
        self.assertEqual(health.status, "ok")

    def test_api_process_document_endpoint(self):
        """Verify POST /api/v1/documents/process returns structured intelligence."""
        client = self.client
        doc_payload = {
            "content": "# CISA Alert: Akira Ransomware Tactics\n\n## Overview\nAkira ransomware targeting Cisco ASA devices.\n\n## IOCs\nC2: 198.51.100.99",
            "filename": "akira_alert.md",
            "doc_type": "markdown",
            "save_to_db": False,
        }
        resp = client.post("/api/v1/documents/process", json=doc_payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()

        self.assertIn("Akira Ransomware", data["metadata"]["title"])
        self.assertEqual(data["metadata"]["document_type"], "markdown")
        self.assertGreaterEqual(data["chunks_count"], 2)
        self.assertTrue(any("Overview" in c["heading"] for c in data["chunks"]))
        self.assertTrue(all(c["has_embedding"] for c in data["chunks"]))

    def test_api_process_and_save_to_db(self):
        """Verify POST /api/v1/documents/process with save_to_db persists and allows chunk lookup."""
        client = self.client
        doc_payload = {
            "content": "# NIST SP 800-53 Rev 5 Security Controls\nAuthor: NIST\n\n## Access Control\nAC-1 policy and procedures.\n\n## Audit and Accountability\nAU-1 logging standards.",
            "filename": "sp800-53.md",
            "doc_type": "markdown",
            "save_to_db": True,
        }
        resp = client.post("/api/v1/documents/process", json=doc_payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        content_id = data.get("content_id")
        self.assertIsNotNone(content_id)

        # Confirm listing
        list_resp = client.get("/api/v1/documents")
        self.assertEqual(list_resp.status_code, 200)
        docs = list_resp.json()
        self.assertTrue(any(d["id"] == content_id for d in docs))

        # Confirm chunks endpoint
        chunks_resp = client.get(f"/api/v1/documents/{content_id}/chunks")
        self.assertEqual(chunks_resp.status_code, 200)
        chunks = chunks_resp.json()
        self.assertGreaterEqual(len(chunks), 2)


if __name__ == "__main__":
    unittest.main()
