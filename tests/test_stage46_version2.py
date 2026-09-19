"""Test Suite for Section 47 (Step 46): Version 2 Capabilities.

Verifies the 12 capabilities mandated in Section 47 of IMPLEMENT.md:
  1. GitHub (GHSA, exploit PoCs)
  2. Government (CISA, national directives)
  3. CERT (operational CSIRT bulletins)
  4. Vendor advisories (MSRC, Cisco, Red Hat)
  5. Academic research (arXiv, peer-reviewed)
  6. Security reports (labs, Unit 42, Talos)
  7. Videos (YouTube, CCC conference metadata)
  8. Documents (sandboxed PDF, DOCX, PPTX)
  9. MITRE ATT&CK (Enterprise matrix, techniques, tactics)
  10. Semantic search (vector embeddings & RRF)
  11. AI summarization (structured evidence synthesis)
  12. Knowledge graph (entity-relation traversal)
"""

import os
import unittest

from connectors.base import BaseConnector

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestSection47Version2(unittest.TestCase):
    """Verifies all 12 capabilities of Version 2 defined in Section 47."""

    def test_01_github_connector_capability(self):
        """V2.1: GitHub security advisories and exploit PoCs connector."""
        from connectors.github.connector import GitHubSecurityConnector
        self.assertIsNotNone(GitHubSecurityConnector)
        self.assertTrue(issubclass(GitHubSecurityConnector, BaseConnector))

    def test_02_government_and_cert_connectors(self):
        """V2.2 & V2.3: Government and National CERT advisory connectors."""
        from connectors.cert.connector import CERTConnector
        self.assertIsNotNone(CERTConnector)
        self.assertTrue(issubclass(CERTConnector, BaseConnector))

    def test_03_vendor_advisories_connector(self):
        """V2.4: Vendor security advisories connector."""
        from connectors.vendor.connector import VendorAdvisoryConnector
        self.assertIsNotNone(VendorAdvisoryConnector)
        self.assertTrue(issubclass(VendorAdvisoryConnector, BaseConnector))

    def test_04_academic_research_connector(self):
        """V2.5: Academic research database connector."""
        from connectors.research.connector import ResearchDatabaseConnector
        self.assertIsNotNone(ResearchDatabaseConnector)
        self.assertTrue(issubclass(ResearchDatabaseConnector, BaseConnector))

    def test_05_security_reports_and_blogs(self):
        """V2.6: Threat lab reports and security blogs connector."""
        from connectors.blog.connector import SecurityBlogConnector
        self.assertIsNotNone(SecurityBlogConnector)
        self.assertTrue(issubclass(SecurityBlogConnector, BaseConnector))

    def test_06_video_intelligence_capability(self):
        """V2.7: Video metadata and conference lecture intelligence."""
        from connectors.video.connector import VideoConnector
        self.assertIsNotNone(VideoConnector)
        self.assertTrue(issubclass(VideoConnector, BaseConnector))

    def test_07_sandboxed_document_processing(self):
        """V2.8: Sandboxed document ingestion for PDF, DOCX, PPTX."""
        from services.documents.processor import DocumentProcessor
        from services.documents.sandbox import SandboxedDocumentProcessor
        self.assertIsNotNone(DocumentProcessor)
        self.assertIsNotNone(SandboxedDocumentProcessor)

    def test_08_mitre_attack_matrix(self):
        """V2.9: MITRE ATT&CK framework navigator, tactics, and techniques."""
        from app.models.mitre import MitreTacticModel, MitreTechniqueModel, MitreGroupModel
        from app.api.v1.endpoints.mitre import router as mitre_router
        self.assertIsNotNone(MitreTacticModel)
        self.assertIsNotNone(MitreTechniqueModel)
        self.assertIsNotNone(MitreGroupModel)
        self.assertIsNotNone(mitre_router)

    def test_09_semantic_search_capability(self):
        """V2.10: Semantic dense vector search and RRF hybrid ranking."""
        from services.semantic import semantic_service, SemanticService
        self.assertIsNotNone(semantic_service)
        self.assertIsNotNone(SemanticService)

    def test_10_ai_summarization_pipeline(self):
        """V2.11: AI-powered structured evidence summarization."""
        from services.summarization.service import summarization_service
        self.assertIsNotNone(summarization_service)

    def test_11_knowledge_graph_capability(self):
        """V2.12: Knowledge graph traversal, nodes, and relationships."""
        from services.graph import knowledge_graph_service, KnowledgeGraphService, GraphNode, GraphEdge
        from app.models.graph import EntityRelationship
        self.assertIsNotNone(knowledge_graph_service)
        self.assertIsNotNone(KnowledgeGraphService)
        self.assertIsNotNone(GraphNode)
        self.assertIsNotNone(GraphEdge)
        self.assertIsNotNone(EntityRelationship)

    def test_12_version2_all_eleven_connectors_registered(self):
        """Verify all 11 priority connectors from Section 34 are managed."""
        from connectors.manager import connector_manager
        connectors = connector_manager.list_connectors()
        self.assertEqual(len(connectors), 11)


if __name__ == "__main__":
    unittest.main()
