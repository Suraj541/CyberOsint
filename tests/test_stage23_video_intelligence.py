"""
Stage 23: Video Intelligence Baseline Tests
Validates Section 24 / Step 23 implementation:
- Package connectors/video/ with models, transcript processor, and connector
- Mandated fields: title, channel, description, URL, duration, published_at, language
- Video -> Transcript -> Chunks -> Topics -> Entities -> Search pipeline
- Timestamp extraction: 00:14:32 -> Kerberos delegation, 00:28:51 -> Active Directory attack paths
- Integration with IngestionPipeline, taxonomy classification, and semantic search
Conforms strictly to IMPLEMENT.md Section 24.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

repo_root = Path(__file__).resolve().parent.parent
api_root = repo_root / "apps" / "api"
for p in (repo_root, api_root):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from app.models.base import Base
from app.models.chunk import ContentChunk
from app.models.content import Content
from connectors.base import BaseConnector, NormalizedItem
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError
from connectors.video import (
    TranscriptProcessor,
    TranscriptTimestamp,
    VideoConnector,
    VideoItem,
    format_seconds_to_timestamp,
    parse_timestamp_seconds,
    transcript_processor,
)
from services.ingestion.pipeline import IngestionPipeline


class TestStage23VideoIntelligence(unittest.TestCase):
    """Test suite validating Section 24 / Step 23 Video Intelligence implementation."""

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

    def tearDown(self):
        """Clean up in-memory database."""
        self.db.close()
        Base.metadata.drop_all(bind=self.engine)

    def test_video_package_structure(self):
        """Confirm connectors/video contains all mandated modules."""
        video_dir = repo_root / "connectors" / "video"
        self.assertTrue(video_dir.exists(), "connectors/video/ directory missing")
        self.assertTrue((video_dir / "__init__.py").exists(), "connectors/video/__init__.py missing")
        self.assertTrue((video_dir / "connector.py").exists(), "connectors/video/connector.py missing")
        self.assertTrue((video_dir / "models.py").exists(), "connectors/video/models.py missing")
        self.assertTrue((video_dir / "transcript.py").exists(), "connectors/video/transcript.py missing")

    def test_video_connector_registered_and_subclasses_base(self):
        """Confirm VideoConnector subclasses BaseConnector and is registered under standard keys."""
        self.assertTrue(issubclass(VideoConnector, BaseConnector))
        for key in ("video", "youtube", "conference_video", "webinar"):
            self.assertTrue(connector_registry.has(key), f"Key '{key}' not in connector_registry")
            cls = connector_registry.get(key)
            self.assertIs(cls, VideoConnector)

    def test_timestamp_parsing_and_formatting(self):
        """Confirm timestamp string <-> seconds conversions."""
        self.assertEqual(parse_timestamp_seconds("00:14:32"), 872)
        self.assertEqual(parse_timestamp_seconds("00:28:51"), 1731)
        self.assertEqual(parse_timestamp_seconds("14:32"), 872)
        self.assertEqual(format_seconds_to_timestamp(872), "00:14:32")
        self.assertEqual(format_seconds_to_timestamp(1731), "00:28:51")

    def test_timestamp_extraction_from_show_notes(self):
        """
        Confirm extract_timestamps accurately extracts mandated examples from Section 24:
        00:14:32 -> Kerberos delegation
        00:28:51 -> Active Directory attack paths
        """
        description_text = """
        DEF CON 32 Keynote: Active Directory Compromise and Kerberos Telecommand
        In this deep-dive talk we cover:
        00:02:10 - Overview of Ground Segment Architectures
        00:14:32 → Kerberos delegation
        00:28:51 → Active Directory attack paths
        00:45:10 - Mitigation Strategies and Remediation
        """
        timestamps = transcript_processor.extract_timestamps(description_text)
        self.assertGreaterEqual(len(timestamps), 4)

        # Check Kerberos delegation timestamp
        ts_kerberos = next((t for t in timestamps if t.timestamp_str == "00:14:32"), None)
        self.assertIsNotNone(ts_kerberos)
        self.assertIn("Kerberos delegation", ts_kerberos.topic)
        self.assertEqual(ts_kerberos.seconds, 872)

        # Check Active Directory attack paths timestamp
        ts_ad = next((t for t in timestamps if t.timestamp_str == "00:28:51"), None)
        self.assertIsNotNone(ts_ad)
        self.assertIn("Active Directory attack paths", ts_ad.topic)
        self.assertEqual(ts_ad.seconds, 1731)

    def test_transcript_processing_video_to_chunks_to_topics_to_entities(self):
        """
        Validate the complete pipeline from IMPLEMENT.md Section 24:
        Video -> Transcript -> Chunks -> Topics -> Entities -> Search.
        """
        transcript_text = """
        00:14:32 → Kerberos delegation
        In this segment we demonstrate unconstrained Kerberos delegation exploitation using ticket granting tickets.
        00:28:51 → Active Directory attack paths
        Here we inspect Active Directory domain escalation paths using Mimikatz to dump NTDS.dit.
        """
        timestamps = transcript_processor.process_transcript(transcript_text)
        self.assertGreaterEqual(len(timestamps), 2)

        # Confirm entities are extracted in each segment
        ts_kerberos = timestamps[0]
        self.assertIn("Kerberos", ts_kerberos.entities)

        ts_ad = timestamps[1]
        self.assertTrue(
            any("Active Directory" in e or "Mimikatz" in e for e in ts_ad.entities),
            f"Expected Active Directory or Mimikatz in entities: {ts_ad.entities}",
        )

        # Confirm search chunks generation
        video_item = VideoItem(
            title="AD Exploitation Talk",
            channel="Black Hat",
            description="Presentation on enterprise attacks",
            url="https://youtube.com/watch?v=sample-ad-talk",
            duration=3600,
            timestamps=timestamps,
        )
        search_chunks = transcript_processor.generate_searchable_chunks(video_item)
        self.assertGreaterEqual(len(search_chunks), 2)
        self.assertIn("[00:14:32]", search_chunks[0]["content"])
        self.assertIn("Kerberos delegation", search_chunks[0]["content"])
        self.assertIn("[00:28:51]", search_chunks[1]["content"])
        self.assertIn("Active Directory attack paths", search_chunks[1]["content"])

    def test_video_connector_normalization_mandated_fields(self):
        """
        Confirm VideoConnector.normalize produces NormalizedItem containing
        all 7 mandated fields from Section 24:
        title, channel, description, URL, duration, published_at, language.
        """
        raw_video = {
            "title": "Black Hat USA: Bypassing EDR with Process Injection",
            "channel": "Black Hat Conference",
            "description": "00:05:10 - Process Injection Concepts\n00:14:32 → Kerberos delegation\n00:28:51 → Active Directory attack paths",
            "url": "https://youtube.com/watch?v=sample-bh-talk",
            "duration": 2700,
            "published_at": "2024-08-10T14:00:00Z",
            "language": "en",
        }
        connector = VideoConnector(source_config={"name": "Black Hat YouTube"})
        parsed = connector.parse(raw_video)
        normalized = connector.normalize(parsed)

        self.assertIsInstance(normalized, NormalizedItem)
        self.assertEqual(normalized.content_type, "video")
        self.assertEqual(normalized.title, "Black Hat USA: Bypassing EDR with Process Injection")
        self.assertEqual(normalized.url, "https://youtube.com/watch?v=sample-bh-talk")
        self.assertEqual(normalized.author, "Black Hat Conference")
        self.assertEqual(normalized.metadata["channel"], "Black Hat Conference")
        self.assertEqual(normalized.metadata["duration"], 2700)
        self.assertEqual(normalized.metadata["duration_formatted"], "00:45:00")
        self.assertEqual(normalized.metadata["language"], "en")
        self.assertGreaterEqual(len(normalized.metadata["timestamps"]), 2)

    def test_ingestion_pipeline_with_video_connector(self):
        """
        Confirm IngestionPipeline ingests video records, links entities,
        and automatically creates searchable ContentChunk records.
        """
        video_payload = [
            {
                "title": "DEF CON 32: Breaking Satellite Communications",
                "channel": "DEF CON Conference",
                "description": "00:14:32 → Kerberos delegation\n00:28:51 → Active Directory attack paths",
                "url": "https://youtube.com/watch?v=sample-defcon-32",
                "duration": 3120,
                "published_at": "2024-08-11T12:00:00Z",
                "language": "en",
            }
        ]
        connector = VideoConnector(
            source_config={
                "name": "DEF CON Channel",
                "feed_content": json.dumps(video_payload),
            }
        )
        pipeline = IngestionPipeline()
        metrics = pipeline.run(self.db, connector, source_name="DEF CON Channel")

        self.assertEqual(metrics.ingested_count, 1)
        self.assertEqual(metrics.errors_count, 0)

        # Verify Content row
        content = self.db.query(Content).filter(Content.content_type == "video").first()
        self.assertIsNotNone(content)
        self.assertEqual(content.author, "DEF CON Conference")

        # Verify semantic ContentChunks created
        chunks = self.db.query(ContentChunk).filter(ContentChunk.content_id == content.id).all()
        self.assertGreaterEqual(len(chunks), 1)

        # Check that timestamp markers exist in chunks
        all_chunk_text = " ".join([c.chunk_text for c in chunks])
        self.assertIn("00:14:32", all_chunk_text)
        self.assertIn("Kerberos delegation", all_chunk_text)

    def test_ssrf_protection_on_video_connector(self):
        """Confirm VideoConnector rejects loopback or private network URLs."""
        connector = VideoConnector(source_config={"url": "http://127.0.0.1:8000/internal_videos.json"})
        with self.assertRaises(SSRFSecurityError):
            connector.discover()


if __name__ == "__main__":
    unittest.main()
