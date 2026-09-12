"""
Video Intelligence Connector Package
Provides video metadata collection, timestamp extraction, and transcript intelligence.
Conforms strictly to IMPLEMENT.md Section 24 specifications.
"""

from connectors.video.connector import VideoConnector
from connectors.video.models import (
    TranscriptTimestamp,
    VideoItem,
    format_seconds_to_timestamp,
    parse_timestamp_seconds,
)
from connectors.video.transcript import TranscriptProcessor, transcript_processor

__all__ = [
    "VideoConnector",
    "VideoItem",
    "TranscriptTimestamp",
    "TranscriptProcessor",
    "transcript_processor",
    "format_seconds_to_timestamp",
    "parse_timestamp_seconds",
]
