"""
Video Intelligence Data Models
Defines structured objects for audiovisual OSINT metadata, timestamped chapters,
and speech-to-text transcript chunks.
Conforms strictly to IMPLEMENT.md Section 24 specifications.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def parse_timestamp_seconds(timestamp_str: str) -> int:
    """
    Parse timestamp string formatted as HH:MM:SS or MM:SS into total seconds.
    Examples:
        '00:14:32' -> 872
        '00:28:51' -> 1731
        '14:32'    -> 872
    """
    parts = timestamp_str.strip().split(":")
    try:
        if len(parts) == 3:
            h, m, s = int(parts[0]), int(parts[1]), int(parts[2])
            return h * 3600 + m * 60 + s
        elif len(parts) == 2:
            m, s = int(parts[0]), int(parts[1])
            return m * 60 + s
        return 0
    except ValueError:
        return 0


def format_seconds_to_timestamp(total_seconds: int) -> str:
    """Format total integer seconds into canonical HH:MM:SS format."""
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


@dataclass
class TranscriptTimestamp:
    """Timestamp chapter / segment with topic and extracted context."""

    timestamp_str: str
    topic: str
    seconds: int = 0
    text: str = ""
    entities: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.seconds and self.timestamp_str:
            self.seconds = parse_timestamp_seconds(self.timestamp_str)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_str": self.timestamp_str,
            "seconds": self.seconds,
            "topic": self.topic,
            "text": self.text,
            "entities": self.entities,
        }


@dataclass
class VideoItem:
    """
    Normalized Video Intelligence Object.
    Contains all 7 mandated metadata fields from IMPLEMENT.md Section 24:
    title, channel, description, URL, duration, published_at, language,
    plus timestamped chapters and optional full transcript.
    """

    title: str
    channel: str
    description: str
    url: str
    duration: int  # in seconds
    published_at: Optional[str] = None
    language: str = "en"
    timestamps: List[TranscriptTimestamp] = field(default_factory=list)
    transcript: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "channel": self.channel,
            "description": self.description,
            "url": self.url,
            "duration": self.duration,
            "published_at": self.published_at,
            "language": self.language,
            "timestamps": [t.to_dict() for t in self.timestamps],
            "transcript": self.transcript,
            "tags": self.tags,
        }
