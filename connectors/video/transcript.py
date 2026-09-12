"""
Video Transcript and Timestamp Intelligence Processor
Implements the Video Intelligence pipeline specified in IMPLEMENT.md Section 24:
Video -> Transcript -> Chunks -> Topics -> Entities -> Search.
Parses, normalizes, and enriches timestamped chapters (e.g. 00:14:32 -> Kerberos delegation).
"""

import re
from typing import Any, Dict, List, Optional

from connectors.video.models import (
    TranscriptTimestamp,
    VideoItem,
    format_seconds_to_timestamp,
    parse_timestamp_seconds,
)
from packages.classifier import rule_classifier
from packages.extractor import entity_extractor


# Regex pattern to match timestamp lines:
# Supports:
# 00:14:32 → Kerberos delegation
# 00:28:51 - Active Directory attack paths
# 14:32 Kerberos delegation
# [00:14:32] Kerberos delegation
RE_TIMESTAMP_LINE = re.compile(
    r"(?:^|\n)\s*\[?(\d{1,2}:\d{2}(?::\d{2})?)\]?\s*(?:[-–—→:>|]|\s)\s*([^\n\r]+)",
    re.MULTILINE,
)


class TranscriptProcessor:
    """
    Parses and chunks video transcripts and description chapters,
    correlating timestamps with topics and extracted entities.
    """

    def extract_timestamps(self, text: str) -> List[TranscriptTimestamp]:
        """
        Extract timestamp markers from descriptions, chapter tracks, or show notes.
        Example:
            '00:14:32 → Kerberos delegation'
            '00:28:51 → Active Directory attack paths'
        """
        if not text:
            return []

        results: List[TranscriptTimestamp] = []
        seen_seconds = set()

        for match in RE_TIMESTAMP_LINE.finditer(text):
            time_str = match.group(1).strip()
            topic_str = match.group(2).strip()

            # Normalize timestamp string to HH:MM:SS
            seconds = parse_timestamp_seconds(time_str)
            canonical_time = format_seconds_to_timestamp(seconds)

            # Clean topic title
            clean_topic = re.sub(r"^[-–—→:>|]\s*", "", topic_str).strip()
            if not clean_topic or len(clean_topic) < 2:
                continue

            if seconds not in seen_seconds:
                seen_seconds.add(seconds)
                results.append(
                    TranscriptTimestamp(
                        timestamp_str=canonical_time,
                        seconds=seconds,
                        topic=clean_topic,
                        text=clean_topic,
                    )
                )

        # Sort chronologically by second offset
        results.sort(key=lambda t: t.seconds)
        return results

    def process_transcript(
        self,
        text: str,
        existing_timestamps: Optional[List[TranscriptTimestamp]] = None,
    ) -> List[TranscriptTimestamp]:
        """
        Processes text and extracts/enriches timestamped chunks with topics and entities:
        Transcript -> Chunks -> Topics -> Entities.
        """
        timestamps = list(existing_timestamps or [])

        # If no pre-existing timestamps, scan the text
        if not timestamps:
            timestamps = self.extract_timestamps(text)

        # If still no timestamps, partition the text into synthetic interval chunks
        if not timestamps and text:
            words = text.split()
            chunk_size = 120  # ~1 minute of speech
            for i in range(0, len(words), chunk_size):
                approx_seconds = (i // chunk_size) * 60
                time_str = format_seconds_to_timestamp(approx_seconds)
                chunk_text = " ".join(words[i : i + chunk_size])
                # Generate lead topic snippet
                lead_topic = " ".join(words[i : min(i + 8, len(words))])
                timestamps.append(
                    TranscriptTimestamp(
                        timestamp_str=time_str,
                        seconds=approx_seconds,
                        topic=lead_topic,
                        text=chunk_text,
                    )
                )

        # Enrich each timestamp chunk with Topics and Entities
        enriched: List[TranscriptTimestamp] = []
        for ts in timestamps:
            content_to_analyze = f"{ts.topic}\n{ts.text}"

            # 1. Extract Entities (CVE, malware, threat actor, product, technique)
            extracted = entity_extractor.extract(content_to_analyze)
            entity_names = [e.name for e in extracted]

            # 2. Extract / Classify Topics
            classification = rule_classifier.classify(ts.topic, ts.text)
            topic_label = ts.topic
            if classification and classification.category != "general_security":
                cat_display = classification.category.replace("_", " ").title()
                if cat_display.lower() not in topic_label.lower():
                    topic_label = f"{ts.topic} ({cat_display})"

            enriched.append(
                TranscriptTimestamp(
                    timestamp_str=ts.timestamp_str,
                    seconds=ts.seconds,
                    topic=topic_label,
                    text=ts.text,
                    entities=entity_names,
                )
            )

        return enriched

    def generate_searchable_chunks(self, video: VideoItem) -> List[Dict[str, Any]]:
        """
        Converts a VideoItem and its timestamps into indexable semantic search chunks.
        Each chunk is formatted with a timestamp header so search results pinpoint the exact video moment:
        e.g. '[00:14:32] Kerberos delegation: ...'
        """
        chunks: List[Dict[str, Any]] = []

        if video.timestamps:
            for ts in video.timestamps:
                chunk_text = f"[{ts.timestamp_str}] {ts.topic}"
                if ts.text and ts.text != ts.topic:
                    chunk_text += f"\n{ts.text}"

                chunks.append({
                    "timestamp": ts.timestamp_str,
                    "seconds": ts.seconds,
                    "topic": ts.topic,
                    "content": chunk_text,
                    "entities": ts.entities,
                })
        else:
            chunks.append({
                "timestamp": "00:00:00",
                "seconds": 0,
                "topic": video.title,
                "content": f"{video.title}\n{video.description}",
                "entities": [],
            })

        return chunks


transcript_processor = TranscriptProcessor()
