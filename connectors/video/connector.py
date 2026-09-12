"""
Video Intelligence Connector
Collects, parses, and normalizes video metadata and transcripts from cybersecurity conferences
(DEF CON, Black Hat, CCC, RSA), lectures, and vulnerability walkthroughs.
Conforms strictly to IMPLEMENT.md Section 24 specifications.
"""

from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
import httpx
import xml.etree.ElementTree as ET

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError, validate_url_for_ssrf
from connectors.video.models import (
    TranscriptTimestamp,
    VideoItem,
    format_seconds_to_timestamp,
    parse_timestamp_seconds,
)
from connectors.video.transcript import transcript_processor
from packages.classifier import rule_classifier
from packages.extractor import entity_extractor

logger = logging.getLogger("cyber_osint.connectors.video")


@connector_registry.register("video")
@connector_registry.register("youtube")
@connector_registry.register("conference_video")
@connector_registry.register("webinar")
class VideoConnector(BaseConnector):
    """
    Ingestion connector for Cybersecurity Video Intelligence.
    Collects title, channel, description, URL, duration, published_at, language,
    and enriches timestamped chapters (e.g. 00:14:32 -> Kerberos delegation).
    """

    DEFAULT_USER_AGENT = "CyberOSINT-Video-Bot/1.0 (+https://cyber-osint.local/bot)"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.raw_feed_content: Optional[str] = self.config.get("feed_content")

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json, application/xml, text/xml, */*",
        }

    def discover(self) -> List[Dict[str, Any]]:
        """
        Discover video entries from source configuration or public video metadata interfaces.
        Enforces SSRF preflight protection on all remote network fetches.
        """
        if self.raw_feed_content:
            text = self.raw_feed_content.strip()
            # Try JSON first
            if text.startswith("{") or text.startswith("["):
                try:
                    data = json.loads(text)
                    entries = data if isinstance(data, list) else data.get("videos", data.get("items", [data]))
                    if self.max_entries:
                        entries = entries[: self.max_entries]
                    return entries
                except Exception as exc:
                    logger.debug("Failed to parse in-memory feed as JSON: %s", exc)

            # Try XML / Atom / RSS (e.g. YouTube XML feeds)
            if "<feed" in text or "<rss" in text or "<channel" in text:
                return self._parse_xml_entries(text)

        if not self.source_url:
            return []

        # Validate URL for SSRF
        is_safe, error_msg = validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)
        if not is_safe:
            raise SSRFSecurityError(f"SSRF protection blocked discovery URL '{self.source_url}': {error_msg}")

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(self.source_url, headers=self._get_headers())
                resp.raise_for_status()
                text = resp.text

                # Parse JSON API or XML Feed
                if "application/json" in resp.headers.get("content-type", "") or text.strip().startswith(("{", "[")):
                    data = resp.json()
                    entries = data if isinstance(data, list) else data.get("videos", data.get("items", [data]))
                else:
                    entries = self._parse_xml_entries(text)

                if self.max_entries:
                    entries = entries[: self.max_entries]
                return entries
        except Exception as exc:
            logger.error("VideoConnector discovery error for '%s': %s", self.source_name, exc)
            return []

    def _parse_xml_entries(self, xml_text: str) -> List[Dict[str, Any]]:
        """Parses standard YouTube/Atom/RSS video feeds."""
        entries: List[Dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_text)
            # Handle Atom feeds (YouTube format)
            ns = {
                "atom": "http://www.w3.org/2005/Atom",
                "media": "http://search.yahoo.com/mrss/",
                "yt": "http://www.youtube.com/xml/schemas/2015",
            }

            for entry in root.findall(".//atom:entry", ns):
                title = entry.findtext("atom:title", namespaces=ns) or ""
                link_elem = entry.find("atom:link[@rel='alternate']", namespaces=ns)
                url = link_elem.attrib.get("href", "") if link_elem is not None else ""
                author = entry.findtext("atom:author/atom:name", namespaces=ns) or ""
                published = entry.findtext("atom:published", namespaces=ns) or ""

                media_group = entry.find("media:group", namespaces=ns)
                description = ""
                if media_group is not None:
                    desc_elem = media_group.find("media:description", namespaces=ns)
                    if desc_elem is not None and desc_elem.text:
                        description = desc_elem.text

                entries.append({
                    "title": title,
                    "url": url,
                    "channel": author,
                    "description": description,
                    "published_at": published,
                    "duration": 0,
                    "language": "en",
                })

            if not entries:
                # Handle standard RSS 2.0 items
                for item in root.findall(".//item"):
                    entries.append({
                        "title": item.findtext("title") or "",
                        "url": item.findtext("link") or "",
                        "channel": item.findtext("author") or self.source_name or "Unknown Channel",
                        "description": item.findtext("description") or "",
                        "published_at": item.findtext("pubDate") or "",
                        "duration": 0,
                        "language": "en",
                    })
        except Exception as exc:
            logger.warning("Error parsing XML video feed: %s", exc)

        return entries

    def fetch(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Pass through discovered video entry or fetch deeper transcript metadata."""
        return entry

    def parse(self, raw_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw video metadata into normalized fields:
        title, channel, description, URL, duration, published_at, language,
        and process timestamp chapters.
        """
        title = raw_entry.get("title") or raw_entry.get("name") or "Untitled Conference Presentation"
        channel = (
            raw_entry.get("channel")
            or raw_entry.get("author")
            or raw_entry.get("channel_title")
            or self.source_name
            or "Cybersecurity Conference"
        )
        description = raw_entry.get("description") or raw_entry.get("summary") or ""
        url = raw_entry.get("url") or raw_entry.get("link") or ""

        # Duration in seconds
        raw_duration = raw_entry.get("duration", 0)
        if isinstance(raw_duration, str):
            duration = parse_timestamp_seconds(raw_duration)
        else:
            duration = int(raw_duration or 0)

        published_at = raw_entry.get("published_at") or raw_entry.get("date") or raw_entry.get("pubDate")
        language = raw_entry.get("language") or "en"
        transcript = raw_entry.get("transcript") or raw_entry.get("captions")

        # Extract timestamps from show notes, description, or explicit timestamps list
        raw_timestamps = raw_entry.get("timestamps") or []
        pre_parsed: List[TranscriptTimestamp] = []
        if isinstance(raw_timestamps, list):
            for t in raw_timestamps:
                if isinstance(t, dict) and t.get("timestamp_str") and t.get("topic"):
                    pre_parsed.append(
                        TranscriptTimestamp(
                            timestamp_str=t["timestamp_str"],
                            topic=t["topic"],
                            seconds=t.get("seconds") or parse_timestamp_seconds(t["timestamp_str"]),
                            text=t.get("text") or t["topic"],
                        )
                    )

        # Process timestamps through TranscriptProcessor (Video -> Transcript -> Chunks -> Topics -> Entities)
        combined_text = f"{description}\n{transcript or ''}"
        timestamps = transcript_processor.process_transcript(combined_text, existing_timestamps=pre_parsed)

        return {
            "title": title.strip(),
            "channel": channel.strip(),
            "description": description.strip(),
            "url": url.strip(),
            "duration": duration,
            "published_at": published_at,
            "language": language,
            "timestamps": timestamps,
            "transcript": transcript,
            "tags": raw_entry.get("tags") or ["video", "conference"],
        }

    def normalize(self, parsed: Dict[str, Any]) -> NormalizedItem:
        """
        Normalize video intelligence item conforming strictly to IMPLEMENT.md Section 8 and Section 24.
        Ensures content_type="video" and stores all 7 mandated metadata fields plus timestamps.
        """
        title = parsed["title"]
        channel = parsed["channel"]
        description = parsed["description"]
        url = parsed["url"]
        duration = parsed["duration"]
        published_at = parsed["published_at"]
        language = parsed["language"]
        timestamps = parsed["timestamps"]

        # Formulate full raw text for entity extraction and classification
        raw_text_parts = [title, description]
        for ts in timestamps:
            raw_text_parts.append(f"[{ts.timestamp_str}] {ts.topic}: {ts.text}")
        if parsed.get("transcript"):
            raw_text_parts.append(parsed["transcript"])
        full_content = "\n\n".join(raw_text_parts)

        # Classify video topic against cybersecurity taxonomy
        classified = rule_classifier.classify(title, description)
        category = classified.category if classified else "threat_intelligence"

        # Extract deterministic cybersecurity entities
        extracted_entities = entity_extractor.extract(full_content)
        structured_entities = [
            {
                "name": ent.name,
                "type": ent.entity_type,
                "confidence": ent.confidence,
                "description": ent.context_snippet,
            }
            for ent in extracted_entities
        ]

        # Assemble metadata conforming to Section 24
        metadata = {
            "channel": channel,
            "duration": duration,
            "duration_formatted": format_seconds_to_timestamp(duration) if duration > 0 else None,
            "language": language,
            "timestamps": [t.to_dict() for t in timestamps],
            "has_transcript": bool(parsed.get("transcript")),
            "entities": structured_entities,
            "tags": list(set(parsed.get("tags", []) + [category, "video"])),
        }

        return NormalizedItem(
            title=title,
            url=url,
            description=description,
            author=channel,
            published_at=published_at,
            source=channel or self.source_name,
            content_type="video",
            category=category,
            raw_content=full_content,
            metadata=metadata,
        )

    def health_check(self) -> ConnectorHealth:
        """Perform connector health assessment."""
        start_time = time.time()
        if self.raw_feed_content:
            return ConnectorHealth(
                is_healthy=True,
                status_message="In-memory video connector active",
                latency_ms=(time.time() - start_time) * 1000,
            )

        if not self.source_url:
            return ConnectorHealth(
                is_healthy=True,
                status_message="VideoConnector initialized without static source_url",
                latency_ms=0.0,
            )

        is_safe, error_msg = validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)
        if not is_safe:
            return ConnectorHealth(
                is_healthy=False,
                status_message=f"SSRF check failed: {error_msg}",
                latency_ms=(time.time() - start_time) * 1000,
            )

        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.head(self.source_url, headers=self._get_headers())
                latency = (time.time() - start_time) * 1000
                return ConnectorHealth(
                    is_healthy=resp.status_code < 400,
                    status_message=f"HTTP {resp.status_code}",
                    latency_ms=latency,
                )
        except Exception as exc:
            return ConnectorHealth(
                is_healthy=False,
                status_message=f"Health check failed: {exc}",
                latency_ms=(time.time() - start_time) * 1000,
            )
