"""
National CERT & CSIRT Security Advisory Connector
Ingests official cybersecurity alerts and operational bulletins from CISA / US-CERT,
CERT-EU, and national CSIRTs with automated CVE correlation and SSRF preflight protection.
Conforms strictly to IMPLEMENT.md Section 12 specifications.
"""

from datetime import datetime, timezone
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional
import httpx

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError, validate_url_for_ssrf

logger = logging.getLogger("cyber_osint.connectors.cert")


class CERTConnector(BaseConnector):
    """
    Ingestion connector for official National CERT / CSIRT operational alerts and bulletins.
    Parses alert identifiers, severity ratings, affected technologies, and referenced CVEs.
    """

    DEFAULT_USER_AGENT = "CyberOSINT-CERT-Bot/1.0 (+https://cyber-osint.local/bot)"
    DEFAULT_CISA_ALERTS_URL = "https://www.cisa.gov/cybersecurity-advisories/all.json"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.raw_feed_content: Optional[str] = self.config.get("feed_content")  # In-memory test JSON / list

        if not self.source_url:
            self.source_url = self.DEFAULT_CISA_ALERTS_URL

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }

    def discover(self) -> List[Dict[str, Any]]:
        """
        Discover alerts from CERT/CSIRT source.
        Enforces SSRF preflight validation before sending outgoing HTTP requests.
        """
        if self.raw_feed_content:
            data = json.loads(self.raw_feed_content) if isinstance(self.raw_feed_content, str) else self.raw_feed_content
            entries = data if isinstance(data, list) else data.get("alerts", data.get("items", [data]))
            if self.max_entries:
                entries = entries[: self.max_entries]
            return entries

        validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)

        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=3,
                headers=self._get_headers(),
            ) as client:
                resp = client.get(self.source_url)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as exc:
            logger.error("HTTP error fetching CERT alerts from '%s': %s", self.source_url, exc)
            raise RuntimeError(f"Failed to fetch CERT alerts: {exc}") from exc

        entries = payload if isinstance(payload, list) else payload.get("alerts", payload.get("items", [payload]))
        if self.max_entries:
            entries = entries[: self.max_entries]

        logger.info("Discovered %d CERT alerts from source '%s'", len(entries), self.source_name)
        return entries

    def fetch(self, item: Any) -> Dict[str, Any]:
        """Convert raw item into dictionary."""
        if isinstance(item, dict):
            return item
        return dict(item)

    def parse(self, response: Any) -> Dict[str, Any]:
        """
        Extract structured alert ID, title, affected systems, CVE references, and severity.
        """
        item = response

        # Alert identifier (e.g. AA24-123A, ICSMA-23-111-01, Alert-2024-001)
        alert_id = item.get("alert_id") or item.get("id") or item.get("identifier") or "CERT-ALERT"
        title = item.get("title") or item.get("name") or alert_id
        description = item.get("description") or item.get("summary") or item.get("body") or ""
        canonical_url = item.get("url") or item.get("link") or f"https://www.cisa.gov/news-events/cybersecurity-advisories/{alert_id}"

        # Severity
        severity = str(item.get("severity") or item.get("risk_rating") or "HIGH").upper()

        # Extract referenced CVEs from text or explicit field
        referenced_cves: List[str] = item.get("cves") or []
        if not referenced_cves:
            combined_text = f"{title} {description}"
            cve_matches = re.findall(r"\b(CVE-\d{4}-\d{4,7})\b", combined_text, re.IGNORECASE)
            # Deduplicate preserving order
            seen_cves = set()
            for c in cve_matches:
                c_up = c.upper()
                if c_up not in seen_cves:
                    seen_cves.add(c_up)
                    referenced_cves.append(c_up)

        affected_systems = item.get("affected_systems") or item.get("affected_products") or []
        if isinstance(affected_systems, str):
            affected_systems = [affected_systems]

        published_at = item.get("published_at") or item.get("release_date") or item.get("date")
        author = item.get("author") or item.get("organization") or "Cybersecurity and Infrastructure Security Agency"

        return {
            "alert_id": alert_id,
            "title": f"{alert_id}: {title}" if alert_id not in title else title,
            "summary": description[:300],
            "description": description,
            "canonical_url": canonical_url,
            "severity": severity,
            "referenced_cves": referenced_cves,
            "affected_systems": affected_systems,
            "published_at": published_at,
            "author": author,
            "references": [canonical_url],
        }

    def normalize(self, data: Any) -> NormalizedItem:
        """
        Normalize CERT alert into standard NormalizedItem contract with structured entities.
        """
        alert_id = data.get("alert_id", "CERT-ALERT")
        title = data.get("title", alert_id)
        description = data.get("description", "")
        url = data.get("canonical_url", f"https://www.cisa.gov/advisories/{alert_id}")
        published_at = data.get("published_at")
        author = data.get("author", "National CERT")

        tags = ["CERT", "Security Advisory", "Government"]
        if data.get("severity"):
            tags.append(data["severity"].title())

        # Structured entities
        entities: List[Dict[str, Any]] = [
            {
                "type": "advisory",
                "name": alert_id,
                "description": data.get("summary", "")[:500],
                "metadata": {
                    "severity": data.get("severity"),
                    "affected_systems": data.get("affected_systems", []),
                    "referenced_cves": data.get("referenced_cves", []),
                },
            }
        ]

        # Add CVE entities
        for cve in data.get("referenced_cves", []):
            tags.append(cve)
            entities.append({
                "type": "cve",
                "name": cve,
                "description": f"Vulnerability {cve} flagged in CERT alert {alert_id}",
                "metadata": {
                    "alert_id": alert_id,
                    "severity": data.get("severity"),
                },
            })

        # Add affected product/system entities
        for sys_name in data.get("affected_systems", []):
            clean_sys = str(sys_name).strip()
            if clean_sys:
                entities.append({
                    "type": "product",
                    "name": clean_sys,
                    "description": f"Affected system or technology in {alert_id}",
                    "metadata": {"alert_id": alert_id},
                })

        return NormalizedItem(
            title=title,
            url=url,
            description=description,
            author=author,
            published_at=published_at,
            source=self.source_name,
            content_type="advisory",
            raw_content=json.dumps(data, default=str),
            language="en",
            metadata={
                "alert_id": alert_id,
                "severity": data.get("severity"),
                "referenced_cves": data.get("referenced_cves", []),
                "affected_systems": data.get("affected_systems", []),
                "tags": tags,
                "entities": entities,
                "source_id": self.source_id,
            },
        )

    def health_check(self) -> ConnectorHealth:
        """Probe CERT alerts endpoint for HTTP responsiveness."""
        if self.raw_feed_content:
            return ConnectorHealth(
                status="ok",
                source_url="in_memory_cert_alerts",
                latency_ms=1.0,
                details={"mode": "in_memory"},
            )

        if not self.source_url:
            return ConnectorHealth(
                status="failing",
                source_url="",
                error_message="Missing source_url in CERT connector",
            )

        try:
            validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)
        except SSRFSecurityError as ssrf_err:
            return ConnectorHealth(
                status="failing",
                source_url=self.source_url,
                error_message=f"SSRF violation: {ssrf_err}",
            )

        start = time.perf_counter()
        try:
            with httpx.Client(
                timeout=min(self.timeout, 10.0),
                follow_redirects=True,
                max_redirects=3,
                headers=self._get_headers(),
            ) as client:
                res = client.get(self.source_url)
                latency = round((time.perf_counter() - start) * 1000, 2)
                if res.status_code >= 400:
                    return ConnectorHealth(
                        status="failing",
                        source_url=self.source_url,
                        latency_ms=latency,
                        error_message=f"HTTP status {res.status_code}",
                    )
                return ConnectorHealth(
                    status="ok",
                    source_url=self.source_url,
                    latency_ms=latency,
                    details={"status_code": res.status_code},
                )
        except Exception as exc:
            latency = round((time.perf_counter() - start) * 1000, 2)
            return ConnectorHealth(
                status="failing",
                source_url=self.source_url,
                latency_ms=latency,
                error_message=str(exc),
            )


# Auto-register CERT connector into connector registry
connector_registry.register("cert", CERTConnector)
connector_registry.register("cisa_alert", CERTConnector)
connector_registry.register("us_cert", CERTConnector)
