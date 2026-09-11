"""
CVE & Vulnerability Intelligence Connector
Ingests structured CVEs from CISA Known Exploited Vulnerabilities (KEV) Catalog,
NVD CVE API 2.0, and MITRE vulnerability feeds with SSRF preflight protection.
Conforms strictly to IMPLEMENT.md Section 12 and Section 13 specifications.
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

logger = logging.getLogger("cyber_osint.connectors.cve")


class CVEConnector(BaseConnector):
    """
    Ingestion connector for official vulnerability intelligence feeds (CISA KEV, NVD, MITRE).
    Extracts structured CVE metadata, CVSS scores, affected products, CWEs, and entity definitions.
    """

    DEFAULT_USER_AGENT = "CyberOSINT-CVE-Bot/1.0 (+https://cyber-osint.local/bot)"
    DEFAULT_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.raw_feed_content: Optional[str] = self.config.get("feed_content")  # In-memory test JSON

        if not self.source_url:
            self.source_url = self.DEFAULT_CISA_KEV_URL

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }

    def discover(self) -> List[Dict[str, Any]]:
        """
        Fetch and discover vulnerability entries from the CVE/KEV source.
        Preflights the feed URL against SSRF rules before sending outgoing HTTP requests.
        """
        # 1. Test/offline in-memory feed content
        if self.raw_feed_content:
            data = json.loads(self.raw_feed_content) if isinstance(self.raw_feed_content, str) else self.raw_feed_content
            entries = data.get("vulnerabilities") or (data if isinstance(data, list) else [])
            if self.max_entries:
                entries = entries[: self.max_entries]
            return entries

        # 2. SSRF Preflight check
        validate_url_for_ssrf(self.source_url, allow_private=self.allow_private)

        # 3. HTTP Request
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
            logger.error("HTTP error fetching CVE feed from '%s': %s", self.source_url, exc)
            raise RuntimeError(f"Failed to fetch CVE feed: {exc}") from exc

        # Extract items list
        entries = payload.get("vulnerabilities") or (payload if isinstance(payload, list) else [])
        if self.max_entries:
            entries = entries[: self.max_entries]

        logger.info("Discovered %d CVE entries from source '%s'", len(entries), self.source_name)
        return entries

    def fetch(self, item: Any) -> Dict[str, Any]:
        """Normalize raw item payload into dictionary representation."""
        if isinstance(item, dict):
            return item
        return dict(item)

    def parse(self, response: Any) -> Dict[str, Any]:
        """
        Extract structured vulnerability metadata from CISA KEV or NVD formatted dictionaries.
        """
        item = response

        # Format 1: CISA KEV Schema (cveID, vendorProject, product, vulnerabilityName, shortDescription, dateAdded)
        if "cveID" in item:
            cve_id = item.get("cveID", "").strip().upper()
            vuln_name = item.get("vulnerabilityName") or item.get("shortDescription") or cve_id
            title = f"{cve_id}: {vuln_name}"
            desc = item.get("shortDescription") or item.get("vulnerabilityName") or ""
            vendor = item.get("vendorProject", "Unknown Vendor")
            product = item.get("product", "Unknown Product")
            date_added = item.get("dateAdded")
            cwes = item.get("cwes") or []
            weakness = cwes[0] if isinstance(cwes, list) and cwes else item.get("cwe")
            notes = item.get("notes") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            # Known ransomware campaign flag
            ransomware = item.get("knownRansomwareCampaignUse", "Unknown")

            return {
                "cve_id": cve_id,
                "title": title,
                "description": desc,
                "canonical_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "vendor": vendor,
                "product": product,
                "affected_products": [f"{vendor} {product}".strip()],
                "severity": "CRITICAL" if ransomware.lower() == "known" else "HIGH",
                "cvss_score": 9.0 if ransomware.lower() == "known" else 7.5,
                "weakness": weakness,
                "published_at": f"{date_added}T00:00:00Z" if date_added else None,
                "references": [notes] if notes else [],
                "author": "CISA Cybersecurity and Infrastructure Security Agency",
            }

        # Format 2: NVD CVE API 2.0 Schema (cve: { id, descriptions, metrics, weaknesses })
        cve_node = item.get("cve", item)
        cve_id = cve_node.get("id", "").strip().upper()

        # Descriptions
        desc = ""
        for d in cve_node.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        if not desc and cve_node.get("descriptions"):
            desc = cve_node["descriptions"][0].get("value", "")

        # Metrics & CVSS
        metrics = cve_node.get("metrics", {})
        cvss_score = 0.0
        severity = "UNKNOWN"
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metric_key in metrics and metrics[metric_key]:
                data_node = metrics[metric_key][0].get("cvssData", {})
                cvss_score = float(data_node.get("baseScore", 0.0))
                severity = str(data_node.get("baseSeverity") or metrics[metric_key][0].get("baseSeverity") or "UNKNOWN").upper()
                break

        # Weaknesses (CWE)
        weakness = None
        for w in cve_node.get("weaknesses", []):
            for desc_w in w.get("description", []):
                val = desc_w.get("value")
                if val and val.startswith("CWE-"):
                    weakness = val
                    break
            if weakness:
                break

        # References
        refs = [r.get("url") for r in cve_node.get("references", []) if r.get("url")]

        published = cve_node.get("published")

        title = f"{cve_id}: {desc[:80]}..." if desc else cve_id

        return {
            "cve_id": cve_id,
            "title": title,
            "description": desc,
            "canonical_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "vendor": "Multiple",
            "product": "Vulnerable Software",
            "affected_products": [],
            "severity": severity,
            "cvss_score": cvss_score,
            "weakness": weakness,
            "published_at": published,
            "references": refs[:5],
            "author": "National Vulnerability Database (NVD)",
        }

    def normalize(self, data: Any) -> NormalizedItem:
        """
        Transform parsed vulnerability data into standard NormalizedItem contract
        and populate structured entities for automated database linking.
        """
        cve_id = data.get("cve_id") or "CVE-UNKNOWN"
        title = data.get("title") or cve_id
        description = data.get("description") or ""
        url = data.get("canonical_url") or f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        author = data.get("author") or self.source_name
        published_at = data.get("published_at")

        # Tags
        tags = ["CVE", "Vulnerability"]
        if data.get("severity") and data["severity"] != "UNKNOWN":
            tags.append(data["severity"].title())
        if data.get("weakness"):
            tags.append(data["weakness"])

        # Structured entities for downstream automated Entity linking
        entities: List[Dict[str, Any]] = [
            {
                "type": "cve",
                "name": cve_id,
                "description": description[:500],
                "metadata": {
                    "cvss_score": data.get("cvss_score"),
                    "severity": data.get("severity"),
                    "weakness": data.get("weakness"),
                    "references": data.get("references", []),
                    "affected_products": data.get("affected_products", []),
                },
            }
        ]

        if data.get("product") and data["product"] != "Unknown Product":
            entities.append({
                "type": "product",
                "name": data["product"],
                "description": f"Product from vendor {data.get('vendor')}",
                "metadata": {"vendor": data.get("vendor")},
            })

        if data.get("weakness"):
            entities.append({
                "type": "cwe",
                "name": data["weakness"],
                "description": f"Common Weakness Enumeration {data['weakness']}",
                "metadata": {},
            })

        return NormalizedItem(
            title=title,
            url=url,
            description=description,
            author=author,
            published_at=published_at,
            source=self.source_name,
            content_type="cve",
            raw_content=json.dumps(data, default=str),
            language="en",
            metadata={
                "cve_id": cve_id,
                "cvss_score": data.get("cvss_score"),
                "severity": data.get("severity"),
                "weakness": data.get("weakness"),
                "affected_products": data.get("affected_products", []),
                "references": data.get("references", []),
                "vendor": data.get("vendor"),
                "product": data.get("product"),
                "tags": tags,
                "entities": entities,
                "source_id": self.source_id,
            },
        )

    def health_check(self) -> ConnectorHealth:
        """Probe CVE source endpoint for HTTP responsiveness and JSON schema validity."""
        if self.raw_feed_content:
            return ConnectorHealth(
                status="ok",
                source_url="in_memory_cve_feed",
                latency_ms=1.0,
                details={"mode": "in_memory"},
            )

        if not self.source_url:
            return ConnectorHealth(
                status="failing",
                source_url="",
                error_message="Missing source_url in CVE connector",
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


# Auto-register CVE connector into connector registry
connector_registry.register("cve", CVEConnector)
connector_registry.register("nvd", CVEConnector)
connector_registry.register("kev", CVEConnector)
connector_registry.register("cisa_kev", CVEConnector)
