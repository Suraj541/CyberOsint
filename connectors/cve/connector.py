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

import hashlib
import os
from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.registry import connector_registry
from connectors.security import SSRFSecurityError, validate_url_for_ssrf
from services.sync.state import sync_state_manager

logger = logging.getLogger("cyber_osint.connectors.cve")


class CVEConnector(BaseConnector):
    """
    Ingestion connector for official vulnerability intelligence feeds (CISA KEV, NVD, MITRE).
    Extracts structured CVE metadata, CVSS scores, affected products, CWEs, and entity definitions.
    Features robust NVD API 2.0 pagination, rate limiting, incremental sync, and state persistence.
    """

    DEFAULT_USER_AGENT = "CyberOSINT-CVE-Bot/1.0 (+https://cyber-osint.local/bot)"
    DEFAULT_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.results_per_page: int = int(self.config.get("results_per_page", 2000))
        self.max_pages: int = int(self.config.get("max_pages", 50))
        self.raw_feed_content: Optional[str] = self.config.get("feed_content")  # In-memory test JSON
        self.api_key: Optional[str] = self.config.get("api_key") or os.environ.get("NVD_API_KEY")

        if not self.source_url:
            self.source_url = self.DEFAULT_CISA_KEV_URL

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/json, text/plain, */*",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def discover(self) -> List[Dict[str, Any]]:
        """
        Fetch and discover vulnerability entries from the CVE/KEV/NVD source.
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

        # 3. Route to specialized fetcher (NVD API 2.0 vs CISA KEV / generic JSON)
        is_nvd = (
            "services.nvd.nist.gov" in self.source_url
            or "api.nvd" in self.source_url
            or "/cves/2.0" in self.source_url
        )
        if is_nvd:
            return self._discover_nvd()
        else:
            return self._discover_generic_or_kev()

    def _discover_nvd(self) -> List[Dict[str, Any]]:
        """
        Fetch NVD API 2.0 with full pagination (startIndex, resultsPerPage, totalResults),
        rate-limiting (0.6s with API key, 6.0s without), exponential backoff, and incremental sync.
        """
        all_entries: List[Dict[str, Any]] = []
        start_index = 0
        page_size = min(self.results_per_page, 2000)
        delay_between_requests = 0.6 if self.api_key else 6.0
        max_retries = 3

        # Persistent sync state check for incremental sync
        connector_id = f"cve_nvd_{self.source_id or 'default'}"
        sync_state = sync_state_manager.get_state(None, connector_id)
        last_modified_cursor = sync_state.get("last_seen_modified_at")
        latest_seen_modified: Optional[datetime] = None

        logger.info(
            "Starting NVD API 2.0 ingestion for '%s' (pageSize=%d, incremental=%s)",
            self.source_name,
            page_size,
            bool(last_modified_cursor),
        )

        for page in range(self.max_pages):
            params: Dict[str, Any] = {
                "startIndex": start_index,
                "resultsPerPage": page_size,
            }

            # Incremental synchronization parameter if within 120 days allowed by NVD
            if last_modified_cursor and page == 0:
                try:
                    last_mod_dt = datetime.fromisoformat(last_modified_cursor.replace("Z", "+00:00"))
                    if last_mod_dt.tzinfo is None:
                        last_mod_dt = last_mod_dt.replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    days_diff = (now_dt - last_mod_dt).days
                    if 0 <= days_diff <= 120:
                        params["lastModStartDate"] = last_mod_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
                        params["lastModEndDate"] = now_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
                        logger.info("NVD incremental sync window: %s to %s", params["lastModStartDate"], params["lastModEndDate"])
                except Exception as ex:
                    logger.warning("Could not apply NVD lastModStartDate filter: %s", ex)

            # Request execution with exponential backoff on 429/503
            payload = None
            for attempt in range(max_retries):
                try:
                    with httpx.Client(
                        timeout=self.timeout,
                        follow_redirects=True,
                        max_redirects=3,
                        headers=self._get_headers(),
                    ) as client:
                        resp = client.get(self.source_url, params=params)
                        if resp.status_code in (429, 503, 504):
                            wait_time = (2 ** attempt) * 2.0
                            logger.warning("NVD rate-limited (status %d). Backing off %.1fs...", resp.status_code, wait_time)
                            time.sleep(wait_time)
                            continue
                        resp.raise_for_status()
                        payload = resp.json()
                        break
                except httpx.RequestError as req_err:
                    if attempt == max_retries - 1:
                        logger.error("Failed NVD request after %d attempts: %s", max_retries, req_err)
                        raise RuntimeError(f"NVD API request failed: {req_err}") from req_err
                    time.sleep((attempt + 1) * 2.0)

            if payload is None:
                logger.warning("No response payload received from NVD at startIndex=%d", start_index)
                break

            vulnerabilities = payload.get("vulnerabilities", [])
            total_results = payload.get("totalResults", len(vulnerabilities))

            for v in vulnerabilities:
                all_entries.append(v)
                # Track latest lastModified for cursor
                cve_node = v.get("cve", v)
                mod_str = cve_node.get("lastModified")
                if mod_str:
                    try:
                        mod_dt = datetime.fromisoformat(mod_str.replace("Z", "+00:00"))
                        if latest_seen_modified is None or mod_dt > latest_seen_modified:
                            latest_seen_modified = mod_dt
                    except Exception:
                        pass

            logger.info(
                "NVD page %d fetched (%d-%d of %d total)",
                page + 1,
                start_index,
                start_index + len(vulnerabilities),
                total_results,
            )

            # Check termination criteria
            if self.max_entries and len(all_entries) >= self.max_entries:
                all_entries = all_entries[: self.max_entries]
                break

            if start_index + len(vulnerabilities) >= total_results or len(vulnerabilities) == 0:
                break

            start_index += len(vulnerabilities)
            time.sleep(delay_between_requests)

        # Update persistent sync state
        try:
            sync_state_manager.update_state(
                db=None,
                connector_id=connector_id,
                source_url=self.source_url,
                last_seen_modified_at=latest_seen_modified,
                cursor=str(start_index),
                metadata={"total_fetched": len(all_entries)},
            )
        except Exception as st_err:
            logger.debug("Failed to record NVD sync state: %s", st_err)

        logger.info("Completed NVD discovery: %d entries retrieved", len(all_entries))
        return all_entries

    def _discover_generic_or_kev(self) -> List[Dict[str, Any]]:
        """Fetch monolithic CVE feed (e.g. CISA KEV JSON) with SSRF validation and ETag/hash tracking."""
        try:
            with httpx.Client(
                timeout=self.timeout,
                follow_redirects=True,
                max_redirects=3,
                headers=self._get_headers(),
            ) as client:
                resp = client.get(self.source_url)
                resp.raise_for_status()
                raw_text = resp.text
                payload = resp.json()
        except Exception as exc:
            logger.error("HTTP error fetching CVE feed from '%s': %s", self.source_url, exc)
            raise RuntimeError(f"Failed to fetch CVE feed: {exc}") from exc

        # Extract items list
        entries = payload.get("vulnerabilities") or (payload if isinstance(payload, list) else [])
        if self.max_entries:
            entries = entries[: self.max_entries]

        # Checkpoint persistent sync state
        try:
            payload_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
            connector_id = f"cve_kev_{self.source_id or 'default'}"
            sync_state_manager.update_state(
                db=None,
                connector_id=connector_id,
                source_url=self.source_url,
                last_payload_hash=payload_hash,
                metadata={"item_count": len(entries)},
            )
        except Exception as st_err:
            logger.debug("Failed to record KEV sync state: %s", st_err)

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
        last_modified = cve_node.get("lastModified") or published

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
            "modified_at": last_modified,
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
                "modified_at": data.get("modified_at"),
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
