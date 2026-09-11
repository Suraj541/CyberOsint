"""
GitHub Security Advisories Connector
Ingests security advisories from the GitHub Advisory Database (GHSA)
with SSRF preflight protection, package ecosystem tracking, and CVSS metadata extraction.
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

logger = logging.getLogger("cyber_osint.connectors.github")


class GitHubSecurityConnector(BaseConnector):
    """
    Connector for GitHub Security Advisories (GHSA).
    Parses open-source package vulnerability disclosures, CVSS scores, affected packages,
    and associated CVE references.
    """

    DEFAULT_USER_AGENT = "CyberOSINT-GitHub-Bot/1.0 (+https://cyber-osint.local/bot)"
    DEFAULT_GHSA_API_URL = "https://api.github.com/advisories"

    def __init__(self, source_config: Optional[Dict[str, Any]] = None, **kwargs):
        super().__init__(source_config)
        self.allow_private: bool = self.config.get("allow_private", False)
        self.timeout: float = float(self.config.get("timeout", 30.0))
        self.user_agent: str = self.config.get("user_agent", self.DEFAULT_USER_AGENT)
        self.github_token: Optional[str] = self.config.get("github_token") or self.config.get("api_key")
        self.max_entries: Optional[int] = self.config.get("max_entries")
        self.raw_feed_content: Optional[str] = self.config.get("feed_content")  # In-memory test JSON

        if not self.source_url:
            self.source_url = self.DEFAULT_GHSA_API_URL

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return headers

    def discover(self) -> List[Dict[str, Any]]:
        """
        Discover security advisories from GitHub Advisory API.
        Validates the URL against SSRF rules before sending outgoing requests.
        """
        if self.raw_feed_content:
            data = json.loads(self.raw_feed_content) if isinstance(self.raw_feed_content, str) else self.raw_feed_content
            entries = data if isinstance(data, list) else data.get("advisories", [data])
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
            logger.error("HTTP error fetching GitHub Advisories from '%s': %s", self.source_url, exc)
            raise RuntimeError(f"Failed to fetch GitHub Advisories: {exc}") from exc

        entries = payload if isinstance(payload, list) else payload.get("advisories", [payload])
        if self.max_entries:
            entries = entries[: self.max_entries]

        logger.info("Discovered %d GitHub advisories from source '%s'", len(entries), self.source_name)
        return entries

    def fetch(self, item: Any) -> Dict[str, Any]:
        """Convert raw item into dictionary."""
        if isinstance(item, dict):
            return item
        return dict(item)

    def parse(self, response: Any) -> Dict[str, Any]:
        """
        Extract structured GHSA, CVE, CVSS, and affected package metadata from advisory payload.
        """
        item = response
        ghsa_id = item.get("ghsa_id") or item.get("id") or "GHSA-UNKNOWN"
        summary = item.get("summary") or item.get("title") or ghsa_id
        description = item.get("description") or summary

        # CVE extraction
        cve_id = item.get("cve_id")
        if not cve_id:
            identifiers = item.get("identifiers") or []
            for ident in identifiers:
                if isinstance(ident, dict) and ident.get("type", "").upper() == "CVE":
                    cve_id = ident.get("value")
                    break
        if not cve_id and description:
            match = re.search(r"\b(CVE-\d{4}-\d{4,7})\b", description)
            if match:
                cve_id = match.group(1)

        # Severity & CVSS
        severity = str(item.get("severity") or "unknown").upper()
        cvss_data = item.get("cvss") or {}
        cvss_score = 0.0
        if isinstance(cvss_data, dict):
            cvss_score = float(cvss_data.get("score") or 0.0)
        elif isinstance(cvss_data, (int, float)):
            cvss_score = float(cvss_data)

        # Affected packages
        affected_packages = []
        vulns = item.get("vulnerabilities") or []
        for v in vulns:
            if isinstance(v, dict):
                pkg_node = v.get("package") or {}
                pkg_name = pkg_node.get("name") if isinstance(pkg_node, dict) else str(pkg_node)
                eco = pkg_node.get("ecosystem", "generic") if isinstance(pkg_node, dict) else "generic"
                if pkg_name:
                    affected_packages.append(f"{eco}:{pkg_name}")

        canonical_url = item.get("html_url") or item.get("url") or f"https://github.com/advisories/{ghsa_id}"
        published_at = item.get("published_at") or item.get("created_at")

        references = []
        for ref in item.get("references") or []:
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            if url:
                references.append(url)

        title = f"{ghsa_id}: {summary}"

        return {
            "ghsa_id": ghsa_id,
            "cve_id": cve_id,
            "title": title,
            "summary": summary,
            "description": description,
            "canonical_url": canonical_url,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected_packages": affected_packages,
            "published_at": published_at,
            "references": references[:5],
            "author": item.get("author") or "GitHub Advisory Database",
        }

    def normalize(self, data: Any) -> NormalizedItem:
        """
        Normalize advisory data into standard NormalizedItem contract with structured entities.
        """
        ghsa_id = data.get("ghsa_id", "GHSA-UNKNOWN")
        cve_id = data.get("cve_id")
        title = data.get("title", ghsa_id)
        description = data.get("description", "")
        url = data.get("canonical_url", f"https://github.com/advisories/{ghsa_id}")
        published_at = data.get("published_at")
        author = data.get("author", "GitHub Security")

        tags = ["GitHub", "Security Advisory", "GHSA"]
        if data.get("severity") and data["severity"] != "UNKNOWN":
            tags.append(data["severity"].title())

        # Structured entities
        entities: List[Dict[str, Any]] = [
            {
                "type": "advisory",
                "name": ghsa_id,
                "description": data.get("summary", "")[:500],
                "metadata": {
                    "severity": data.get("severity"),
                    "cvss_score": data.get("cvss_score"),
                    "references": data.get("references", []),
                    "affected_packages": data.get("affected_packages", []),
                },
            }
        ]

        if cve_id:
            tags.append(cve_id)
            entities.append({
                "type": "cve",
                "name": cve_id,
                "description": f"Vulnerability {cve_id} referenced in {ghsa_id}",
                "metadata": {
                    "cvss_score": data.get("cvss_score"),
                    "severity": data.get("severity"),
                    "advisory": ghsa_id,
                },
            })

        for pkg in data.get("affected_packages", []):
            parts = pkg.split(":", 1)
            pkg_name = parts[1] if len(parts) == 2 else parts[0]
            ecosystem = parts[0] if len(parts) == 2 else "generic"
            entities.append({
                "type": "product",
                "name": pkg_name,
                "description": f"Package {pkg_name} ({ecosystem})",
                "metadata": {"ecosystem": ecosystem, "advisory": ghsa_id},
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
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "severity": data.get("severity"),
                "cvss_score": data.get("cvss_score"),
                "affected_packages": data.get("affected_packages", []),
                "references": data.get("references", []),
                "tags": tags,
                "entities": entities,
                "source_id": self.source_id,
            },
        )

    def health_check(self) -> ConnectorHealth:
        """Check GitHub Security Advisories endpoint health and responsiveness."""
        if self.raw_feed_content:
            return ConnectorHealth(
                status="ok",
                source_url="in_memory_github_advisories",
                latency_ms=1.0,
                details={"mode": "in_memory"},
            )

        if not self.source_url:
            return ConnectorHealth(
                status="failing",
                source_url="",
                error_message="Missing source_url in GitHub connector",
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


# Auto-register GitHub connector into connector registry
connector_registry.register("github", GitHubSecurityConnector)
connector_registry.register("ghsa", GitHubSecurityConnector)
connector_registry.register("github_advisory", GitHubSecurityConnector)
