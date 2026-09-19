"""
Advanced OSINT Connector Manager
Coordinates the 11 prioritized OSINT connector categories from IMPLEMENT.md Section 34.
Enforces strict priority hierarchy (1-11) and independent enable/disable toggling.
"""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple, Type

from connectors.base import BaseConnector, ConnectorHealth, NormalizedItem
from connectors.blog.connector import SecurityBlogConnector
from connectors.cert.connector import CERTConnector
from connectors.conference.connector import ConferenceSourceConnector
from connectors.cve.connector import CVEConnector
from connectors.github.connector import GitHubSecurityConnector
from connectors.registry import connector_registry
from connectors.research.connector import ResearchDatabaseConnector
from connectors.rss.connector import RSSConnector
from connectors.social.connector import PublicSocialConnector
from connectors.specialized.connector import SpecializedSourceConnector
from connectors.vendor.connector import VendorAdvisoryConnector
from connectors.video.connector import VideoConnector

logger = logging.getLogger("cyber_osint.connectors.manager")

# The 11 mandated connector categories and their strict priority order
PRIORITY_CONNECTOR_SPECS = [
    {
        "id": "security_feeds",
        "priority": 1,
        "name": "Security Feeds (RSS / Atom)",
        "category": "security_feeds",
        "connector_cls": RSSConnector,
        "description": "Commercial and community news feeds (BleepingComputer, DarkReading, KrebsOnSecurity, Threatpost).",
        "default_enabled": True,
    },
    {
        "id": "government_cert",
        "priority": 2,
        "name": "Government & National CERT Bulletins",
        "category": "government_cert",
        "connector_cls": CERTConnector,
        "description": "National CSIRTs, CISA alerts, CERT-EU operational bulletins, and critical infrastructure directives.",
        "default_enabled": True,
    },
    {
        "id": "cve_databases",
        "priority": 3,
        "name": "CVE Databases & KEV Catalogs",
        "category": "cve_databases",
        "connector_cls": CVEConnector,
        "description": "NVD NIST, MITRE CVE, CISA Known Exploited Vulnerabilities (KEV), and VulnCheck feeds.",
        "default_enabled": True,
    },
    {
        "id": "vendor_advisories",
        "priority": 4,
        "name": "Vendor Security Advisories",
        "category": "vendor_advisories",
        "connector_cls": VendorAdvisoryConnector,
        "description": "Hardware and software vendor bulletins: Microsoft MSRC, Cisco, Red Hat, Palo Alto, Apple, Google.",
        "default_enabled": True,
    },
    {
        "id": "security_blogs",
        "priority": 5,
        "name": "Security Research Labs & Blogs",
        "category": "security_blogs",
        "connector_cls": SecurityBlogConnector,
        "description": "Elite research teams: Google Project Zero, Mandiant, Cisco Talos, Unit 42, SentinelOne Labs.",
        "default_enabled": True,
    },
    {
        "id": "github",
        "priority": 6,
        "name": "GitHub Security & Exploit PoCs",
        "category": "github",
        "connector_cls": GitHubSecurityConnector,
        "description": "GitHub Security Advisories (GHSA), weaponized exploit PoCs, offensive security tooling repositories.",
        "default_enabled": True,
    },
    {
        "id": "research_databases",
        "priority": 7,
        "name": "Academic Research Databases",
        "category": "research_databases",
        "connector_cls": ResearchDatabaseConnector,
        "description": "Peer-reviewed security publications and preprints from arXiv CS.CR, IACR ePrint, and USENIX.",
        "default_enabled": True,
    },
    {
        "id": "video_platforms",
        "priority": 8,
        "name": "Video & Multimedia Platforms",
        "category": "video_platforms",
        "connector_cls": VideoConnector,
        "description": "Conference talk recordings, security lectures, and technical walkthroughs from YouTube, Black Hat, DEF CON.",
        "default_enabled": True,
    },
    {
        "id": "conference_sources",
        "priority": 9,
        "name": "Conference Proceedings & Talks",
        "category": "conference_sources",
        "connector_cls": ConferenceSourceConnector,
        "description": "Speaker briefings, slide decks, and workshop whitepapers from DEF CON, Black Hat, CCC, BSides.",
        "default_enabled": True,
    },
    {
        "id": "public_social",
        "priority": 10,
        "name": "Public Social Security Intelligence",
        "category": "public_social",
        "connector_cls": PublicSocialConnector,
        "description": "Decentralized infosec discussions from Mastodon (infosec.exchange), Bluesky, and Reddit r/netsec.",
        "default_enabled": True,
    },
    {
        "id": "specialized_sources",
        "priority": 11,
        "name": "Specialized Threat Registries",
        "category": "specialized_sources",
        "connector_cls": SpecializedSourceConnector,
        "description": "Malware analysis feeds, IOC registries, and exploit archives (MalwareBazaar, Exploit-DB, URLhaus).",
        "default_enabled": True,
    },
]


class AdvancedConnectorManager:
    """
    Central coordinator managing all 11 prioritized OSINT connector categories.
    Guarantees independent enable/disable controls and priority-ordered batch execution.
    Synchronizes with declarative connectors.yaml configuration.
    """

    def __init__(self):
        self._enabled_state: Dict[str, bool] = {}
        self._last_run_telemetry: Dict[str, Dict[str, Any]] = {}
        self._instances: Dict[str, BaseConnector] = {}
        self._intervals: Dict[str, int] = {}
        self._priority_labels: Dict[str, str] = {}
        self._urls: Dict[str, Optional[str]] = {}
        self._api_key_envs: Dict[str, Optional[str]] = {}
        self._custom_options: Dict[str, Dict[str, Any]] = {}

        # Initialize registration and enabled states
        for spec in PRIORITY_CONNECTOR_SPECS:
            cid = spec["id"]
            self._enabled_state[cid] = spec["default_enabled"]
            self._intervals[cid] = 60
            self._priority_labels[cid] = "medium"
            # Register in global registry under ID and category
            connector_registry.register(cid, spec["connector_cls"])
            if spec["category"] != cid:
                connector_registry.register(spec["category"], spec["connector_cls"])

        # Attempt initial synchronization from connectors.yaml if available
        try:
            self.sync_from_yaml()
        except Exception as exc:
            logger.debug("Initial connectors.yaml sync deferred or failed: %s", exc)

    def sync_from_yaml(self) -> Dict[str, Any]:
        """
        Synchronizes runtime manager with the declarative connectors.yaml file.
        Updates enabled states, intervals, priority labels, URLs, and options.
        """
        from connectors.config import connector_config_manager
        configs = connector_config_manager.load_config()
        updated = []
        for key, conf in configs.items():
            category_or_id = conf.category or key
            spec = self.get_spec(category_or_id)
            if not spec:
                for s in self.list_connectors():
                    if s["category"] == conf.type or s["id"] == conf.type or s["category"] == conf.category:
                        spec = self.get_spec(s["id"])
                        break

            if spec:
                cid = spec["id"]
                self.set_enabled(cid, conf.enabled)
                self._intervals[cid] = conf.interval_minutes
                self._priority_labels[cid] = conf.priority
                if conf.url:
                    self._urls[cid] = conf.url
                if conf.api_key_env:
                    self._api_key_envs[cid] = conf.api_key_env
                opts = dict(conf.options)
                if conf.timeout:
                    opts["timeout"] = conf.timeout
                if conf.headers:
                    opts["headers"] = conf.headers
                self._custom_options[cid] = opts
                updated.append(cid)

        return {
            "synced_count": len(updated),
            "synced_ids": updated,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def list_connectors(self) -> List[Dict[str, Any]]:
        """
        Returns all 11 connector specifications sorted strictly by priority order (1 to 11).
        Includes current enable/disable status, intervals, and latest runtime telemetry.
        """
        results = []
        for spec in sorted(PRIORITY_CONNECTOR_SPECS, key=lambda x: x["priority"]):
            cid = spec["id"]
            telemetry = self._last_run_telemetry.get(cid, {})
            results.append({
                "id": cid,
                "priority": spec["priority"],
                "name": spec["name"],
                "category": spec["category"],
                "description": spec["description"],
                "connector_class": spec["connector_cls"].__name__,
                "is_enabled": self._enabled_state.get(cid, True),
                "interval_minutes": self._intervals.get(cid, 60),
                "priority_label": self._priority_labels.get(cid, "medium"),
                "url": self._urls.get(cid),
                "api_key_env": self._api_key_envs.get(cid),
                "last_run": telemetry.get("last_run"),
                "last_started_at": telemetry.get("last_started_at"),
                "last_finished_at": telemetry.get("last_finished_at"),
                "last_success_at": telemetry.get("last_success_at"),
                "last_error_at": telemetry.get("last_error_at"),
                "last_error": telemetry.get("last_error"),
                "next_run_at": telemetry.get("next_run_at"),
                "last_status": telemetry.get("last_status", "idle"),
                "items_count": telemetry.get("items_count", 0),
                "items_fetched": telemetry.get("items_fetched", 0),
                "items_processed": telemetry.get("items_processed", 0),
                "items_inserted": telemetry.get("items_inserted", 0),
                "items_updated": telemetry.get("items_updated", 0),
                "items_duplicate": telemetry.get("items_duplicate", 0),
                "items_failed": telemetry.get("items_failed", 0),
                "execution_duration_ms": telemetry.get("execution_duration_ms", 0.0),
            })
        return results

    def get_spec(self, connector_id: str) -> Optional[Dict[str, Any]]:
        """Find specification by connector ID."""
        for spec in PRIORITY_CONNECTOR_SPECS:
            if spec["id"] == connector_id:
                return spec
        return None

    def set_enabled(self, connector_id: str, enabled: bool) -> bool:
        """
        Independently enables or disables an OSINT connector.
        Conforms to IMPLEMENT.md Section 34: "Each connector should be independently enabled or disabled."
        """
        spec = self.get_spec(connector_id)
        if not spec:
            raise KeyError(f"Connector '{connector_id}' is not one of the 11 recognized priority categories.")
        self._enabled_state[connector_id] = enabled
        logger.info("Connector '%s' enabled status set to %s", connector_id, enabled)
        return True

    def is_enabled(self, connector_id: str) -> bool:
        """Check if connector is currently enabled."""
        return self._enabled_state.get(connector_id, False)

    def toggle_connector(self, connector_id: str, enabled: Optional[bool] = None) -> bool:
        """Toggles or sets the enabled status of a connector."""
        if enabled is None:
            enabled = not self.is_enabled(connector_id)
        return self.set_enabled(connector_id, enabled)


    def get_instance(self, connector_id: str, source_config: Optional[Dict[str, Any]] = None) -> BaseConnector:
        """Instantiates connector instance, populating defaults from connectors.yaml."""
        spec = self.get_spec(connector_id)
        if not spec:
            raise KeyError(f"Unknown connector ID: {connector_id}")

        cls_ = spec["connector_cls"]
        cfg = dict(source_config) if source_config else {}
        cfg["enabled"] = self.is_enabled(connector_id)
        if "source_url" not in cfg and self._urls.get(connector_id):
            cfg["source_url"] = self._urls[connector_id]
        if "interval_minutes" not in cfg and self._intervals.get(connector_id):
            cfg["interval_minutes"] = self._intervals[connector_id]
        if connector_id in self._custom_options:
            for k, v in self._custom_options[connector_id].items():
                if k not in cfg:
                    cfg[k] = v
        return cls_(source_config=cfg)

    def health_check(self, connector_id: str) -> ConnectorHealth:
        """Executes active health check on a specific connector."""
        connector = self.get_instance(connector_id)
        return connector.health_check()

    def health_check_all(self) -> Dict[str, Any]:
        """Runs health checks across all 11 connectors."""
        results = {}
        healthy_count = 0
        for spec in PRIORITY_CONNECTOR_SPECS:
            cid = spec["id"]
            health = self.health_check(cid)
            results[cid] = health.model_dump()
            if health.status == "ok":
                healthy_count += 1

        return {
            "total_connectors": len(PRIORITY_CONNECTOR_SPECS),
            "healthy_count": healthy_count,
            "results": results,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    def run_connector(self, connector_id: str, db: Optional[Any] = None) -> List[NormalizedItem]:
        """
        Executes discovery and normalization pipeline for a single connector.
        Throws error if disabled unless forced.
        Automatically persists normalized items into Content/Entity tables if db is available.
        """
        if not self.is_enabled(connector_id):
            logger.warning("Attempted to run disabled connector '%s'", connector_id)
            return []

        connector = self.get_instance(connector_id)
        start_t = datetime.now(timezone.utc)
        start_iso = start_t.isoformat()
        current_telemetry = self._last_run_telemetry.setdefault(connector_id, {})
        current_telemetry["last_started_at"] = start_iso
        current_telemetry["last_status"] = "running"

        try:
            items = connector.run_pipeline()
            finished_t = datetime.now(timezone.utc)
            duration_ms = round((finished_t - start_t).total_seconds() * 1000, 2)

            # Persist items to database via IngestionPipeline
            metrics = None
            try:
                from services.ingestion.pipeline import ingestion_pipeline
                from app.models.source import Source
                target_db = db
                owns_db = False
                if target_db is None:
                    try:
                        from app.database import SessionLocal
                        target_db = SessionLocal()
                        owns_db = True
                    except Exception:
                        target_db = None

                if target_db is not None:
                    try:
                        source_spec = self.get_spec(connector_id)
                        spec_name = source_spec["name"] if source_spec else connector_id
                        source_url = self._urls.get(connector_id) or ""
                        source = target_db.query(Source).filter(
                            (Source.name == connector_id) | (Source.url == source_url)
                        ).first()
                        source_id = source.id if source else None
                        metrics = ingestion_pipeline.ingest_items(
                            db=target_db,
                            items=items,
                            source_id=source_id,
                            source_name=spec_name,
                        )
                    finally:
                        if owns_db:
                            target_db.close()
            except Exception as persist_err:
                logger.warning("Database persistence error during connector '%s' run: %s", connector_id, persist_err)

            inserted = metrics.ingested_count if metrics else len(items)
            updated = metrics.updated_count if metrics else 0
            duplicates = metrics.duplicates_skipped if metrics else 0
            errors = metrics.errors_count if metrics else 0
            interval_mins = self._intervals.get(connector_id, 60)
            next_run_iso = (finished_t + timedelta(minutes=interval_mins)).isoformat()

            current_telemetry.update({
                "last_run": start_iso,
                "last_started_at": start_iso,
                "last_finished_at": finished_t.isoformat(),
                "last_success_at": finished_t.isoformat(),
                "last_status": "success",
                "last_error": None,
                "next_run_at": next_run_iso,
                "items_count": len(items),
                "items_fetched": len(items),
                "items_processed": len(items),
                "items_inserted": inserted,
                "items_updated": updated,
                "items_duplicate": duplicates,
                "items_failed": errors,
                "execution_duration_ms": duration_ms,
            })
            return items
        except Exception as exc:
            finished_t = datetime.now(timezone.utc)
            duration_ms = round((finished_t - start_t).total_seconds() * 1000, 2)
            current_telemetry.update({
                "last_run": start_iso,
                "last_started_at": start_iso,
                "last_finished_at": finished_t.isoformat(),
                "last_error_at": finished_t.isoformat(),
                "last_error": str(exc),
                "last_status": "error",
                "items_count": 0,
                "items_failed": 1,
                "execution_duration_ms": duration_ms,
            })
            logger.error("Connector '%s' execution failed: %s", connector_id, exc)
            raise

    def run_all_enabled(self) -> Dict[str, Any]:
        """
        Executes all currently enabled connectors in strict priority order (1 through 11).
        """
        total_items: List[NormalizedItem] = []
        batch_summary: List[Dict[str, Any]] = []

        # Sort strictly by priority 1 -> 11
        sorted_specs = sorted(PRIORITY_CONNECTOR_SPECS, key=lambda x: x["priority"])

        for spec in sorted_specs:
            cid = spec["id"]
            if not self.is_enabled(cid):
                batch_summary.append({
                    "id": cid,
                    "priority": spec["priority"],
                    "status": "skipped_disabled",
                    "items_count": 0,
                })
                continue

            try:
                items = self.run_connector(cid)
                total_items.extend(items)
                batch_summary.append({
                    "id": cid,
                    "priority": spec["priority"],
                    "status": "success",
                    "items_count": len(items),
                })
            except Exception as e:
                batch_summary.append({
                    "id": cid,
                    "priority": spec["priority"],
                    "status": "failed",
                    "error": str(e),
                    "items_count": 0,
                })

        return {
            "total_items_discovered": len(total_items),
            "executed_connectors": len([b for b in batch_summary if b["status"] == "success"]),
            "skipped_connectors": len([b for b in batch_summary if b["status"] == "skipped_disabled"]),
            "failed_connectors": len([b for b in batch_summary if b["status"] == "failed"]),
            "priority_execution_order": [b["id"] for b in batch_summary],
            "batch_summary": batch_summary,
            "executed_at": datetime.now(timezone.utc).isoformat(),
        }


# Global singleton manager instance
connector_manager = AdvancedConnectorManager()
ConnectorManager = AdvancedConnectorManager

