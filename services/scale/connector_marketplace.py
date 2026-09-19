"""Section 49 (Step 48): Connector Marketplace Service.

Provides:
  - Manifest validation for third-party community connectors
  - Catalog search, installation, uninstallation, and rating management
  - Pre-seeded curated community OSINT connectors
"""

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.scale import MarketplaceConnectorModel
from app.schemas.scale import ConnectorManifest, MarketplaceConnectorOut, MarketplacePublishRequest

INITIAL_MARKETPLACE_CONNECTORS = [
    {
        "name": "Shodan Internet Intelligence Plugin",
        "slug": "shodan-osint-connector",
        "version": "1.2.0",
        "author": "Community Security Collective",
        "category": "threat_intel",
        "description": "Scans exposed industrial control systems, open SSL ports, and banner metadata via Shodan API.",
        "repository_url": "https://github.com/cyber-osint-hub/shodan-connector",
        "is_installed": True,
        "is_verified": True,
        "rating": 4.9,
        "downloads_count": 1420,
        "manifest": {
            "schema_version": "1.0",
            "name": "Shodan Internet Intelligence Plugin",
            "slug": "shodan-osint-connector",
            "version": "1.2.0",
            "author": "Community Security Collective",
            "category": "threat_intel",
            "permissions": ["network:outbound", "api_key:required"],
            "allowed_domains": ["api.shodan.io"],
            "timeout_seconds": 25,
            "entry_point": "shodan_connector.ShodanConnector",
        },
    },
    {
        "name": "GreyNoise Internet Noise Analyzer",
        "slug": "greynoise-analyzer",
        "version": "1.1.0",
        "author": "Threat Research Labs",
        "category": "scanner",
        "description": "Filters out benign internet background noise, mass scanners, and common research crawlers from SIEM telemetry.",
        "repository_url": "https://github.com/cyber-osint-hub/greynoise-connector",
        "is_installed": True,
        "is_verified": True,
        "rating": 4.8,
        "downloads_count": 980,
        "manifest": {
            "schema_version": "1.0",
            "name": "GreyNoise Internet Noise Analyzer",
            "slug": "greynoise-analyzer",
            "version": "1.1.0",
            "author": "Threat Research Labs",
            "category": "scanner",
            "permissions": ["network:outbound"],
            "allowed_domains": ["api.greynoise.io"],
            "timeout_seconds": 20,
            "entry_point": "greynoise_connector.GreyNoiseConnector",
        },
    },
    {
        "name": "AlienVault OTX Pulse Importer",
        "slug": "alienvault-otx-importer",
        "version": "2.0.1",
        "author": "Open Threat Exchange Team",
        "category": "threat_intel",
        "description": "Ingests community-submitted threat pulses containing adversary IOCs, hashes, domains, and targeted industries.",
        "repository_url": "https://github.com/cyber-osint-hub/alienvault-otx",
        "is_installed": False,
        "is_verified": True,
        "rating": 4.7,
        "downloads_count": 2150,
        "manifest": {
            "schema_version": "1.0",
            "name": "AlienVault OTX Pulse Importer",
            "slug": "alienvault-otx-importer",
            "version": "2.0.1",
            "author": "Open Threat Exchange Team",
            "category": "threat_intel",
            "permissions": ["network:outbound", "api_key:required"],
            "allowed_domains": ["otx.alienvault.com"],
            "timeout_seconds": 30,
            "entry_point": "otx_connector.OTXConnector",
        },
    },
    {
        "name": "AbuseIPDB Blacklist Synchronizer",
        "slug": "abuseipdb-blacklist-sync",
        "version": "1.0.4",
        "author": "Network Defense SIG",
        "category": "threat_intel",
        "description": "Periodically downloads and caches high-confidence abusive IP addresses actively engaged in brute-force attacks.",
        "repository_url": "https://github.com/cyber-osint-hub/abuseipdb-sync",
        "is_installed": False,
        "is_verified": True,
        "rating": 4.6,
        "downloads_count": 1640,
        "manifest": {
            "schema_version": "1.0",
            "name": "AbuseIPDB Blacklist Synchronizer",
            "slug": "abuseipdb-blacklist-sync",
            "version": "1.0.4",
            "author": "Network Defense SIG",
            "category": "threat_intel",
            "permissions": ["network:outbound"],
            "allowed_domains": ["api.abuseipdb.com"],
            "timeout_seconds": 15,
            "entry_point": "abuseipdb_connector.AbuseIPDBConnector",
        },
    },
    {
        "name": "VirusTotal v3 Intelligence Feed",
        "slug": "virustotal-v3-feed",
        "version": "1.3.2",
        "author": "Malware Analysts Group",
        "category": "malware",
        "description": "Extracts sample detonation telemetry, AV detection ratios, and sandbox behavior graphs from VirusTotal v3 API.",
        "repository_url": "https://github.com/cyber-osint-hub/virustotal-v3",
        "is_installed": False,
        "is_verified": True,
        "rating": 4.9,
        "downloads_count": 3400,
        "manifest": {
            "schema_version": "1.0",
            "name": "VirusTotal v3 Intelligence Feed",
            "slug": "virustotal-v3-feed",
            "version": "1.3.2",
            "author": "Malware Analysts Group",
            "category": "malware",
            "permissions": ["network:outbound", "api_key:required"],
            "allowed_domains": ["www.virustotal.com"],
            "timeout_seconds": 35,
            "entry_point": "vt_connector.VirusTotalConnector",
        },
    },
]


def seed_marketplace(db: Session) -> None:
    """Seeds default verified marketplace connectors if table is empty."""
    existing_count = db.query(MarketplaceConnectorModel).count()
    if existing_count > 0:
        return

    for item in INITIAL_MARKETPLACE_CONNECTORS:
        c = MarketplaceConnectorModel(
            name=item["name"],
            slug=item["slug"],
            version=item["version"],
            author=item["author"],
            category=item["category"],
            description=item["description"],
            repository_url=item["repository_url"],
            manifest_json=item["manifest"],
            is_installed=item["is_installed"],
            is_verified=item["is_verified"],
            rating=item["rating"],
            downloads_count=item["downloads_count"],
        )
        db.add(c)
    db.commit()


def validate_manifest(manifest_dict: Dict[str, Any]) -> ConnectorManifest:
    """Validates connector manifest format and security permissions."""
    manifest = ConnectorManifest(**manifest_dict)
    if not manifest.name or not manifest.slug:
        raise ValueError("Connector name and slug are required.")
    if not manifest.entry_point:
        raise ValueError("Entry point class must be defined in manifest.")
    return manifest


def list_marketplace_connectors(
    db: Session,
    category: Optional[str] = None,
    installed_only: bool = False,
    search: Optional[str] = None,
) -> List[MarketplaceConnectorOut]:
    """Lists marketplace connectors with filtering."""
    seed_marketplace(db)
    query = db.query(MarketplaceConnectorModel)
    if category:
        query = query.filter(MarketplaceConnectorModel.category == category)
    if installed_only:
        query = query.filter(MarketplaceConnectorModel.is_installed.is_(True))
    if search:
        s = f"%{search.lower()}%"
        query = query.filter(
            (MarketplaceConnectorModel.name.ilike(s))
            | (MarketplaceConnectorModel.description.ilike(s))
            | (MarketplaceConnectorModel.author.ilike(s))
        )
    items = query.order_by(MarketplaceConnectorModel.rating.desc()).all()
    return [_to_out(i) for i in items]


def get_connector_by_id(db: Session, connector_id: int) -> Optional[MarketplaceConnectorOut]:
    """Retrieves a single connector by ID."""
    seed_marketplace(db)
    item = db.query(MarketplaceConnectorModel).filter(MarketplaceConnectorModel.id == connector_id).first()
    return _to_out(item) if item else None


def toggle_install_connector(db: Session, connector_id: int, install: bool) -> Optional[MarketplaceConnectorOut]:
    """Installs or uninstalls a marketplace connector."""
    seed_marketplace(db)
    item = db.query(MarketplaceConnectorModel).filter(MarketplaceConnectorModel.id == connector_id).first()
    if not item:
        return None
    item.is_installed = install
    if install:
        item.downloads_count += 1
    db.commit()
    db.refresh(item)
    return _to_out(item)


def publish_connector(db: Session, req: MarketplacePublishRequest) -> MarketplaceConnectorOut:
    """Publishes a new community connector after manifest validation."""
    validate_manifest(req.manifest)
    slug = req.name.lower().replace(" ", "-").replace("_", "-")
    conn = MarketplaceConnectorModel(
        name=req.name,
        slug=slug,
        version=req.version,
        author=req.author,
        category=req.category,
        description=req.description,
        repository_url=req.repository_url,
        manifest_json=req.manifest,
        is_installed=False,
        is_verified=False,
        rating=5.0,
        downloads_count=1,
    )
    db.add(conn)
    db.commit()
    db.refresh(conn)
    return _to_out(conn)


def _to_out(item: MarketplaceConnectorModel) -> MarketplaceConnectorOut:
    return MarketplaceConnectorOut(
        id=item.id,
        name=item.name,
        slug=item.slug,
        version=item.version,
        author=item.author,
        category=item.category,
        description=item.description,
        repository_url=item.repository_url,
        manifest=item.manifest_json or {},
        is_installed=item.is_installed,
        is_verified=item.is_verified,
        rating=item.rating,
        downloads_count=item.downloads_count,
        created_at=item.created_at.isoformat() if item.created_at else None,
    )
