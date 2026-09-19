"""Campaign Tracking Service.

Conforms to Section 48 (Step 47) Version 3 specification:
  - Coordinated malicious threat campaigns tracking
  - Attributed actors, targeted sectors and countries
  - Exploited CVEs, deployed malware, and active periods
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.models.intelligence import CampaignModel
from app.schemas.intelligence import CampaignCreate

logger = logging.getLogger("cyber_osint.services.campaigns")

CURATED_CAMPAIGNS: List[Dict[str, Any]] = [
    {
        "name": "Volt Typhoon Critical Infrastructure Intrusion",
        "actor_name": "Volt Typhoon",
        "status": "active",
        "start_date": datetime(2023, 5, 1, tzinfo=timezone.utc),
        "end_date": None,
        "target_sectors": ["Critical Infrastructure", "Telecommunications", "Energy", "Water Systems", "Transportation"],
        "target_countries": ["United States", "Guam"],
        "malware_used": ["KV-botnet", "Fast Reverse Proxy"],
        "cves_exploited": ["CVE-2024-3400", "CVE-2023-46805", "CVE-2024-21887"],
        "description": "Widespread campaign targeting SOHO routers and edge network appliances to establish stealthy pre-positioned access into US critical infrastructure utilities.",
        "confidence_score": 0.95,
    },
    {
        "name": "Midnight Blizzard Cloud Identity Campaign",
        "actor_name": "APT29",
        "status": "active",
        "start_date": datetime(2023, 11, 1, tzinfo=timezone.utc),
        "end_date": None,
        "target_sectors": ["Technology", "Government", "Defense"],
        "target_countries": ["United States", "United Kingdom"],
        "malware_used": ["MagicWeb", "EnvyScout"],
        "cves_exploited": ["CVE-2023-42793"],
        "description": "Password-spraying and OAuth token manipulation campaign against corporate email environments and cloud management consoles.",
        "confidence_score": 0.92,
    },
    {
        "name": "LockBit 3.0 Global Extortion Wave",
        "actor_name": "LockBit",
        "status": "active",
        "start_date": datetime(2022, 6, 1, tzinfo=timezone.utc),
        "end_date": None,
        "target_sectors": ["Healthcare", "Manufacturing", "Finance", "Municipalities"],
        "target_countries": ["United States", "Germany", "United Kingdom", "France", "Japan"],
        "malware_used": ["LockBit 3.0", "StealBit"],
        "cves_exploited": ["CVE-2023-4966", "CVE-2023-0669"],
        "description": "Mass automated initial access broker exploitation targeting edge VPN gateways followed by rapid multithreaded double extortion ransomware deployment.",
        "confidence_score": 0.96,
    },
]


class CampaignService:
    """Manages Threat Campaign lifecycle, queries, and correlation."""

    def seed_initial_campaigns(self, db: Session) -> int:
        """Seeds curated baseline campaigns."""
        seeded = 0
        for item in CURATED_CAMPAIGNS:
            existing = db.query(CampaignModel).filter(CampaignModel.name == item["name"]).first()
            if not existing:
                camp = CampaignModel(
                    name=item["name"],
                    actor_name=item["actor_name"],
                    status=item["status"],
                    start_date=item["start_date"],
                    end_date=item["end_date"],
                    target_sectors=item["target_sectors"],
                    target_countries=item["target_countries"],
                    malware_used=item["malware_used"],
                    cves_exploited=item["cves_exploited"],
                    description=item["description"],
                    confidence_score=item["confidence_score"],
                )
                db.add(camp)
                seeded += 1
        if seeded > 0:
            db.commit()
            logger.info("Seeded %d curated campaigns", seeded)
        return seeded

    def list_campaigns(
        self,
        db: Session,
        status: Optional[str] = None,
        actor_name: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        skip: int = 0,
    ) -> List[CampaignModel]:
        """Lists threat campaigns with filters and keyword matching."""
        self.seed_initial_campaigns(db)
        query = db.query(CampaignModel)

        if status:
            query = query.filter(CampaignModel.status == status)
        if actor_name:
            query = query.filter(CampaignModel.actor_name.ilike(f"%{actor_name}%"))

        campaigns = query.order_by(CampaignModel.start_date.desc().nullslast()).all()

        if search:
            s = search.lower().strip()
            campaigns = [
                c for c in campaigns
                if s in f"{c.name} {c.actor_name or ''} {c.description or ''} {' '.join(c.malware_used or [])}".lower()
            ]

        return campaigns[skip : skip + limit]

    def get_campaign_by_id(self, db: Session, campaign_id: int) -> Optional[CampaignModel]:
        """Retrieves a campaign by ID."""
        self.seed_initial_campaigns(db)
        return db.query(CampaignModel).filter(CampaignModel.id == campaign_id).first()

    def create_campaign(self, db: Session, data: CampaignCreate) -> CampaignModel:
        """Registers a new campaign record."""
        camp = CampaignModel(**data.model_dump())
        db.add(camp)
        db.commit()
        db.refresh(camp)
        return camp


campaign_service = CampaignService()
