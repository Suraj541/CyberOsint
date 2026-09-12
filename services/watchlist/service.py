"""
Watchlist Management Service
Orchestrates watchlists and watched items across 10 intelligence categories.
Conforms strictly to IMPLEMENT.md Section 32 (Step 31: Build Watchlists).
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.content import Content
from app.models.watchlist import Watchlist, WatchlistItem
from services.watchlist.matcher import watchlist_matcher
from services.watchlist.models import (
    MatchedContentItem,
    MatchedWatchlistItem,
    WatchlistCreateDTO,
    WatchlistDTO,
    WatchlistFeedResponse,
    WatchlistItemCreateDTO,
    WatchlistItemDTO,
    WatchlistItemType,
    WatchlistUpdateDTO,
)


# Default Seed Intelligence Candidates for Feed Testing & Fallback
SEED_CANDIDATE_POOL: List[Dict[str, Any]] = [
    {
        "id": 101,
        "title": "Critical RCE Flaw in Enterprise Gateway Appliances (CVE-2024-3400)",
        "description": "Command injection flaw in PAN-OS GlobalProtect feature permits unauthenticated remote code execution.",
        "summary": "Nation-state actors observed actively deploying backdoor webshells via unpatched edge devices.",
        "canonical_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
        "content_type": "advisory",
        "source": "CISA",
        "category": "vulnerability_management",
        "author": "CISA Threat Hunt Team",
        "published_at": "2024-04-14T12:00:00Z",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "tags": ["zeroday", "pan-os", "command-injection", "cisa-kev"],
        "entities": [
            {"entity_type": "cve", "name": "CVE-2024-3400"},
            {"entity_type": "vendor", "name": "Palo Alto Networks"},
            {"entity_type": "product", "name": "PAN-OS"},
            {"entity_type": "product", "name": "GlobalProtect"},
        ],
    },
    {
        "id": 102,
        "title": "LockBit 3.0 Ransomware Campaign Targets Critical Healthcare Infrastructure",
        "description": "Analysis of affiliate encryptor variants employing automated PsExec lateral movement.",
        "summary": "Ransomware group deploys novel obfuscated loaders and exfiltrates proprietary clinical records.",
        "canonical_url": "https://www.bleepingcomputer.com/news/security/lockbit-health-intel/",
        "content_type": "article",
        "source": "BleepingComputer",
        "category": "ransomware",
        "author": "Lawrence Abrams",
        "published_at": "2024-04-13T09:30:00Z",
        "severity": "HIGH",
        "cvss_score": 8.5,
        "tags": ["ransomware", "lockbit", "healthcare", "data-exfiltration"],
        "entities": [
            {"entity_type": "threat_actor", "name": "LockBit"},
            {"entity_type": "malware", "name": "LockBit 3.0"},
            {"entity_type": "technique", "name": "Data Exfiltration"},
        ],
    },
    {
        "id": 1001,
        "title": "Kubernetes Security: Hardening Clusters and Mitigating Node Breaches",
        "description": "Comprehensive guide to cluster hardening, pod security admission standards, and control plane isolation.",
        "summary": "Covers RBAC hardening, mTLS between microservices, network policies, and runtime defense.",
        "content_type": "article",
        "category": "cloud_security",
        "source": "CISA Cloud Division",
        "canonical_url": "https://www.cisa.gov/resources-tools/k8s-hardening-guidance",
        "author": "Kubernetes SIG Security",
        "published_at": "2024-05-10T10:00:00Z",
        "severity": "HIGH",
        "cvss_score": 8.0,
        "tags": ["kubernetes", "container security", "cloud security", "hardening"],
        "entities": [
            {"entity_type": "technology", "name": "Kubernetes"},
            {"entity_type": "technology", "name": "Docker"},
            {"entity_type": "tool", "name": "KubeArmor"},
            {"entity_type": "tool", "name": "Falco"},
        ],
    },
    {
        "id": 1005,
        "title": "Kubernetes Threat Detection via eBPF and Behavioral Anomaly Sensors",
        "description": "Real-time threat monitoring inside container runtimes utilizing kernel eBPF probes.",
        "summary": "Deploying Falco and Tetragon rules to detect unauthorized binary execution, container breakouts, and socket hooks.",
        "content_type": "research",
        "category": "threat_detection",
        "source": "USENIX Security Proceedings",
        "canonical_url": "https://www.usenix.org/conference/usenixsecurity24/presentation/ebpf-k8s",
        "author": "Dr. Sarah Lin",
        "published_at": "2024-05-20T11:00:00Z",
        "severity": "HIGH",
        "cvss_score": 8.2,
        "tags": ["kubernetes", "ebpf", "falco", "runtime security"],
        "entities": [
            {"entity_type": "technology", "name": "Kubernetes"},
            {"entity_type": "technology", "name": "eBPF"},
            {"entity_type": "tool", "name": "Falco"},
            {"entity_type": "researcher", "name": "Dr. Sarah Lin"},
        ],
    },
    {
        "id": 1006,
        "title": "Runtime Security in Cloud-Native Environments: Intercepting Container Escapes",
        "description": "Deep-dive analysis into container breakout primitives (CVE-2024-21626) and runtime protection.",
        "summary": "Explains runc file descriptor leaks, kernel namespace evasion, and mitigation using gVisor and Kata Containers.",
        "content_type": "research",
        "category": "runtime_security",
        "source": "Google Zero Day Project",
        "canonical_url": "https://googleprojectzero.blogspot.com/2024/04/runc-container-escapes.html",
        "author": "Jann Horn",
        "published_at": "2024-04-28T13:15:00Z",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "tags": ["container escape", "cve-2024-21626", "runc", "zero-day"],
        "entities": [
            {"entity_type": "cve", "name": "CVE-2024-21626"},
            {"entity_type": "product", "name": "runc"},
            {"entity_type": "researcher", "name": "Jann Horn"},
            {"entity_type": "technology", "name": "Linux Kernel"},
        ],
    },
]


class WatchlistService:
    """
    Core Watchlist Management Service.
    Handles watchlist lifecycles, watched target items, and matching feeds.
    """

    def __init__(self) -> None:
        self._in_memory_watchlists: Dict[int, Dict[str, Any]] = {}
        self._in_memory_items: Dict[int, Dict[str, Any]] = {}
        self._next_wl_id: int = 101
        self._next_item_id: int = 1001
        self._seeded_sessions: Set[str] = set()

    def _seed_defaults(self, session_id: str, db: Optional[Session] = None) -> None:
        """Seeds standard default watchlists for a new session."""
        # 1. Zero-Day & KEV Watchlist
        self.create_watchlist(
            session_id=session_id,
            name="Critical Zero-Days & KEV",
            description="Actively exploited zero-day vulnerabilities and critical edge perimeter threats.",
            notification_channel="in_app",
            items=[
                WatchlistItemCreateDTO(item_type=WatchlistItemType.CVE, item_value="CVE-2024-3400", severity_threshold="CRITICAL"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.VENDOR, item_value="Palo Alto Networks"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TOPIC, item_value="Zero-Day Vulnerabilities"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.KEYWORD, item_value="command injection"),
            ],
            db=db,
        )

        # 2. Kubernetes & Cloud Defense Watchlist
        self.create_watchlist(
            session_id=session_id,
            name="Kubernetes & Cloud Defense",
            description="Cloud-native orchestration security, container escapes, and runtime detection.",
            notification_channel="in_app",
            items=[
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TECHNOLOGY, item_value="Kubernetes"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.PRODUCT, item_value="PAN-OS"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TOOL, item_value="Falco"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TOOL, item_value="KubeArmor"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TOPIC, item_value="Container Security"),
            ],
            db=db,
        )

        # 3. Ransomware & Threat Actors Watchlist
        self.create_watchlist(
            session_id=session_id,
            name="Ransomware & Threat Actors",
            description="Extortion syndicates, novel encryptor payloads, and exfiltration campaigns.",
            notification_channel="in_app",
            items=[
                WatchlistItemCreateDTO(item_type=WatchlistItemType.THREAT_ACTOR, item_value="LockBit"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.MALWARE, item_value="LockBit 3.0"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.TOPIC, item_value="Ransomware"),
                WatchlistItemCreateDTO(item_type=WatchlistItemType.KEYWORD, item_value="data exfiltration"),
            ],
            db=db,
        )

    def create_watchlist(
        self,
        session_id: str,
        name: str,
        description: Optional[str] = None,
        notification_channel: str = "in_app",
        items: Optional[List[WatchlistItemCreateDTO]] = None,
        user_id: Optional[int] = None,
        db: Optional[Session] = None,
    ) -> WatchlistDTO:
        """Creates a new watchlist with optional initial monitored items."""
        now_str = datetime.now(timezone.utc).isoformat()

        if db:
            try:
                wl = Watchlist(
                    session_id=session_id,
                    user_id=user_id,
                    name=name,
                    description=description,
                    notification_channel=notification_channel,
                    is_active=True,
                )
                db.add(wl)
                db.flush()

                if items:
                    for it in items:
                        item_record = WatchlistItem(
                            watchlist_id=wl.id,
                            item_type=it.item_type.value if hasattr(it.item_type, "value") else str(it.item_type),
                            item_value=it.item_value,
                            severity_threshold=it.severity_threshold,
                            notify_on_match=it.notify_on_match,
                        )
                        db.add(item_record)

                db.commit()
                db.refresh(wl)
                return self.get_watchlist(wl.id, db=db)  # type: ignore
            except Exception:
                db.rollback()

        # In-memory creation
        wl_id = self._next_wl_id
        self._next_wl_id += 1

        created_items: List[WatchlistItemDTO] = []
        if items:
            for it in items:
                item_id = self._next_item_id
                self._next_item_id += 1
                itype_val = it.item_type.value if hasattr(it.item_type, "value") else str(it.item_type)
                item_dto = WatchlistItemDTO(
                    id=item_id,
                    watchlist_id=wl_id,
                    item_type=itype_val,
                    item_value=it.item_value,
                    severity_threshold=it.severity_threshold,
                    notify_on_match=it.notify_on_match,
                    created_at=now_str,
                )
                self._in_memory_items[item_id] = item_dto.model_dump()
                created_items.append(item_dto)

        wl_dto = WatchlistDTO(
            id=wl_id,
            session_id=session_id,
            user_id=user_id,
            name=name,
            description=description,
            is_active=True,
            notification_channel=notification_channel,
            item_count=len(created_items),
            items=created_items,
            created_at=now_str,
            updated_at=now_str,
        )
        self._in_memory_watchlists[wl_id] = wl_dto.model_dump()
        return wl_dto

    def get_watchlist(self, watchlist_id: int, db: Optional[Session] = None) -> Optional[WatchlistDTO]:
        """Retrieves a single watchlist by ID."""
        if db:
            try:
                wl = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
                if wl:
                    items_dto = [
                        WatchlistItemDTO(
                            id=it.id,
                            watchlist_id=it.watchlist_id,
                            item_type=it.item_type,
                            item_value=it.item_value,
                            severity_threshold=it.severity_threshold,
                            notify_on_match=it.notify_on_match,
                            created_at=it.created_at.isoformat() if it.created_at else None,
                        )
                        for it in wl.items
                    ]
                    return WatchlistDTO(
                        id=wl.id,
                        session_id=wl.session_id,
                        user_id=wl.user_id,
                        name=wl.name,
                        description=wl.description,
                        is_active=wl.is_active,
                        notification_channel=wl.notification_channel,
                        item_count=len(items_dto),
                        items=items_dto,
                        created_at=wl.created_at.isoformat() if wl.created_at else None,
                        updated_at=wl.updated_at.isoformat() if wl.updated_at else None,
                    )
            except Exception:
                pass

        # In-memory
        if watchlist_id in self._in_memory_watchlists:
            d = self._in_memory_watchlists[watchlist_id]
            # Refresh items
            matching_items = [
                WatchlistItemDTO(**it)
                for it in self._in_memory_items.values()
                if it["watchlist_id"] == watchlist_id
            ]
            d["items"] = matching_items
            d["item_count"] = len(matching_items)
            return WatchlistDTO(**d)

        return None

    def list_watchlists(self, session_id: str, db: Optional[Session] = None) -> List[WatchlistDTO]:
        """Lists all watchlists for a session/user."""
        results: List[WatchlistDTO] = []

        if db:
            try:
                records = (
                    db.query(Watchlist)
                    .filter(Watchlist.session_id == session_id)
                    .order_by(Watchlist.created_at.desc())
                    .all()
                )
                for wl in records:
                    items_dto = [
                        WatchlistItemDTO(
                            id=it.id,
                            watchlist_id=it.watchlist_id,
                            item_type=it.item_type,
                            item_value=it.item_value,
                            severity_threshold=it.severity_threshold,
                            notify_on_match=it.notify_on_match,
                            created_at=it.created_at.isoformat() if it.created_at else None,
                        )
                        for it in wl.items
                    ]
                    results.append(
                        WatchlistDTO(
                            id=wl.id,
                            session_id=wl.session_id,
                            user_id=wl.user_id,
                            name=wl.name,
                            description=wl.description,
                            is_active=wl.is_active,
                            notification_channel=wl.notification_channel,
                            item_count=len(items_dto),
                            items=items_dto,
                            created_at=wl.created_at.isoformat() if wl.created_at else None,
                            updated_at=wl.updated_at.isoformat() if wl.updated_at else None,
                        )
                    )
                if results:
                    return results
            except Exception:
                pass

        # In-memory
        for wl_id, d in self._in_memory_watchlists.items():
            if d.get("session_id") == session_id:
                matching_items = [
                    WatchlistItemDTO(**it)
                    for it in self._in_memory_items.values()
                    if it["watchlist_id"] == wl_id
                ]
                d["items"] = matching_items
                d["item_count"] = len(matching_items)
                results.append(WatchlistDTO(**d))

        if not results and session_id not in self._seeded_sessions:
            self._seeded_sessions.add(session_id)
            self._seed_defaults(session_id, db=db)
            return self.list_watchlists(session_id, db=db)

        return results

    def update_watchlist(
        self,
        watchlist_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None,
        notification_channel: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> Optional[WatchlistDTO]:
        """Updates watchlist metadata."""
        if db:
            try:
                wl = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
                if wl:
                    if name is not None:
                        wl.name = name
                    if description is not None:
                        wl.description = description
                    if is_active is not None:
                        wl.is_active = is_active
                    if notification_channel is not None:
                        wl.notification_channel = notification_channel
                    db.commit()
                    db.refresh(wl)
                    return self.get_watchlist(wl.id, db=db)
            except Exception:
                db.rollback()

        if watchlist_id in self._in_memory_watchlists:
            d = self._in_memory_watchlists[watchlist_id]
            if name is not None:
                d["name"] = name
            if description is not None:
                d["description"] = description
            if is_active is not None:
                d["is_active"] = is_active
            if notification_channel is not None:
                d["notification_channel"] = notification_channel
            d["updated_at"] = datetime.now(timezone.utc).isoformat()
            return self.get_watchlist(watchlist_id)

        return None

    def delete_watchlist(self, watchlist_id: int, db: Optional[Session] = None) -> bool:
        """Deletes a watchlist and all child items."""
        if db:
            try:
                wl = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
                if wl:
                    db.delete(wl)
                    db.commit()
                    return True
            except Exception:
                db.rollback()

        if watchlist_id in self._in_memory_watchlists:
            del self._in_memory_watchlists[watchlist_id]
            # Delete items
            to_del = [iid for iid, it in self._in_memory_items.items() if it["watchlist_id"] == watchlist_id]
            for iid in to_del:
                del self._in_memory_items[iid]
            return True

        return False

    def add_item(
        self,
        watchlist_id: int,
        item_type: str,
        item_value: str,
        severity_threshold: Optional[str] = None,
        notify_on_match: bool = True,
        db: Optional[Session] = None,
    ) -> Optional[WatchlistItemDTO]:
        """Adds a monitored item to a watchlist."""
        now_str = datetime.now(timezone.utc).isoformat()

        if db:
            try:
                wl = db.query(Watchlist).filter(Watchlist.id == watchlist_id).first()
                if not wl:
                    return None
                rec = WatchlistItem(
                    watchlist_id=watchlist_id,
                    item_type=item_type.lower(),
                    item_value=item_value.strip(),
                    severity_threshold=severity_threshold,
                    notify_on_match=notify_on_match,
                )
                db.add(rec)
                db.commit()
                db.refresh(rec)
                return WatchlistItemDTO(
                    id=rec.id,
                    watchlist_id=rec.watchlist_id,
                    item_type=rec.item_type,
                    item_value=rec.item_value,
                    severity_threshold=rec.severity_threshold,
                    notify_on_match=rec.notify_on_match,
                    created_at=rec.created_at.isoformat() if rec.created_at else now_str,
                )
            except Exception:
                db.rollback()

        if watchlist_id not in self._in_memory_watchlists:
            return None

        iid = self._next_item_id
        self._next_item_id += 1
        dto = WatchlistItemDTO(
            id=iid,
            watchlist_id=watchlist_id,
            item_type=item_type.lower(),
            item_value=item_value.strip(),
            severity_threshold=severity_threshold,
            notify_on_match=notify_on_match,
            created_at=now_str,
        )
        self._in_memory_items[iid] = dto.model_dump()
        return dto

    def remove_item(self, item_id: int, db: Optional[Session] = None) -> bool:
        """Removes an item from a watchlist."""
        if db:
            try:
                rec = db.query(WatchlistItem).filter(WatchlistItem.id == item_id).first()
                if rec:
                    db.delete(rec)
                    db.commit()
                    return True
            except Exception:
                db.rollback()

        if item_id in self._in_memory_items:
            del self._in_memory_items[item_id]
            return True

        return False

    def match_content_dict(
        self,
        content_dict: Dict[str, Any],
        watchlist_id: Optional[int] = None,
        db: Optional[Session] = None,
    ) -> List[MatchedWatchlistItem]:
        """Evaluates a content item dictionary against watchlists."""
        hits: List[MatchedWatchlistItem] = []

        if watchlist_id:
            wl = self.get_watchlist(watchlist_id, db=db)
            if wl and wl.is_active:
                hits.extend(watchlist_matcher.match_all(wl.items, content_dict, wl.name))
        else:
            # Match against all known active watchlists
            # We fetch all from memory or DB
            all_wls = list(self._in_memory_watchlists.values())
            for wd in all_wls:
                if wd.get("is_active"):
                    items = [
                        WatchlistItemDTO(**it)
                        for it in self._in_memory_items.values()
                        if it["watchlist_id"] == wd["id"]
                    ]
                    hits.extend(watchlist_matcher.match_all(items, content_dict, wd["name"]))

        return hits

    def get_watchlist_feed(
        self,
        watchlist_id: int,
        limit: int = 20,
        db: Optional[Session] = None,
    ) -> WatchlistFeedResponse:
        """
        Retrieves all intelligence articles matching the watched items of a specific watchlist.
        """
        wl = self.get_watchlist(watchlist_id, db=db)
        if not wl:
            return WatchlistFeedResponse(
                watchlist_id=watchlist_id,
                watchlist_name="Unknown Watchlist",
                total_matches=0,
                items=[],
            )

        # Candidates from DB and Seed
        candidates = list(SEED_CANDIDATE_POOL)
        if db:
            try:
                db_items = db.query(Content).order_by(Content.published_at.desc().nullslast()).limit(40).all()
                existing_ids = {c["id"] for c in candidates}
                for it in db_items:
                    if it.id not in existing_ids:
                        ents = []
                        if hasattr(it, "content_entities"):
                            for ce in it.content_entities:
                                if ce.entity:
                                    ents.append({"name": ce.entity.name, "entity_type": ce.entity.entity_type})
                        tags = [ct.tag.name for ct in getattr(it, "content_tags", []) if ct.tag]
                        candidates.append({
                            "id": it.id,
                            "title": it.title,
                            "description": it.description,
                            "summary": it.summary,
                            "canonical_url": it.canonical_url,
                            "content_type": it.content_type,
                            "source": it.source.name if it.source else "OSINT Source",
                            "published_at": it.published_at.isoformat() if it.published_at else None,
                            "severity": "HIGH",
                            "tags": tags,
                            "entities": ents,
                        })
            except Exception:
                pass

        matched_items: List[MatchedContentItem] = []
        for c in candidates:
            item_hits = watchlist_matcher.match_all(wl.items, c, wl.name)
            if item_hits:
                matched_items.append(
                    MatchedContentItem(
                        content_id=c["id"],
                        title=c["title"],
                        description=c.get("description"),
                        summary=c.get("summary"),
                        canonical_url=c["canonical_url"],
                        content_type=c.get("content_type", "article"),
                        source=c.get("source", "OSINT"),
                        published_at=c.get("published_at"),
                        severity=c.get("severity"),
                        cvss_score=c.get("cvss_score"),
                        matched_items=item_hits,
                        match_score=round(min(len(item_hits) * 0.4 + 0.6, 1.0), 2),
                    )
                )

        matched_items.sort(key=lambda x: x.match_score, reverse=True)
        return WatchlistFeedResponse(
            watchlist_id=wl.id,
            watchlist_name=wl.name,
            total_matches=len(matched_items),
            items=matched_items[:limit],
        )


watchlist_service = WatchlistService()
