"""
Personalized Recommendation Service
Orchestrates user interaction tracking, profile preference state, multi-factor ranking, and topic discovery.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models.content import Content
from app.models.entity import ContentEntity, Entity
from app.models.recommendation import UserInteraction, UserProfile
from app.models.tag import ContentTag, Tag
from services.recommendation.difficulty import difficulty_classifier
from services.recommendation.models import (
    ContentTypeFilter,
    DifficultyLevel,
    PersonalizedFeedResponse,
    RecommendationItem,
    TopicRecommendation,
    UserProfileDTO,
)
from services.recommendation.scorer import recommendation_scorer
from services.recommendation.topic_graph import topic_graph


# Rich seed corpus ensuring comprehensive representation across all Section 31 content types
SEED_CANDIDATES: List[Dict[str, Any]] = [
    {
        "id": 1001,
        "title": "Kubernetes Security: Hardening Clusters and Mitigating Node Breaches",
        "description": "Comprehensive guide to cluster hardening, pod security admission standards, and control plane isolation.",
        "summary": "Covers RBAC hardening, mTLS between microservices, network policies, and runtime defense.",
        "content_type": "article",
        "category": "cloud_security",
        "difficulty_level": "intermediate",
        "source": "CISA Cloud Division",
        "canonical_url": "https://www.cisa.gov/resources-tools/k8s-hardening-guidance",
        "author": "Kubernetes SIG Security",
        "published_at": "2024-05-10T10:00:00Z",
        "quality_score": 0.96,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["kubernetes security", "cloud security", "k8s", "rbac", "hardening"],
        "entities": ["Kubernetes", "Docker", "Linux", "CNCF"],
    },
    {
        "id": 1002,
        "title": "Container Security: Image Vulnerability Scanning and CI/CD Guardrails",
        "description": "Strategies for enforcing zero-trust container pipelines, static vulnerability detection, and attestation.",
        "summary": "Best practices for container base image minimization, distroless builds, and SBOM generation.",
        "content_type": "article",
        "category": "container_security",
        "difficulty_level": "intermediate",
        "source": "Red Hat Security",
        "canonical_url": "https://access.redhat.com/articles/container-security-guide",
        "author": "Red Hat Research",
        "published_at": "2024-05-15T14:30:00Z",
        "quality_score": 0.94,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["container security", "docker", "sbom", "cve", "image-scanning"],
        "entities": ["Docker", "Kubernetes", "Red Hat", "Trivy"],
    },
    {
        "id": 1003,
        "title": "Docker Security Best Practices: Daemon Hardening and Rootless Execution",
        "description": "In-depth guide for eliminating root privileges in production Docker environments.",
        "summary": "Configuring userns-remap, seccomp profiles, AppArmor sandboxing, and minimal Linux capabilities.",
        "content_type": "article",
        "category": "container_security",
        "difficulty_level": "intermediate",
        "source": "Docker Security Advisories",
        "canonical_url": "https://docs.docker.com/engine/security/",
        "author": "Docker Security Team",
        "published_at": "2024-05-12T09:00:00Z",
        "quality_score": 0.92,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["docker security", "container security", "seccomp", "apparmor", "rootless"],
        "entities": ["Docker", "Linux", "AppArmor"],
    },
    {
        "id": 1004,
        "title": "Cloud Security Posture Management: Multi-Cloud IAM and Threat Telemetry",
        "description": "Architecting resilient cross-cloud identity perimeter and continuous compliance audits.",
        "summary": "Automated discovery of misconfigured S3 buckets, IAM privilege escalation vectors, and lateral egress.",
        "content_type": "article",
        "category": "cloud_security",
        "difficulty_level": "intermediate",
        "source": "AWS Security Blogs",
        "canonical_url": "https://aws.amazon.com/blogs/security/cloud-security-posture/",
        "author": "AWS Threat Intelligence",
        "published_at": "2024-05-18T16:00:00Z",
        "quality_score": 0.90,
        "quality_tier": "TIER_2_HIGH",
        "tags": ["cloud security", "iam", "aws", "cspm", "compliance"],
        "entities": ["AWS", "Azure", "GCP", "Kubernetes"],
    },
    {
        "id": 1005,
        "title": "Kubernetes Threat Detection via eBPF and Behavioral Anomaly Sensors",
        "description": "Real-time threat monitoring inside container runtimes utilizing kernel eBPF probes.",
        "summary": "Deploying Falco and Tetragon rules to detect unauthorized binary execution, container breakouts, and socket hooks.",
        "content_type": "research",
        "category": "threat_detection",
        "difficulty_level": "advanced",
        "source": "USENIX Security Proceedings",
        "canonical_url": "https://www.usenix.org/conference/usenixsecurity24/presentation/ebpf-k8s",
        "author": "Dr. Sarah Lin, Systems Lab",
        "published_at": "2024-05-20T11:00:00Z",
        "quality_score": 0.98,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["kubernetes threat detection", "ebpf", "runtime security", "falco", "anomaly detection"],
        "entities": ["Kubernetes", "Linux Kernel", "Falco", "eBPF"],
    },
    {
        "id": 1006,
        "title": "Runtime Security in Cloud-Native Environments: Intercepting Container Escapes",
        "description": "Deep-dive analysis into container breakout primitives (CVE-2024-21626) and runtime protection.",
        "summary": "Explains runc file descriptor leaks, kernel namespace evasion, and mitigation using gVisor and Kata Containers.",
        "content_type": "research",
        "category": "runtime_security",
        "difficulty_level": "expert",
        "source": "Google Zero Day Project",
        "canonical_url": "https://googleprojectzero.blogspot.com/2024/04/runc-container-escapes.html",
        "author": "Jann Horn",
        "published_at": "2024-04-28T13:15:00Z",
        "quality_score": 0.99,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["runtime security", "container escape", "runc", "cve-2024-21626", "kernel security"],
        "entities": ["runc", "Docker", "Linux Kernel", "CVE-2024-21626"],
    },
    {
        "id": 1007,
        "title": "Hands-On Video: Hunting Threats in Kubernetes Clusters with Open Source Tools",
        "description": "Interactive walk-through demonstrating live detection of anomalous cryptomining pods.",
        "summary": "Live demo of kube-bench, Trivy operator, and Falco alert streaming into SIEM.",
        "content_type": "video",
        "category": "cloud_security",
        "difficulty_level": "beginner",
        "source": "Cyber In-Depth Video Channel",
        "canonical_url": "https://youtube.com/watch?v=k8s_threat_hunt",
        "author": "Alex Reed, Threat Hunter",
        "published_at": "2024-05-25T18:00:00Z",
        "quality_score": 0.88,
        "quality_tier": "TIER_2_HIGH",
        "tags": ["kubernetes security", "video", "tutorial", "threat hunting", "falco"],
        "entities": ["Kubernetes", "Falco", "Trivy"],
    },
    {
        "id": 1008,
        "title": "KubeArmor: Cloud-Native Runtime Security Enforcement Engine",
        "description": "Open-source tool leveraging LSM (eBPF, AppArmor, SELinux) to restrict pod attack surface.",
        "summary": "Defines declarative security policies for blocking untrusted package managers and unauthorized file writes.",
        "content_type": "tool",
        "category": "security_tooling",
        "difficulty_level": "intermediate",
        "source": "CNCF Sandbox",
        "canonical_url": "https://github.com/kubearmor/KubeArmor",
        "author": "KubeArmor Maintainers",
        "published_at": "2024-05-01T12:00:00Z",
        "quality_score": 0.95,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["tool", "kubearmor", "runtime security", "kubernetes security", "lsm"],
        "entities": ["Kubernetes", "AppArmor", "SELinux", "eBPF"],
    },
    {
        "id": 1009,
        "title": "Certified Kubernetes Security Specialist (CKS) Complete Roadmap",
        "description": "Structured curriculum covering cluster setup, cluster hardening, system hardening, and monitoring.",
        "summary": "Hands-on labs for CIS benchmarks, secret management, image scanning, and immutable pods.",
        "content_type": "course",
        "category": "education",
        "difficulty_level": "intermediate",
        "source": "Linux Foundation Training",
        "canonical_url": "https://training.linuxfoundation.org/certification/certified-kubernetes-security-specialist/",
        "author": "Linux Foundation Education",
        "published_at": "2024-04-10T10:00:00Z",
        "quality_score": 0.97,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["course", "kubernetes security", "certification", "cks", "hardening"],
        "entities": ["Linux Foundation", "CNCF", "Kubernetes"],
    },
    {
        "id": 1010,
        "title": "Whitepaper: NIST SP 800-190 Application Container Security Guide",
        "description": "Official US government reference document specifying container technology architecture and threat landscape.",
        "summary": "Detailed security guidance covering image threats, registry threats, orchestrator threats, and container threats.",
        "content_type": "document",
        "category": "standards",
        "difficulty_level": "advanced",
        "source": "NIST Computer Security Division",
        "canonical_url": "https://csrc.nist.gov/publications/detail/sp/800-190/final",
        "author": "Murugiah Souppaya, John Morello",
        "published_at": "2024-03-15T12:00:00Z",
        "quality_score": 0.99,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["document", "nist", "standards", "container security", "compliance"],
        "entities": ["NIST", "Docker", "Kubernetes"],
    },
    {
        "id": 1011,
        "title": "LockBit 3.0 Encryptor Analysis and Cryptographic Flaws",
        "description": "Technical disassembly of LockBit Black payload, AES key scheduling, and mitigation options.",
        "summary": "Deep reverse engineering of anti-analysis tricks, shadow copy deletion, and recovery feasibility.",
        "content_type": "research",
        "category": "malware_analysis",
        "difficulty_level": "expert",
        "source": "Mandiant Threat Research",
        "canonical_url": "https://www.mandiant.com/resources/blog/lockbit-reverse-engineering",
        "author": "Mandiant FLARE Team",
        "published_at": "2024-05-08T15:00:00Z",
        "quality_score": 0.96,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["ransomware", "malware analysis", "reverse engineering", "lockbit", "threat actor"],
        "entities": ["LockBit", "Mandiant", "Windows"],
    },
    {
        "id": 1012,
        "title": "Critical RCE Flaw in Enterprise Gateway Appliances (CVE-2024-3400)",
        "description": "Command injection flaw in PAN-OS GlobalProtect feature permits unauthenticated remote code execution.",
        "summary": "Nation-state actors observed actively deploying backdoor webshells via unpatched edge devices.",
        "content_type": "article",
        "category": "vulnerability_management",
        "difficulty_level": "advanced",
        "source": "CISA Cybersecurity Alerts",
        "canonical_url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
        "author": "CISA Hunt Team",
        "published_at": "2024-04-14T12:00:00Z",
        "quality_score": 1.0,
        "quality_tier": "TIER_1_AUTHORITATIVE",
        "tags": ["cve", "zero-day", "pan-os", "command-injection", "cisa-kev"],
        "entities": ["Palo Alto Networks", "CVE-2024-3400", "CISA"],
    },
]


class RecommendationService:
    """
    Unified Personalized Recommendation Engine.
    Powers dashboard discoveries, related content suggestions, topic graph expansions, and bookmark management.
    """

    def __init__(self) -> None:
        # In-memory fast cache for quick lookup / fallback environments
        self._in_memory_profiles: Dict[str, Dict[str, Any]] = {}
        self._in_memory_interactions: List[Dict[str, Any]] = []

    def record_interaction(
        self,
        session_id: str,
        interaction_type: str,
        content_id: Optional[int] = None,
        search_query: Optional[str] = None,
        user_id: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        Records a user interaction event (view, save, unsave, search, click).
        """
        created_at_dt = datetime.now(timezone.utc)
        meta_str = json.dumps(metadata or {})

        # Record in memory
        event = {
            "session_id": session_id,
            "user_id": user_id,
            "content_id": content_id,
            "interaction_type": interaction_type,
            "search_query": search_query,
            "metadata": metadata or {},
            "created_at": created_at_dt.isoformat(),
        }
        self._in_memory_interactions.append(event)

        # Record in database if active
        if db:
            try:
                db_record = UserInteraction(
                    session_id=session_id,
                    user_id=user_id,
                    content_id=content_id,
                    interaction_type=interaction_type,
                    search_query=search_query,
                    metadata_json=meta_str,
                    created_at=created_at_dt,
                )
                db.add(db_record)
                db.commit()
                db.refresh(db_record)
                return db_record.to_dict()
            except Exception as ex:
                db.rollback()

        return event

    def get_or_create_profile(
        self,
        session_id: str,
        user_id: Optional[int] = None,
        db: Optional[Session] = None,
    ) -> UserProfileDTO:
        """
        Retrieves or initializes a user recommendation profile.
        """
        # 1. Check database
        if db:
            try:
                profile = db.query(UserProfile).filter(UserProfile.session_id == session_id).first()
                if profile:
                    saved_count = (
                        db.query(UserInteraction)
                        .filter(
                            UserInteraction.session_id == session_id,
                            UserInteraction.interaction_type == "save",
                        )
                        .count()
                    )
                    viewed_count = (
                        db.query(UserInteraction)
                        .filter(
                            UserInteraction.session_id == session_id,
                            UserInteraction.interaction_type == "view",
                        )
                        .count()
                    )
                    search_count = (
                        db.query(UserInteraction)
                        .filter(
                            UserInteraction.session_id == session_id,
                            UserInteraction.interaction_type == "search",
                        )
                        .count()
                    )
                    return UserProfileDTO(
                        session_id=profile.session_id,
                        user_id=profile.user_id,
                        interests=profile.interests,
                        difficulty_level=profile.difficulty_level,
                        preferred_types=profile.preferred_types,
                        saved_count=saved_count,
                        viewed_count=viewed_count,
                        search_count=search_count,
                    )
                else:
                    # Create default profile in DB
                    default_interests = ["Kubernetes Security", "Cloud Security", "Zero-Day Vulnerabilities"]
                    default_types = ["article", "video", "research", "tool", "course", "document"]
                    new_profile = UserProfile(
                        session_id=session_id,
                        user_id=user_id,
                        difficulty_level=DifficultyLevel.INTERMEDIATE.value,
                    )
                    new_profile.interests = default_interests
                    new_profile.preferred_types = default_types
                    db.add(new_profile)
                    db.commit()
                    db.refresh(new_profile)
                    return UserProfileDTO(
                        session_id=new_profile.session_id,
                        user_id=new_profile.user_id,
                        interests=new_profile.interests,
                        difficulty_level=new_profile.difficulty_level,
                        preferred_types=new_profile.preferred_types,
                        saved_count=0,
                        viewed_count=0,
                        search_count=0,
                    )
            except Exception:
                db.rollback()

        # 2. In-memory fallback
        if session_id not in self._in_memory_profiles:
            self._in_memory_profiles[session_id] = {
                "session_id": session_id,
                "user_id": user_id,
                "interests": ["Kubernetes Security", "Cloud Security", "Zero-Day Vulnerabilities"],
                "difficulty_level": DifficultyLevel.INTERMEDIATE.value,
                "preferred_types": ["article", "video", "research", "tool", "course", "document"],
            }

        p = self._in_memory_profiles[session_id]
        saved_count = sum(
            1 for i in self._in_memory_interactions
            if i["session_id"] == session_id and i["interaction_type"] == "save"
        )
        viewed_count = sum(
            1 for i in self._in_memory_interactions
            if i["session_id"] == session_id and i["interaction_type"] == "view"
        )
        search_count = sum(
            1 for i in self._in_memory_interactions
            if i["session_id"] == session_id and i["interaction_type"] == "search"
        )

        return UserProfileDTO(
            session_id=p["session_id"],
            user_id=p["user_id"],
            interests=p["interests"],
            difficulty_level=p["difficulty_level"],
            preferred_types=p["preferred_types"],
            saved_count=saved_count,
            viewed_count=viewed_count,
            search_count=search_count,
        )

    def update_profile(
        self,
        session_id: str,
        interests: Optional[List[str]] = None,
        difficulty_level: Optional[str] = None,
        preferred_types: Optional[List[str]] = None,
        db: Optional[Session] = None,
    ) -> UserProfileDTO:
        """
        Updates profile parameters (interests, difficulty preference, delivery types).
        """
        if db:
            try:
                prof = db.query(UserProfile).filter(UserProfile.session_id == session_id).first()
                if not prof:
                    prof = UserProfile(session_id=session_id)
                    db.add(prof)
                if interests is not None:
                    prof.interests = interests
                if difficulty_level is not None:
                    prof.difficulty_level = difficulty_level
                if preferred_types is not None:
                    prof.preferred_types = preferred_types
                db.commit()
                db.refresh(prof)
                return self.get_or_create_profile(session_id, prof.user_id, db=db)
            except Exception:
                db.rollback()

        # In-memory
        p = self._in_memory_profiles.get(session_id, {
            "session_id": session_id,
            "user_id": None,
            "interests": [],
            "difficulty_level": DifficultyLevel.INTERMEDIATE.value,
            "preferred_types": [],
        })
        if interests is not None:
            p["interests"] = interests
        if difficulty_level is not None:
            p["difficulty_level"] = difficulty_level
        if preferred_types is not None:
            p["preferred_types"] = preferred_types
        self._in_memory_profiles[session_id] = p
        return self.get_or_create_profile(session_id)

    def get_related_topics(self, topic: str, limit: int = 5) -> List[TopicRecommendation]:
        """
        Retrieves semantic topic recommendations based on the topic correlation graph.
        """
        return topic_graph.get_related_topics(topic, limit=limit)

    def _get_user_history(
        self, session_id: str, db: Optional[Session] = None
    ) -> Tuple[Set[int], Set[str], Set[str], Set[int], Set[str], Set[str], List[str]]:
        """
        Collects saved content IDs, viewed content IDs, accumulated tags, entities, and search queries.
        """
        saved_ids: Set[int] = set()
        saved_tags: Set[str] = set()
        saved_entities: Set[str] = set()
        viewed_ids: Set[int] = set()
        viewed_tags: Set[str] = set()
        viewed_entities: Set[str] = set()
        search_queries: List[str] = []

        # From memory
        unsaved_ids: Set[int] = set()
        for inter in self._in_memory_interactions:
            if inter["session_id"] != session_id:
                continue
            itype = inter["interaction_type"]
            cid = inter.get("content_id")
            if itype == "save" and cid:
                saved_ids.add(cid)
            elif itype == "unsave" and cid:
                unsaved_ids.add(cid)
            elif itype == "view" and cid:
                viewed_ids.add(cid)
            elif itype == "search" and inter.get("search_query"):
                search_queries.append(inter["search_query"])
        saved_ids = saved_ids - unsaved_ids

        # From DB if available
        if db:
            try:
                interactions = (
                    db.query(UserInteraction)
                    .filter(UserInteraction.session_id == session_id)
                    .order_by(UserInteraction.created_at.desc())
                    .limit(200)
                    .all()
                )
                db_unsaved = set()
                for i in interactions:
                    if i.interaction_type == "save" and i.content_id:
                        if i.content_id not in db_unsaved:
                            saved_ids.add(i.content_id)
                    elif i.interaction_type == "unsave" and i.content_id:
                        db_unsaved.add(i.content_id)
                        saved_ids.discard(i.content_id)
                    elif i.interaction_type == "view" and i.content_id:
                        viewed_ids.add(i.content_id)
                    elif i.interaction_type == "search" and i.search_query:
                        if i.search_query not in search_queries:
                            search_queries.append(i.search_query)
            except Exception:
                pass

        # Populate tags & entities for saved/viewed items from SEED or DB
        for c in SEED_CANDIDATES:
            cid = c["id"]
            if cid in saved_ids:
                saved_tags.update(t.lower() for t in c.get("tags", []))
                saved_entities.update(e.lower() for e in c.get("entities", []))
            if cid in viewed_ids:
                viewed_tags.update(t.lower() for t in c.get("tags", []))
                viewed_entities.update(e.lower() for e in c.get("entities", []))

        return (
            saved_ids,
            saved_tags,
            saved_entities,
            viewed_ids,
            viewed_tags,
            viewed_entities,
            search_queries,
        )

    def _fetch_candidates(self, db: Optional[Session] = None) -> List[Dict[str, Any]]:
        """
        Fetches candidate items from the database, augmented with seed candidates for rich testing.
        """
        candidates: List[Dict[str, Any]] = list(SEED_CANDIDATES)

        if db:
            try:
                db_items = db.query(Content).order_by(Content.published_at.desc().nullslast()).limit(50).all()
                existing_ids = {c["id"] for c in candidates}
                for item in db_items:
                    if item.id not in existing_ids:
                        # Extract tags
                        tags = []
                        if hasattr(item, "content_tags"):
                            for ct in item.content_tags:
                                if ct.tag:
                                    tags.append(ct.tag.name)
                        # Extract entities
                        ents = []
                        if hasattr(item, "content_entities"):
                            for ce in item.content_entities:
                                if ce.entity:
                                    ents.append(ce.entity.name)

                        candidates.append({
                            "id": item.id,
                            "title": item.title,
                            "description": item.description,
                            "summary": item.summary,
                            "content_type": item.content_type,
                            "category": tags[0] if tags else "general_security",
                            "difficulty_level": None,
                            "source": item.source.name if item.source else "Cyber OSINT Source",
                            "canonical_url": item.canonical_url,
                            "author": item.author,
                            "published_at": item.published_at.isoformat() if item.published_at else None,
                            "quality_score": item.quality_score or 0.85,
                            "quality_tier": "TIER_2_HIGH",
                            "tags": tags,
                            "entities": ents,
                        })
            except Exception:
                pass

        return candidates

    def get_recommendations(
        self,
        session_id: str,
        content_type: Optional[str] = None,
        difficulty: Optional[str] = None,
        limit: int = 10,
        current_content_id: Optional[int] = None,
        db: Optional[Session] = None,
    ) -> PersonalizedFeedResponse:
        """
        Generates ranked recommendations filtered by content_type and difficulty level.
        """
        profile = self.get_or_create_profile(session_id, db=db)
        effective_difficulty = difficulty or profile.difficulty_level

        (
            saved_ids,
            saved_tags,
            saved_entities,
            viewed_ids,
            viewed_tags,
            viewed_entities,
            search_queries,
        ) = self._get_user_history(session_id, db=db)

        raw_candidates = self._fetch_candidates(db=db)

        # Filter by content type if specified
        if content_type and content_type.lower() != "all":
            target_type = content_type.lower()
            filtered_candidates = []
            for c in raw_candidates:
                c_type = c.get("content_type", "article").lower()
                if target_type == "articles" and c_type in ["article", "advisory", "cve"]:
                    filtered_candidates.append(c)
                elif target_type == "videos" and c_type == "video":
                    filtered_candidates.append(c)
                elif target_type == "research" and c_type in ["research", "paper", "report"]:
                    filtered_candidates.append(c)
                elif target_type == "tools" and c_type == "tool":
                    filtered_candidates.append(c)
                elif target_type == "courses" and c_type == "course":
                    filtered_candidates.append(c)
                elif target_type == "documents" and c_type == "document":
                    filtered_candidates.append(c)
                elif target_type == c_type:
                    filtered_candidates.append(c)
            candidates_to_score = filtered_candidates
        else:
            candidates_to_score = raw_candidates

        # Score candidates
        scored_items: List[RecommendationItem] = []
        for cand in candidates_to_score:
            rec_item = recommendation_scorer.score_candidate(
                candidate=cand,
                user_interests=profile.interests,
                user_difficulty=effective_difficulty,
                saved_ids=saved_ids,
                saved_tags=saved_tags,
                saved_entities=saved_entities,
                viewed_ids=viewed_ids,
                viewed_tags=viewed_tags,
                viewed_entities=viewed_entities,
                search_queries=search_queries,
                current_content_id=current_content_id,
            )
            # If explicit difficulty requested, filter or prioritize
            if difficulty and rec_item.difficulty_level.lower() != difficulty.lower():
                # Apply penalty rather than hard-dropping if pool is small
                rec_item.score = round(rec_item.score * 0.65, 4)

            scored_items.append(rec_item)

        # Rank by score descending
        scored_items.sort(key=lambda x: x.score, reverse=True)
        top_items = scored_items[:limit]

        # Generate suggested topics based on profile and top ranked items
        suggested_topics: List[TopicRecommendation] = []
        seed_topic = profile.interests[0] if profile.interests else "Kubernetes Security"
        suggested_topics = topic_graph.get_related_topics(seed_topic, limit=5)

        return PersonalizedFeedResponse(
            items=top_items,
            suggested_topics=suggested_topics,
            profile_summary=profile,
            total_matched=len(scored_items),
        )

    def get_saved_content(
        self, session_id: str, limit: int = 20, db: Optional[Session] = None
    ) -> List[RecommendationItem]:
        """
        Retrieves all explicitly saved/bookmarked items for this session.
        """
        saved_ids, _, _, _, _, _, _ = self._get_user_history(session_id, db=db)
        candidates = self._fetch_candidates(db=db)
        saved_candidates = [c for c in candidates if c["id"] in saved_ids]

        results = []
        for c in saved_candidates:
            rec = RecommendationItem(
                content_id=c["id"],
                title=c["title"],
                description=c.get("description"),
                summary=c.get("summary"),
                canonical_url=c["canonical_url"],
                content_type=c.get("content_type", "article"),
                category=c.get("category"),
                difficulty_level=c.get("difficulty_level") or "intermediate",
                score=1.0,
                match_reasons=["Saved in your library"],
                source=c.get("source", "OSINT Source"),
                author=c.get("author"),
                published_at=c.get("published_at"),
                tags=c.get("tags", []),
                entities=c.get("entities", []),
                is_saved=True,
                source_quality_tier=c.get("quality_tier", "TIER_1_AUTHORITATIVE"),
                source_quality_score=float(c.get("quality_score") or 0.95),
            )
            results.append(rec)
        return results[:limit]


recommendation_service = RecommendationService()
