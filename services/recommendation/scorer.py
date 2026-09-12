"""
Recommendation Multi-Factor Scorer
Combines 7 inputs: Interests, Saved, Searches, Viewed History, Categories, Entities, and Difficulty.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

import math
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from services.recommendation.difficulty import difficulty_classifier
from services.recommendation.models import RecommendationItem
from services.recommendation.topic_graph import topic_graph


class RecommendationScorer:
    """
    Multi-Factor Recommendation Scorer.
    Calculates unified relevance score across interests, bookmarks, history, entities, and difficulty.
    """

    # Multi-factor weights
    WEIGHT_TOPIC = 0.25
    WEIGHT_SAVED = 0.18
    WEIGHT_SEARCH = 0.15
    WEIGHT_VIEWED = 0.12
    WEIGHT_ENTITY = 0.10
    WEIGHT_DIFFICULTY = 0.10
    WEIGHT_QUALITY = 0.05
    WEIGHT_RECENCY = 0.05

    def __init__(self) -> None:
        pass

    def score_candidate(
        self,
        candidate: Dict[str, Any],
        user_interests: List[str],
        user_difficulty: str,
        saved_ids: Set[int],
        saved_tags: Set[str],
        saved_entities: Set[str],
        viewed_ids: Set[int],
        viewed_tags: Set[str],
        viewed_entities: Set[str],
        search_queries: List[str],
        current_content_id: Optional[int] = None,
    ) -> RecommendationItem:
        """
        Calculates composite recommendation score and produces explanatory match reasons.
        """
        cid = candidate["id"]
        title = candidate.get("title", "")
        description = candidate.get("description", "") or ""
        summary = candidate.get("summary", "") or ""
        content_type = candidate.get("content_type", "article")
        category = candidate.get("category", "") or ""
        tags = [t.lower() for t in candidate.get("tags", [])]
        entities = [e.lower() for e in candidate.get("entities", [])]
        source_name = candidate.get("source", "OSINT Source")
        canonical_url = candidate.get("canonical_url", "")
        author = candidate.get("author")
        published_at_str = candidate.get("published_at")
        quality_score = float(candidate.get("quality_score") or 0.75)
        quality_tier = candidate.get("quality_tier", "TIER_2_HIGH")

        full_text = f"{title} {description} {summary} {category} {' '.join(tags)} {' '.join(entities)}".lower()

        match_reasons: List[str] = []

        # 1. Interests & Topic Graph Expansion Score (0.0 to 1.0)
        s_topic = 0.0
        expanded_interest_weights = topic_graph.expand_topic_weights(user_interests)
        matched_interests = []
        for topic_name, weight in expanded_interest_weights.items():
            t_clean = topic_name.lower()
            if t_clean in full_text or any(t_clean in tag for tag in tags):
                score_gain = weight * 0.5
                s_topic += score_gain
                matched_interests.append(topic_name)
        s_topic = min(s_topic, 1.0)

        if matched_interests:
            match_reasons.append(f"Matches interest: {matched_interests[0]}")

        # 2. Saved Content Affinity Score (0.0 to 1.0)
        s_saved = 0.0
        is_saved = cid in saved_ids
        if is_saved:
            s_saved = 1.0
            match_reasons.append("Saved in your library")
        else:
            overlap_tags = saved_tags.intersection(set(tags))
            overlap_ents = saved_entities.intersection(set(entities))
            if overlap_tags or overlap_ents:
                s_saved = min(len(overlap_tags) * 0.35 + len(overlap_ents) * 0.25, 1.0)
                match_reasons.append("Similar to your saved content")

        # 3. Search History Relevance Score (0.0 to 1.0)
        s_search = 0.0
        for q in search_queries[-5:]:
            q_clean = q.strip().lower()
            if q_clean and (q_clean in full_text or q_clean in title.lower()):
                s_search = max(s_search, 0.90)
                match_reasons.append(f"Matches search: '{q[:24]}'")
                break
            elif q_clean:
                q_words = [w for w in q_clean.split() if len(w) > 2]
                overlap = sum(1 for w in q_words if w in full_text)
                if overlap > 0:
                    score_part = overlap / max(len(q_words), 1)
                    s_search = max(s_search, score_part * 0.70)

        # 4. Viewed History Affinity Score (0.0 to 1.0)
        s_viewed = 0.0
        overlap_viewed_tags = viewed_tags.intersection(set(tags))
        overlap_viewed_ents = viewed_entities.intersection(set(entities))
        if overlap_viewed_tags or overlap_viewed_ents:
            s_viewed = min(len(overlap_viewed_tags) * 0.25 + len(overlap_viewed_ents) * 0.20, 1.0)
            if not matched_interests and overlap_viewed_tags:
                match_reasons.append(f"Related to recent views (#{list(overlap_viewed_tags)[0]})")

        # 5. Entity Overlap Score (0.0 to 1.0)
        s_entity = 0.0
        combined_profile_ents = saved_entities.union(viewed_entities)
        overlap_all_ents = combined_profile_ents.intersection(set(entities))
        if overlap_all_ents:
            s_entity = min(len(overlap_all_ents) * 0.40, 1.0)
            match_reasons.append(f"Entity: {list(overlap_all_ents)[0].title()}")

        # 6. Difficulty Classification and Alignment Score (0.0 to 1.0)
        item_difficulty = candidate.get("difficulty_level")
        if not item_difficulty:
            item_difficulty = difficulty_classifier.classify(
                title=title,
                content_type=content_type,
                text_sample=description or summary,
                severity=candidate.get("severity"),
                cvss_score=candidate.get("cvss_score"),
            )
        s_diff = difficulty_classifier.score_alignment(user_difficulty, item_difficulty)
        if s_diff >= 0.90:
            match_reasons.append(f"Level: {item_difficulty.title()}")

        # 7. Quality & Reliability Score (0.0 to 1.0)
        s_quality = min(max(quality_score, 0.0), 1.0)
        if quality_tier in ["TIER_1_AUTHORITATIVE", "TIER_1"]:
            s_quality = min(s_quality + 0.15, 1.0)
            match_reasons.append("Tier 1 Authoritative")

        # 8. Recency Decay Score (0.0 to 1.0)
        s_recency = 0.50
        if published_at_str:
            try:
                pub_dt = datetime.fromisoformat(published_at_str.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_days = max((now - pub_dt).total_seconds() / 86400.0, 0.0)
                # Half-life of 30 days
                s_recency = math.exp(-0.693 * (age_days / 30.0))
            except Exception:
                s_recency = 0.50

        # Base composite score
        composite = (
            self.WEIGHT_TOPIC * s_topic
            + self.WEIGHT_SAVED * s_saved
            + self.WEIGHT_SEARCH * s_search
            + self.WEIGHT_VIEWED * s_viewed
            + self.WEIGHT_ENTITY * s_entity
            + self.WEIGHT_DIFFICULTY * s_diff
            + self.WEIGHT_QUALITY * s_quality
            + self.WEIGHT_RECENCY * s_recency
        )

        # Apply viewed penalty to promote exploration, UNLESS it's the current item being compared or explicit saved
        if cid in viewed_ids and cid != current_content_id and not is_saved:
            composite = max(composite - 0.20, 0.05)

        # If current item, exclude from self-recommendation
        if current_content_id and cid == current_content_id:
            composite = 0.0

        # Ensure at least 1 match reason
        if not match_reasons:
            if content_type == "video":
                match_reasons.append("Security Video Intelligence")
            elif content_type in ["research", "paper"]:
                match_reasons.append("Deep Research Analysis")
            elif content_type == "tool":
                match_reasons.append("Operational Security Tool")
            else:
                match_reasons.append("Threat Intelligence Advisory")

        return RecommendationItem(
            content_id=cid,
            title=title,
            description=description,
            summary=summary,
            canonical_url=canonical_url,
            content_type=content_type,
            category=category,
            difficulty_level=item_difficulty,
            score=round(composite, 4),
            match_reasons=match_reasons[:3],
            source=source_name,
            author=author,
            published_at=published_at_str,
            tags=tags,
            entities=entities,
            is_saved=is_saved,
            source_quality_tier=quality_tier,
            source_quality_score=round(quality_score, 2),
        )


recommendation_scorer = RecommendationScorer()
