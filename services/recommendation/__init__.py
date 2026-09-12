"""
Recommendation Service Package
Exposes RecommendationService, TopicGraph, and DifficultyClassifier.
Conforms strictly to IMPLEMENT.md Section 31 (Step 30: Build Recommendations).
"""

from services.recommendation.difficulty import (
    DifficultyClassifier,
    difficulty_classifier,
)
from services.recommendation.models import (
    ContentTypeFilter,
    DifficultyLevel,
    PersonalizedFeedResponse,
    RecommendationItem,
    TopicRecommendation,
    UserProfileDTO,
)
from services.recommendation.scorer import (
    RecommendationScorer,
    recommendation_scorer,
)
from services.recommendation.service import (
    RecommendationService,
    recommendation_service,
)
from services.recommendation.topic_graph import TopicGraph, topic_graph

__all__ = [
    "DifficultyLevel",
    "ContentTypeFilter",
    "RecommendationItem",
    "TopicRecommendation",
    "UserProfileDTO",
    "PersonalizedFeedResponse",
    "TopicGraph",
    "topic_graph",
    "DifficultyClassifier",
    "difficulty_classifier",
    "RecommendationScorer",
    "recommendation_scorer",
    "RecommendationService",
    "recommendation_service",
]
