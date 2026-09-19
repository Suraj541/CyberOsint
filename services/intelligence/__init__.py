"""Section 48 (Step 47): Version 3 Advanced Intelligence Package.

Exports:
  - ThreatActorService, threat_actor_service
  - MalwareService, malware_service
  - CampaignService, campaign_service
  - TimelineEngine, timeline_engine
  - CorrelationEngine, correlation_engine
  - LearningService, learning_service
  - ResearchAssistantEngine, research_assistant_engine
"""

from services.intelligence.threat_actor_service import (
    ThreatActorService,
    threat_actor_service,
)
from services.intelligence.malware_service import (
    MalwareService,
    malware_service,
)
from services.intelligence.campaign_service import (
    CampaignService,
    campaign_service,
)
from services.intelligence.timeline_engine import (
    TimelineEngine,
    timeline_engine,
)
from services.intelligence.correlation_engine import (
    CorrelationEngine,
    correlation_engine,
)
from services.intelligence.learning_service import (
    LearningService,
    learning_service,
)
from services.intelligence.research_assistant import (
    ResearchAssistantEngine,
    research_assistant_engine,
)

__all__ = [
    "ThreatActorService",
    "threat_actor_service",
    "MalwareService",
    "malware_service",
    "CampaignService",
    "campaign_service",
    "TimelineEngine",
    "timeline_engine",
    "CorrelationEngine",
    "correlation_engine",
    "LearningService",
    "learning_service",
    "ResearchAssistantEngine",
    "research_assistant_engine",
]
