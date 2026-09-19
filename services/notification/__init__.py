"""
Notification Service Package
Exposes NotificationService, NotificationPipeline, ImportanceCalculator, and Dispatchers.
Conforms strictly to IMPLEMENT.md Section 33 (Step 32: Build Notifications).
"""

from services.notification.dispatchers import (
    BaseDispatcher,
    DispatcherRegistry,
    EmailDispatcher,
    PushDispatcher,
    WebDispatcher,
    WebhookDispatcher,
    dispatcher_registry,
)
from services.notification.importance import (
    DEFAULT_CHANNEL_THRESHOLDS,
    ImportanceCalculator,
    importance_calculator,
)
from services.notification.models import (
    ImportanceLevel,
    ImportanceScoreResult,
    NotificationChannel,
    NotificationChannelConfigDTO,
    NotificationCreateDTO,
    NotificationDTO,
    NotificationPipelineResult,
    NotificationStatus,
    WebhookPayloadDTO,
)
from services.notification.pipeline import NotificationPipeline, notification_pipeline
from services.notification.service import NotificationService, notification_service

__all__ = [
    "NotificationChannel",
    "ImportanceLevel",
    "NotificationStatus",
    "ImportanceScoreResult",
    "NotificationDTO",
    "NotificationCreateDTO",
    "NotificationChannelConfigDTO",
    "WebhookPayloadDTO",
    "NotificationPipelineResult",
    "DEFAULT_CHANNEL_THRESHOLDS",
    "ImportanceCalculator",
    "importance_calculator",
    "BaseDispatcher",
    "WebDispatcher",
    "EmailDispatcher",
    "PushDispatcher",
    "WebhookDispatcher",
    "DispatcherRegistry",
    "dispatcher_registry",
    "NotificationPipeline",
    "notification_pipeline",
    "NotificationService",
    "notification_service",
]
