"""
Notification Pipeline Core Orchestrator
Executes the standardized 5-stage notification pipeline from IMPLEMENT.md Section 33:
New Content -> Match Watchlists -> Calculate Importance -> Create Notification -> Send
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Union
from sqlalchemy.orm import Session

from app.models.content import Content
from app.models.notification import Notification, NotificationChannelConfig
from app.models.source_quality import SourceQuality
from app.models.watchlist import Watchlist, WatchlistItem
from services.notification.dispatchers import dispatcher_registry
from services.notification.importance import importance_calculator
from services.notification.models import (
    ImportanceLevel,
    ImportanceScoreResult,
    NotificationChannel,
    NotificationDTO,
    NotificationPipelineResult,
    NotificationStatus,
)
from services.watchlist.matcher import watchlist_matcher
from services.watchlist.models import WatchlistItemDTO

logger = logging.getLogger("cyber_osint.services.notification.pipeline")


class NotificationPipeline:
    """
    Executes the complete 5-stage notification pipeline:
    1. New Content: Ingest and extract content payload & source quality
    2. Match Watchlists: Match content against active surveillance watchlists
    3. Calculate Importance: Evaluate severity, CVSS, exploit indicators, and source depth
    4. Create Notification: Persist alert entity with audit metadata in database
    5. Send: Dispatch across configured channels (Web, Email, Push, Webhook)
    """

    def __init__(self):
        pass

    def _normalize_content(self, content_or_dict: Union[Content, Dict[str, Any]], db: Optional[Session] = None) -> Dict[str, Any]:
        """Convert SQLAlchemy Content model or dictionary into normalized dictionary."""
        if isinstance(content_or_dict, dict):
            return content_or_dict

        content = content_or_dict
        entities_list: List[Dict[str, Any]] = []
        if hasattr(content, "content_entities") and content.content_entities:
            for ce in content.content_entities:
                if ce.entity:
                    entities_list.append({
                        "id": ce.entity.id,
                        "name": ce.entity.name,
                        "entity_type": ce.entity.entity_type,
                        "normalized_name": ce.entity.normalized_name,
                    })

        tags_list: List[str] = []
        if hasattr(content, "content_tags") and content.content_tags:
            for ct in content.content_tags:
                if ct.tag:
                    tags_list.append(ct.tag.name)

        source_name = "Unknown Source"
        source_quality_score = None
        if content.source_id and db:
            try:
                sq = db.query(SourceQuality).filter(SourceQuality.source_id == content.source_id).first()
                if sq:
                    source_quality_score = sq.composite_quality_score
            except Exception:
                pass

        if hasattr(content, "source") and content.source:
            source_name = content.source.name

        return {
            "id": content.id,
            "title": content.title or "",
            "description": content.description or "",
            "summary": content.summary or "",
            "canonical_url": content.canonical_url or "",
            "content_type": content.content_type or "article",
            "source": source_name,
            "severity": getattr(content, "severity", "LOW") or "LOW",
            "cvss_score": getattr(content, "cvss_score", None),
            "category": getattr(content, "category", "General") or "General",
            "tags": tags_list,
            "entities": entities_list,
            "published_at": content.published_at.isoformat() if content.published_at else None,
            "source_quality_score": source_quality_score,
        }

    def process_content(
        self,
        db: Session,
        content_or_dict: Union[Content, Dict[str, Any]],
        session_id: Optional[str] = None,
        force_dispatch: bool = False,
        threshold_override: Optional[float] = None,
    ) -> NotificationPipelineResult:
        """
        Runs the full 5-stage pipeline on an intelligence content item.
        """
        # -------------------------------------------------------------
        # STAGE 1: New Content
        # -------------------------------------------------------------
        content_dict = self._normalize_content(content_or_dict, db)
        content_id = content_dict.get("id")
        content_title = content_dict.get("title", "Untitled Content")

        # -------------------------------------------------------------
        # STAGE 2: Match Watchlists
        # -------------------------------------------------------------
        query = db.query(Watchlist).filter(Watchlist.is_active.is_(True))
        if session_id:
            query = query.filter(Watchlist.session_id == session_id)
        active_watchlists = query.all()

        matched_watchlists_data: List[Dict[str, Any]] = []
        all_matched_hits = []

        for wl in active_watchlists:
            if not wl.items:
                continue

            item_dtos = [
                WatchlistItemDTO(
                    id=item.id,
                    watchlist_id=item.watchlist_id,
                    item_type=item.item_type,
                    item_value=item.item_value,
                    severity_threshold=item.severity_threshold,
                    notify_on_match=item.notify_on_match,
                    created_at=item.created_at.isoformat() if item.created_at else None,
                )
                for item in wl.items
                if item.notify_on_match
            ]

            hits = watchlist_matcher.match_all(item_dtos, content_dict, wl.name)
            if hits:
                all_matched_hits.extend(hits)
                matched_watchlists_data.append({
                    "watchlist_id": wl.id,
                    "watchlist_name": wl.name,
                    "session_id": wl.session_id,
                    "user_id": wl.user_id,
                    "channel": wl.notification_channel or "web",
                    "hits": [h.model_dump() for h in hits],
                })

        if not matched_watchlists_data and not force_dispatch:
            calc_result = importance_calculator.calculate(
                content_dict=content_dict,
                matched_items=[],
                source_quality_score=content_dict.get("source_quality_score"),
                threshold_override=threshold_override,
            )
            return NotificationPipelineResult(
                content_id=content_id,
                content_title=content_title,
                matched_watchlists_count=0,
                matched_items_count=0,
                matched_watchlists=[],
                importance=calc_result,
                notifications_created=[],
                dispatch_results=[],
                status="no_match",
            )

        # -------------------------------------------------------------
        # STAGE 3: Calculate Importance
        # -------------------------------------------------------------
        importance_result = importance_calculator.calculate(
            content_dict=content_dict,
            matched_items=all_matched_hits,
            source_quality_score=content_dict.get("source_quality_score"),
            threshold_override=threshold_override,
        )

        # Enforce threshold: "Do not send every discovered article. Implement importance thresholds."
        if not importance_result.exceeds_threshold and not force_dispatch:
            logger.info(
                "Content '%s' matched %d items but suppressed below threshold (Score: %.2f < %.2f)",
                content_title[:40],
                len(all_matched_hits),
                importance_result.score,
                importance_result.threshold_used,
            )
            return NotificationPipelineResult(
                content_id=content_id,
                content_title=content_title,
                matched_watchlists_count=len(matched_watchlists_data),
                matched_items_count=len(all_matched_hits),
                matched_watchlists=matched_watchlists_data,
                importance=importance_result,
                notifications_created=[],
                dispatch_results=[],
                status="suppressed_below_threshold",
            )

        # -------------------------------------------------------------
        # STAGE 4: Create Notification
        # -------------------------------------------------------------
        created_notifications: List[Notification] = []
        notifications_dto: List[NotificationDTO] = []
        dispatch_logs: List[Dict[str, Any]] = []

        # Group matches per watchlist/session
        for match_info in matched_watchlists_data:
            w_id = match_info["watchlist_id"]
            w_name = match_info["watchlist_name"]
            s_id = match_info["session_id"]
            u_id = match_info["user_id"]
            base_channel = match_info.get("channel", "web")
            hits = match_info["hits"]

            # Format descriptive alert title
            top_hit = hits[0]["item_value"] if hits else "Target"
            top_type = hits[0]["item_type"].upper() if hits else "TARGET"
            alert_title = f"[{importance_result.level.value}] {top_type} '{top_hit}' detected in {w_name}"

            alert_body = (
                content_dict.get("summary")
                or content_dict.get("description")
                or f"Monitored intelligence detected matching {len(hits)} items in watchlist '{w_name}'."
            )

            meta_payload = {
                "content_id": content_id,
                "content_title": content_title,
                "content_url": content_dict.get("canonical_url"),
                "watchlist_id": w_id,
                "watchlist_name": w_name,
                "matched_items": hits,
                "importance_factors": importance_result.factors,
                "importance_reason": importance_result.reason,
            }

            # Retrieve user configured channel destinations and thresholds
            configured_channels = (
                db.query(NotificationChannelConfig)
                .filter(
                    NotificationChannelConfig.session_id == s_id,
                    NotificationChannelConfig.is_enabled.is_(True),
                )
                .all()
            )

            # Build list of channels to dispatch to (always include web, plus configured channels or watchlist channel)
            channels_to_dispatch: List[Dict[str, Any]] = [
                {"channel": NotificationChannel.WEB, "destination": None, "threshold": 0.35, "secret": None}
            ]

            if configured_channels:
                for cc in configured_channels:
                    try:
                        c_enum = NotificationChannel(cc.channel_type.lower())
                        # Don't duplicate web
                        if c_enum == NotificationChannel.WEB:
                            continue
                        channels_to_dispatch.append({
                            "channel": c_enum,
                            "destination": cc.destination,
                            "threshold": cc.min_importance_threshold,
                            "secret": cc.secret_token,
                        })
                    except ValueError:
                        pass
            elif base_channel != "web":
                try:
                    c_enum = NotificationChannel(base_channel.lower())
                    channels_to_dispatch.append({
                        "channel": c_enum,
                        "destination": None,
                        "threshold": 0.50,
                        "secret": None,
                    })
                except ValueError:
                    pass

            for ch_info in channels_to_dispatch:
                target_channel = ch_info["channel"]
                min_threshold = ch_info["threshold"]
                dest = ch_info["destination"]
                secret = ch_info["secret"]

                # Channel threshold gate
                should_dispatch = importance_calculator.should_send(
                    channel=target_channel,
                    score=importance_result.score,
                    channel_threshold_override=min_threshold,
                )

                initial_status = (
                    NotificationStatus.PENDING.value
                    if should_dispatch
                    else NotificationStatus.SUPPRESSED.value
                )

                notification_obj = Notification(
                    session_id=s_id,
                    user_id=u_id,
                    watchlist_id=w_id,
                    content_id=content_id if isinstance(content_id, int) else None,
                    title=alert_title,
                    body=alert_body,
                    summary=content_dict.get("summary"),
                    importance_score=importance_result.score,
                    importance_level=importance_result.level.value,
                    channel=target_channel.value,
                    status=initial_status,
                    is_read=False,
                    metadata_json=json.dumps(meta_payload),
                )
                db.add(notification_obj)
                db.flush()  # Generate notification ID
                created_notifications.append(notification_obj)

                notif_dto = NotificationDTO(
                    id=notification_obj.id,
                    session_id=s_id,
                    user_id=u_id,
                    watchlist_id=w_id,
                    watchlist_name=w_name,
                    content_id=content_id if isinstance(content_id, int) else None,
                    content_title=content_title,
                    content_url=content_dict.get("canonical_url"),
                    title=alert_title,
                    body=alert_body,
                    summary=content_dict.get("summary"),
                    importance_score=importance_result.score,
                    importance_level=importance_result.level.value,
                    channel=target_channel.value,
                    status=initial_status,
                    is_read=False,
                    metadata=meta_payload,
                    created_at=notification_obj.created_at.isoformat() if notification_obj.created_at else datetime.now(timezone.utc).isoformat(),
                )
                notifications_dto.append(notif_dto)

                # -------------------------------------------------------------
                # STAGE 5: Send (Dispatch)
                # -------------------------------------------------------------
                if should_dispatch:
                    try:
                        dispatch_res = dispatcher_registry.dispatch(
                            channel=target_channel,
                            notification=notif_dto,
                            destination=dest,
                            secret_token=secret,
                        )
                        notification_obj.status = dispatch_res.get("status", NotificationStatus.DELIVERED.value)
                        dispatch_logs.append(dispatch_res)
                    except Exception as disp_err:
                        logger.error("Failed to dispatch notification #%s to %s: %s", notification_obj.id, target_channel.value, disp_err)
                        notification_obj.status = NotificationStatus.FAILED.value
                        dispatch_logs.append({
                            "channel": target_channel.value,
                            "status": NotificationStatus.FAILED.value,
                            "error": str(disp_err),
                        })
                else:
                    dispatch_logs.append({
                        "channel": target_channel.value,
                        "status": NotificationStatus.SUPPRESSED.value,
                        "reason": f"Score {importance_result.score:.2f} below channel threshold {min_threshold:.2f}",
                    })

        db.commit()

        return NotificationPipelineResult(
            content_id=content_id,
            content_title=content_title,
            matched_watchlists_count=len(matched_watchlists_data),
            matched_items_count=len(all_matched_hits),
            matched_watchlists=matched_watchlists_data,
            importance=importance_result,
            notifications_created=notifications_dto,
            dispatch_results=dispatch_logs,
            status="completed",
        )


notification_pipeline = NotificationPipeline()
