"""
Advanced OSINT Connectors API Endpoints.
Coordinates the 11 prioritized OSINT connector categories from IMPLEMENT.md Section 34.
Enforces strict priority hierarchy (1-11) and independent enable/disable toggling.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, status

from app.schemas.connector import (
    ConnectorBatchRunResponse,
    ConnectorConfigUpdateRequest,
    ConnectorHealthSummaryResponse,
    ConnectorInfoResponse,
    ConnectorRunResponse,
    ConnectorToggleRequest,
    ConnectorYamlConfigItem,
    ConnectorsYamlResponse,
    ConfigReloadResponse,
    RawYamlConfigRequest,
    RawYamlConfigResponse,
)
from connectors.config import connector_config_manager
from connectors.manager import connector_manager, PRIORITY_CONNECTOR_SPECS

logger = logging.getLogger("cyber_osint.api.connectors")

router = APIRouter(prefix="/connectors", tags=["Advanced OSINT Connectors"])


# ============================================================================
# Section 35 (Step 34): Declarative Connector Configuration Endpoints
# ============================================================================

@router.get(
    "/config",
    response_model=ConnectorsYamlResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Parsed Declarative Connector Configurations",
)
def get_parsed_connector_configs() -> ConnectorsYamlResponse:
    """
    Returns all connector specifications parsed from connectors.yaml.
    Includes protocol type, polling intervals, priority tiers, and env-based secret mappings.
    """
    configs = connector_config_manager.list_configs()
    items = []
    for key, conf in configs.items():
        items.append(
            ConnectorYamlConfigItem(
                key=key,
                enabled=conf.enabled,
                type=conf.type,
                category=conf.category,
                url=conf.url,
                interval_minutes=conf.interval_minutes,
                priority=conf.priority,
                description=conf.description,
                api_key_env=conf.api_key_env,
                auth_token_env=conf.auth_token_env,
                timeout=conf.timeout,
                options=conf.options,
            )
        )
    return ConnectorsYamlResponse(
        total=len(items),
        connectors=items,
        last_loaded_at=connector_config_manager.last_loaded_at,
    )


@router.get(
    "/config/raw",
    response_model=RawYamlConfigResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Raw connectors.yaml Text",
)
def get_raw_yaml_config() -> RawYamlConfigResponse:
    """
    Returns the exact raw YAML content from connectors.yaml for Web UI inspection and editing.
    """
    raw_content = connector_config_manager.get_raw_yaml()
    return RawYamlConfigResponse(
        yaml_content=raw_content,
        last_loaded_at=connector_config_manager.last_loaded_at,
    )


@router.put(
    "/config/raw",
    response_model=ConfigReloadResponse,
    status_code=status.HTTP_200_OK,
    summary="Save and Validate Raw connectors.yaml",
)
def update_raw_yaml_config(payload: RawYamlConfigRequest) -> ConfigReloadResponse:
    """
    Audits for plaintext secrets, validates YAML structure, saves to connectors.yaml,
    and hot-reloads runtime manager.
    Strictly enforces IMPLEMENT.md Section 35: 'Never hardcode API keys.'
    """
    try:
        updated_configs = connector_config_manager.save_raw_yaml(payload.yaml_content)
        sync_result = connector_manager.sync_from_yaml()
        return ConfigReloadResponse(
            status="success",
            message=f"Successfully persisted connectors.yaml with {len(updated_configs)} connectors and synced runtime manager.",
            total_loaded=len(updated_configs),
            synced_to_runtime=sync_result.get("synced_count", 0),
            reloaded_at=datetime.now(timezone.utc).isoformat(),
        )
    except ValueError as val_err:
        logger.warning("Rejected raw YAML update due to validation/security violation: %s", val_err)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as exc:
        logger.error("Failed to update raw YAML config: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist configuration: {str(exc)}",
        )


@router.post(
    "/config/reload",
    response_model=ConfigReloadResponse,
    status_code=status.HTTP_200_OK,
    summary="Hot-Reload connectors.yaml into Runtime Manager",
)
def reload_connector_configs() -> ConfigReloadResponse:
    """
    Forces immediate reload of connectors.yaml and updates active manager priority specs.
    """
    try:
        configs = connector_config_manager.load_config()
        sync_result = connector_manager.sync_from_yaml()
        return ConfigReloadResponse(
            status="success",
            message=f"Hot-reloaded {len(configs)} connectors from connectors.yaml.",
            total_loaded=len(configs),
            synced_to_runtime=sync_result.get("synced_count", 0),
            reloaded_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.error("Failed to hot-reload connectors config: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Hot-reload failed: {str(exc)}",
        )


@router.patch(
    "/config/{connector_key}",
    response_model=ConnectorYamlConfigItem,
    status_code=status.HTTP_200_OK,
    summary="Update Single Connector Configuration in connectors.yaml",
)
def update_connector_config(
    connector_key: str,
    payload: ConnectorConfigUpdateRequest,
) -> ConnectorYamlConfigItem:
    """
    Modifies configuration attributes for a specific connector in connectors.yaml and persists.
    """
    try:
        updates = payload.model_dump(exclude_unset=True)
        conf = connector_config_manager.update_connector(connector_key, updates)
        connector_manager.sync_from_yaml()
        return ConnectorYamlConfigItem(
            key=connector_key,
            enabled=conf.enabled,
            type=conf.type,
            category=conf.category,
            url=conf.url,
            interval_minutes=conf.interval_minutes,
            priority=conf.priority,
            description=conf.description,
            api_key_env=conf.api_key_env,
            auth_token_env=conf.auth_token_env,
            timeout=conf.timeout,
            options=conf.options,
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector key '{connector_key}' not found in configuration.",
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update connector '{connector_key}': {str(exc)}",
        )


# ============================================================================
# Section 34 (Step 33): Connector Management and Telemetry
# ============================================================================


@router.get(
    "",
    response_model=List[ConnectorInfoResponse],
    status_code=status.HTTP_200_OK,
    summary="List All 11 Prioritized OSINT Connectors",
)
def list_connectors() -> List[ConnectorInfoResponse]:
    """
    Returns all 11 OSINT connectors sorted strictly by priority order (1 to 11).
    Each connector displays its active enable/disable status and runtime telemetry.
    """
    return [ConnectorInfoResponse(**item) for item in connector_manager.list_connectors()]


@router.get(
    "/health",
    response_model=ConnectorHealthSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Aggregated Health Check Across All 11 Connectors",
)
def get_all_connectors_health() -> ConnectorHealthSummaryResponse:
    """Executes live diagnostic health checks across all 11 prioritized connectors."""
    health_data = connector_manager.health_check_all()
    return ConnectorHealthSummaryResponse(**health_data)


@router.post(
    "/run-all",
    response_model=ConnectorBatchRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Run All Enabled Connectors in Priority Order",
)
def run_all_enabled_connectors() -> ConnectorBatchRunResponse:
    """
    Executes all currently enabled connectors in strict priority order (1 through 11).
    Connectors that are disabled are cleanly skipped.
    """
    batch_result = connector_manager.run_all_enabled()
    return ConnectorBatchRunResponse(**batch_result)


@router.get(
    "/{connector_id}",
    response_model=ConnectorInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Connector Information",
)
def get_connector(connector_id: str) -> ConnectorInfoResponse:
    """Retrieve detailed info and telemetry for a specific connector category."""
    connectors = connector_manager.list_connectors()
    for item in connectors:
        if item["id"] == connector_id:
            return ConnectorInfoResponse(**item)
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Connector '{connector_id}' not found in the 11 priority categories.",
    )


@router.patch(
    "/{connector_id}/toggle",
    response_model=ConnectorInfoResponse,
    status_code=status.HTTP_200_OK,
    summary="Independently Enable or Disable a Connector",
)
def toggle_connector(
    connector_id: str,
    payload: ConnectorToggleRequest,
) -> ConnectorInfoResponse:
    """
    Independently enables or disables an OSINT connector.
    Strictly conforms to IMPLEMENT.md Section 34:
    'Each connector should be independently enabled or disabled.'
    """
    try:
        connector_manager.set_enabled(connector_id, payload.enabled)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector '{connector_id}' not found in the 11 priority categories.",
        )

    # Return updated connector record
    connectors = connector_manager.list_connectors()
    for item in connectors:
        if item["id"] == connector_id:
            return ConnectorInfoResponse(**item)

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Connector '{connector_id}' not found.",
    )


@router.get(
    "/{connector_id}/health",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Check Specific Connector Health",
)
def get_single_connector_health(connector_id: str) -> Dict[str, Any]:
    """Runs a health and connectivity check on a single connector."""
    try:
        health = connector_manager.health_check(connector_id)
        return health.model_dump()
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector '{connector_id}' not found in the 11 priority categories.",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed for '{connector_id}': {str(exc)}",
        )


@router.post(
    "/{connector_id}/run",
    response_model=ConnectorRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Single Connector Discovery",
)
def run_single_connector(connector_id: str) -> ConnectorRunResponse:
    """
    Executes discovery and normalization pipeline for a single connector.
    If the connector is disabled, returns skipped status.
    """
    if not connector_manager.is_enabled(connector_id):
        return ConnectorRunResponse(
            id=connector_id,
            status="skipped_disabled",
            items_count=0,
            executed_at=datetime.now(timezone.utc).isoformat(),
            items=[],
        )

    try:
        items = connector_manager.run_connector(connector_id)
        serialized_items = []
        for item in items:
            pub_date = item.published_at if isinstance(item.published_at, str) else (item.published_at.isoformat() if hasattr(item.published_at, "isoformat") else None)
            raw_text = item.raw_content or item.description or ""
            serialized_items.append({
                "title": item.title,
                "content": raw_text[:300] if raw_text else "",
                "url": item.url,
                "published_at": pub_date,
                "author": item.author,
                "source_type": item.metadata.get("source_type") or item.content_type,
                "cves": item.metadata.get("cves") or item.metadata.get("referenced_cves") or [],
                "tags": item.metadata.get("tags") or [],
            })
        return ConnectorRunResponse(
            id=connector_id,
            status="success",
            items_count=len(items),
            executed_at=datetime.now(timezone.utc).isoformat(),
            items=serialized_items,
        )
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector '{connector_id}' not found in the 11 priority categories.",
        )
    except Exception as exc:
        logger.error("Connector run failed for '%s': %s", connector_id, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Execution failed for '{connector_id}': {str(exc)}",
        )


@router.get(
    "/diagnostic",
    summary="Get Internal Connector & Source Coverage Diagnostic Report",
)
def get_connector_diagnostic_report() -> Dict[str, Any]:
    """
    Returns an internal diagnostic report showing connector types, registered status,
    scheduling status, and per-source coverage conforming to Section 16 & 17.
    """
    from connectors.registry import connector_registry
    from app.workers.scheduler import scheduler

    configs = connector_config_manager.list_configs()
    source_coverage = []

    for key, conf in configs.items():
        spec = None
        for s in PRIORITY_CONNECTOR_SPECS:
            if s["id"] == conf.category or s["category"] == conf.category:
                spec = s
                break

        cid = spec["id"] if spec else key
        telemetry = connector_manager._last_run_telemetry.get(cid, {})
        job = scheduler.get_job(f"connector_{cid}")

        source_coverage.append({
            "source_key": key,
            "category": conf.category or conf.type,
            "source_name": conf.description or key,
            "url": conf.url,
            "connector_type": conf.type,
            "enabled": conf.enabled and connector_manager.is_enabled(cid),
            "registered": connector_registry.has(conf.type) or connector_registry.has(cid),
            "scheduled": job is not None and job.state.is_enabled,
            "last_success": telemetry.get("last_success_at"),
            "last_failure": telemetry.get("last_error_at"),
            "last_error": telemetry.get("last_error"),
            "items_fetched": telemetry.get("items_fetched", 0),
            "items_inserted": telemetry.get("items_inserted", 0),
            "items_duplicate": telemetry.get("items_duplicate", 0),
            "items_failed": telemetry.get("items_failed", 0),
            "next_run": telemetry.get("next_run_at") or (job.state.next_run.isoformat() if job and job.state.next_run else None),
            "execution_duration_ms": telemetry.get("execution_duration_ms", 0.0),
        })

    connector_types = []
    for spec in sorted(PRIORITY_CONNECTOR_SPECS, key=lambda x: x["priority"]):
        cid = spec["id"]
        job = scheduler.get_job(f"connector_{cid}")
        telemetry = connector_manager._last_run_telemetry.get(cid, {})
        connector_types.append({
            "id": cid,
            "priority": spec["priority"],
            "name": spec["name"],
            "category": spec["category"],
            "connector_class": spec["connector_cls"].__name__,
            "registered": connector_registry.has(cid) or connector_registry.has(spec["category"]),
            "is_enabled": connector_manager.is_enabled(cid),
            "is_scheduled": job is not None and job.state.is_enabled,
            "polling_interval_minutes": connector_manager._intervals.get(cid, 60),
            "last_run": telemetry.get("last_run"),
            "last_status": telemetry.get("last_status", "idle"),
            "items_count": telemetry.get("items_count", 0),
            "execution_duration_ms": telemetry.get("execution_duration_ms", 0.0),
        })

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_monitored_sources": len(source_coverage),
        "total_connector_types": len(connector_types),
        "scheduler_running": scheduler.is_running,
        "monitored_sources": source_coverage,
        "connector_types": connector_types,
    }
