"""Section 49 (Step 48): Model Routing & Inference Gateway.

Provides:
  - Task-aware LLM/embedding router (classification, entity_extraction, summarization, deep_research)
  - Latency SLA vs. Cost optimization
  - Circuit breaker mechanism and fallback cascade
"""

import time
from typing import Dict, List, Optional
from app.schemas.scale import ModelRouteConfig, ModelRouteRequest, ModelRouteResponse

REGISTERED_ROUTES: List[ModelRouteConfig] = [
    ModelRouteConfig(
        task_type="classification",
        primary_model="local-distilbert-sec-v2",
        fallback_model="cloud-fast-classifier-mini",
        max_latency_sla_ms=50,
        max_cost_per_query_usd=0.0001,
        circuit_breaker_status="closed",
    ),
    ModelRouteConfig(
        task_type="entity_extraction",
        primary_model="cloud-security-ner-pro",
        fallback_model="local-spacy-cyber-ner",
        max_latency_sla_ms=150,
        max_cost_per_query_usd=0.0005,
        circuit_breaker_status="closed",
    ),
    ModelRouteConfig(
        task_type="summarization",
        primary_model="cloud-reasoning-flash-v3",
        fallback_model="local-mistral-7b-instruct",
        max_latency_sla_ms=500,
        max_cost_per_query_usd=0.0020,
        circuit_breaker_status="closed",
    ),
    ModelRouteConfig(
        task_type="deep_research",
        primary_model="cloud-reasoning-deep-v3",
        fallback_model="cloud-reasoning-flash-v3",
        max_latency_sla_ms=2500,
        max_cost_per_query_usd=0.0150,
        circuit_breaker_status="closed",
    ),
]


def get_model_routes() -> List[ModelRouteConfig]:
    """Returns registered model routes and circuit breaker states."""
    return REGISTERED_ROUTES


def route_query(req: ModelRouteRequest) -> ModelRouteResponse:
    """Routes an inference query through the gateway based on SLA, task type, and health."""
    start_ts = time.time()
    route = next((r for r in REGISTERED_ROUTES if r.task_type == req.task_type), REGISTERED_ROUTES[0])

    if req.latency_priority:
        # Route to lowest latency local model
        selected_model = route.fallback_model if "local" in route.fallback_model else route.primary_model
        provider = "Edge / Local In-Memory"
        reason = f"Prioritized ultra-low latency SLA (<{route.max_latency_sla_ms}ms) over deep token analysis"
        sim_latency = 18.5
    elif route.circuit_breaker_status == "open":
        # Circuit breaker tripped -> fallback
        selected_model = route.fallback_model
        provider = "Fallback Secondary Node"
        reason = "Primary model circuit breaker tripped; routing to secondary fallback"
        sim_latency = 42.0
    else:
        # Normal primary route
        selected_model = route.primary_model
        provider = "Cloud Inference Engine"
        reason = f"Standard task routing optimized for {req.task_type} accuracy and precision"
        sim_latency = 95.0

    simulated_result = (
        f"Gateway synthesized response for [{req.task_type}] using [{selected_model}]. "
        f"Prompt snippet: '{req.prompt[:60]}...' processed successfully."
    )

    return ModelRouteResponse(
        task_type=req.task_type,
        selected_model=selected_model,
        provider=provider,
        routed_reason=reason,
        latency_ms=sim_latency,
        simulated_result=simulated_result,
    )
