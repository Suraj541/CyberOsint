"""
Mistral AI Model Auto-Detection System
Dynamically inspects available models via the active API key,
evaluates capability tiers, and selects the optimal model for cybersecurity intelligence summarization.
Conforms to IMPLEMENT.md and platform resilience standards.
"""

from datetime import datetime, timezone
import hashlib
import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("cyber_osint.services.mistral_detector")

# Priority ranking for intelligence summarization / extraction
# Balances latency, JSON adherence, reasoning quality, and API rate limits
MODEL_PREFERENCE_ORDER = [
    "mistral-small-latest",
    "mistral-small-2501",
    "mistral-small-2409",
    "mistral-small-2402",
    "mistral-medium-latest",
    "mistral-medium-2312",
    "mistral-large-latest",
    "mistral-large-2411",
    "mistral-large-2407",
    "mistral-large-2402",
    "open-mistral-nemo",
    "open-mistral-nemo-2407",
    "codestral-latest",
    "codestral-2501",
    "codestral-2405",
    "open-mixtral-8x22b",
    "open-mixtral-8x7b",
    "open-mistral-7b",
    "ministral-8b-latest",
    "ministral-3b-latest",
]

DEFAULT_FALLBACK_MODEL = "mistral-small-latest"


class MistralModelDetector:
    """
    Introspects and caches available Mistral AI models.
    Supports both mistralai SDK and direct HTTP inspection with TTL caching.
    """

    def __init__(self, cache_ttl_seconds: int = 300):
        self.cache_ttl = cache_ttl_seconds
        self._cached_models: List[str] = []
        self._cached_details: List[Dict[str, Any]] = []
        self._last_detected_time: float = 0.0
        self._last_key_hash: str = ""
        self._active_selected_model: str = DEFAULT_FALLBACK_MODEL
        self._active_reason: str = "Uninitialized default"
        self._detection_status: str = "uninitialized"
        self._last_error: Optional[str] = None

    def _hash_key(self, key: Optional[str]) -> str:
        if not key:
            return ""
        return hashlib.sha256(key.strip().encode("utf-8")).hexdigest()[:16]

    def is_cache_valid(self, api_key: str) -> bool:
        """Check if cached models are still fresh for the given API key."""
        if not self._cached_models:
            return False
        key_hash = self._hash_key(api_key)
        if key_hash != self._last_key_hash:
            return False
        return (time.time() - self._last_detected_time) < self.cache_ttl

    def list_available_models(
        self, api_key: str, force_refresh: bool = False
    ) -> List[str]:
        """
        Query Mistral API for all available models associated with the API key.
        Filters out embedding-only models and caches results.
        """
        if not api_key:
            return []

        if not force_refresh and self.is_cache_valid(api_key):
            return list(self._cached_models)

        discovered_ids: List[str] = []
        details: List[Dict[str, Any]] = []
        err: Optional[str] = None

        # 1. Try official SDK first
        try:
            try:
                from mistralai import Mistral  # noqa: PLC0415
            except ImportError:
                from mistralai.client import Mistral  # noqa: PLC0415
            client = Mistral(api_key=api_key)
            resp = client.models.list()
            data_items = getattr(resp, "data", []) or []
            for item in data_items:
                model_id = getattr(item, "id", None) or (item.get("id") if isinstance(item, dict) else None)
                if model_id:
                    # Filter out embedding-only models
                    if "embed" in str(model_id).lower():
                        continue
                    discovered_ids.append(str(model_id))
                    details.append({"id": str(model_id), "source": "sdk"})
            logger.info("Auto-detected %d Mistral models via SDK", len(discovered_ids))
        except Exception as sdk_exc:
            err = str(sdk_exc)
            logger.debug("Mistral SDK model discovery notice: %s — trying direct HTTP", sdk_exc)

        # 2. Try direct HTTP if SDK returned nothing or failed
        if not discovered_ids:
            try:
                import httpx
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Accept": "application/json",
                }
                with httpx.Client(timeout=10.0) as http_client:
                    r = http_client.get("https://api.mistral.ai/v1/models", headers=headers)
                    if r.status_code == 200:
                        payload = r.json()
                        raw_items = payload.get("data", [])
                        for item in raw_items:
                            m_id = item.get("id")
                            if m_id and "embed" not in m_id.lower():
                                discovered_ids.append(m_id)
                                details.append({"id": m_id, "source": "http"})
                        logger.info("Auto-detected %d Mistral models via HTTP API", len(discovered_ids))
                    else:
                        err = f"HTTP {r.status_code}: {r.text[:100]}"
            except Exception as http_exc:
                err = str(http_exc)
                logger.warning("Mistral HTTP model discovery failed: %s", http_exc)

        if discovered_ids:
            self._cached_models = discovered_ids
            self._cached_details = details
            self._last_detected_time = time.time()
            self._last_key_hash = self._hash_key(api_key)
            self._detection_status = "detected"
            self._last_error = None
        else:
            self._detection_status = "error" if err else "empty"
            self._last_error = err

        return list(self._cached_models)

    def detect_optimal_model(
        self,
        api_key: Optional[str] = None,
        preferred_model: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Tuple[str, str]:
        """
        Evaluate discovered models against user preferences and return (selected_model, reason).
        """
        # Resolve user preference
        pref = (preferred_model or "").strip()
        is_auto = not pref or pref.lower() == "auto"

        if not api_key:
            selected = pref if not is_auto else DEFAULT_FALLBACK_MODEL
            reason = "No API key configured (using fallback model)"
            self._active_selected_model = selected
            self._active_reason = reason
            self._detection_status = "unconfigured"
            return selected, reason

        # Fetch available models
        available = self.list_available_models(api_key, force_refresh=force_refresh)

        # Case 1: Explicit specific model requested
        if not is_auto:
            if available and pref in available:
                selected = pref
                reason = f"Explicit override '{pref}' validated against available account models"
            elif available and pref not in available:
                # Requested model not active in user's tier, fallback to highest matching
                fallback = self._match_best_available(available)
                selected = fallback
                reason = f"Configured model '{pref}' not available on active tier; auto-selected '{fallback}'"
                logger.warning(reason)
            else:
                selected = pref
                reason = f"Explicit override '{pref}' (offline / unverified)"
            self._active_selected_model = selected
            self._active_reason = reason
            return selected, reason

        # Case 2: Auto-detect optimal model
        if available:
            selected = self._match_best_available(available)
            reason = f"Auto-detected optimal model from {len(available)} available account models"
        else:
            selected = DEFAULT_FALLBACK_MODEL
            reason = f"Discovery returned no models; defaulting to '{DEFAULT_FALLBACK_MODEL}'"

        self._active_selected_model = selected
        self._active_reason = reason
        logger.info("Mistral model auto-detection resolved to: %s (%s)", selected, reason)
        return selected, reason

    def _match_best_available(self, available: List[str]) -> str:
        """Select the highest-priority model present in the available list."""
        avail_lower = {m.lower(): m for m in available}

        # Check explicit preference order
        for pref in MODEL_PREFERENCE_ORDER:
            if pref.lower() in avail_lower:
                return avail_lower[pref.lower()]

        # Check partial prefix matches (e.g. any mistral-small, medium, or large)
        for target in ["mistral-small", "mistral-medium", "mistral-large", "codestral", "nemo"]:
            for m in available:
                if target in m.lower():
                    return m

        # Fallback to the first available non-empty model
        return available[0] if available else DEFAULT_FALLBACK_MODEL

    def get_status(self, api_key: Optional[str] = None) -> Dict[str, Any]:
        """Return diagnostic status snapshot of the auto-detection subsystem."""
        key_configured = bool(api_key)
        has_cached = bool(self._cached_models)
        age = round(time.time() - self._last_detected_time, 1) if self._last_detected_time else None

        return {
            "status": self._detection_status,
            "api_key_configured": key_configured,
            "selected_model": self._active_selected_model,
            "selection_reason": self._active_reason,
            "available_models_count": len(self._cached_models),
            "available_models": list(self._cached_models),
            "cache_age_seconds": age,
            "cache_ttl_seconds": self.cache_ttl,
            "last_error": self._last_error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Global singleton detector
mistral_model_detector = MistralModelDetector()
