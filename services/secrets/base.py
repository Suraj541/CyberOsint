"""
Base Abstractions and Schemas for Secret Management.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# The 6 core environment variables mandated by IMPLEMENT.md Section 36
MANDATORY_SECRETS: List[Dict[str, Any]] = [
    {
        "key": "DATABASE_URL",
        "description": "Primary relational database connection string (PostgreSQL / SQLite fallback).",
        "required": True,
        "is_url": True,
    },
    {
        "key": "REDIS_URL",
        "description": "Redis cache, rate-limiting, and distributed queue endpoint.",
        "required": True,
        "is_url": True,
    },
    {
        "key": "SEARCH_URL",
        "description": "OpenSearch cluster URL for hybrid BM25 and vector semantic search.",
        "required": True,
        "is_url": True,
    },
    {
        "key": "AI_API_KEY",
        "description": "API key for LLM intelligence synthesis, threat assessment, and enrichment.",
        "required": False,
        "is_url": False,
    },
    {
        "key": "VIDEO_API_KEY",
        "description": "Multimedia API key for conference talk and video platform discovery.",
        "required": False,
        "is_url": False,
    },
    {
        "key": "GITHUB_TOKEN",
        "description": "GitHub Personal Access Token for GHSA advisories and exploit PoC monitoring.",
        "required": False,
        "is_url": False,
    },
]


@dataclass
class SecretMetadata:
    """Metadata representing the state of an individual secret."""
    key: str
    configured: bool
    masked_value: Optional[str] = None
    description: str = ""
    required: bool = False
    provider: str = "env"
    last_checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class SecretManagerBase(ABC):
    """
    Abstract Base Class for secret managers.
    Conforms to IMPLEMENT.md Section 36: 'Production should use a dedicated secret manager.'
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Returns the canonical provider name (e.g. 'env', 'vault', 'aws', 'encrypted_file')."""
        pass

    @abstractmethod
    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves raw secret value by key."""
        pass

    @abstractmethod
    def set_secret(self, key: str, value: str) -> bool:
        """Persists or updates secret value in backend."""
        pass

    @abstractmethod
    def has_secret(self, key: str) -> bool:
        """Checks whether a secret exists and is non-empty."""
        pass

    @abstractmethod
    def list_keys(self) -> List[str]:
        """Lists all known secret keys tracked by this provider."""
        pass

    def audit_secrets(self) -> Dict[str, Any]:
        """
        Audits all mandatory secrets and returns their configuration status and masked previews.
        Guarantees raw secret plaintext is NEVER included in audit output.
        """
        from services.secrets.masking import mask_connection_url, mask_secret

        results = []
        configured_count = 0
        missing_count = 0

        for sec in MANDATORY_SECRETS:
            k = sec["key"]
            raw_val = self.get_secret(k)
            is_set = bool(raw_val and str(raw_val).strip())

            if is_set:
                configured_count += 1
                if sec.get("is_url"):
                    masked = mask_connection_url(raw_val)
                else:
                    masked = mask_secret(raw_val)
            else:
                if sec["required"]:
                    missing_count += 1
                masked = None

            results.append({
                "key": k,
                "configured": is_set,
                "masked_value": masked,
                "description": sec["description"],
                "required": sec["required"],
                "provider": self.provider_name,
                "last_checked_at": datetime.now(timezone.utc).isoformat(),
            })

        return {
            "provider": self.provider_name,
            "total_tracked": len(MANDATORY_SECRETS),
            "configured_count": configured_count,
            "missing_required_count": missing_count,
            "is_healthy": missing_count == 0,
            "secrets": results,
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
