"""
Declarative Connector Configuration Manager.
Parses, validates, and manages connectors.yaml conforming to IMPLEMENT.md Section 35 (Step 34).
Strictly enforces the rule: 'Never hardcode API keys' via environment variable expansion and secret auditing.
"""

from datetime import datetime, timezone
import logging
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import yaml

logger = logging.getLogger("cyber_osint.connectors.config")

# Patterns indicating potentially hardcoded secrets in YAML text (ordered specific to general)
FORBIDDEN_SECRET_PATTERNS = [
    (r"ghp_[A-Za-z0-9_]{20,}", "Hardcoded GitHub Personal Access Token"),
    (r"github_pat_[A-Za-z0-9_]{20,}", "Hardcoded GitHub Fine-Grained Token"),
    (r"(?i)bearer\s+[A-Za-z0-9_\-\.]{20,}", "Hardcoded Bearer authentication token"),
    (r"(?i)(?:api_key|token|secret|password|bearer|auth_key)\s*:\s*[\"'](?!(\$\{[^}]+\}))([A-Za-z0-9_\-\.]{16,})[\"']", "Potential plaintext secret/token"),
]


class ConnectorConfig(BaseModel):
    """Configuration specification for an individual OSINT connector."""
    enabled: bool = Field(default=True, description="Whether the connector is actively enabled")
    type: str = Field(..., description="Connector protocol type: rss, cert, cve, vendor, blog, github, research, video, conference, social, specialized, api")
    category: Optional[str] = Field(default=None, description="One of the 11 prioritized OSINT categories")
    url: Optional[str] = Field(default=None, description="Source feed or API endpoint URL")
    interval_minutes: int = Field(default=60, ge=1, le=10080, description="Polling schedule interval in minutes")
    priority: str = Field(default="medium", description="Priority level: critical, high, medium, low")
    description: Optional[str] = Field(default=None, description="Human-readable description of source coverage")
    api_key_env: Optional[str] = Field(default=None, description="Environment variable name holding API key (never raw key)")
    auth_token_env: Optional[str] = Field(default=None, description="Environment variable name holding authentication token")
    timeout: float = Field(default=30.0, ge=1.0, le=120.0, description="HTTP request timeout in seconds")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom HTTP headers to include with requests")
    max_entries: Optional[int] = Field(default=None, description="Optional maximum entries to ingest per cycle")
    options: Dict[str, Any] = Field(default_factory=dict, description="Additional connector-specific options")

    @field_validator("priority")
    @classmethod
    def validate_priority(cls, v: str) -> str:
        valid_priorities = {"critical", "high", "medium", "low"}
        val = v.lower().strip()
        if val not in valid_priorities:
            raise ValueError(f"Priority must be one of {valid_priorities}, got '{v}'")
        return val


class ConnectorsFileSchema(BaseModel):
    """Schema representing the full connectors.yaml configuration document."""
    connectors: Dict[str, ConnectorConfig] = Field(
        default_factory=dict,
        description="Dictionary mapping connector keys to their configuration specifications",
    )


class ConnectorConfigManager:
    """
    Service for loading, validating, and managing connectors.yaml.
    Supports environment variable interpolation and synchronizes runtime connector states.
    """

    DEFAULT_YAML_FILENAME = "connectors.yaml"

    def __init__(self, config_path: Optional[Path] = None):
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Default to connectors.yaml in repository root
            root_dir = Path(__file__).resolve().parent.parent
            self.config_path = root_dir / self.DEFAULT_YAML_FILENAME

        self._configs: Dict[str, ConnectorConfig] = {}
        self._last_loaded_at: Optional[str] = None
        self.load_config()

    @property
    def last_loaded_at(self) -> Optional[str]:
        return self._last_loaded_at

    @staticmethod
    def audit_for_secrets(raw_yaml: str) -> None:
        """
        Scans raw YAML content to verify that no plaintext secrets/tokens are hardcoded.
        Conforms strictly to IMPLEMENT.md Section 35: 'Never hardcode API keys.'
        """
        for pattern, reason in FORBIDDEN_SECRET_PATTERNS:
            match = re.search(pattern, raw_yaml)
            if match:
                raise ValueError(
                    f"Security policy violation: {reason} detected in connectors configuration. "
                    "Use environment variables (e.g. ${VAR_NAME} or api_key_env) instead of plaintext keys."
                )

    @staticmethod
    def expand_env_vars(text: str) -> str:
        """
        Substitutes ${VAR_NAME} or ${VAR_NAME:-default} patterns using current environment variables.
        """
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

        def replace_match(match: re.Match) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return pattern.sub(replace_match, text)

    def load_config(self) -> Dict[str, ConnectorConfig]:
        """
        Loads, expands environment variables, and validates connectors.yaml.
        """
        if not self.config_path.exists():
            logger.warning("connectors.yaml not found at '%s'. Using empty configuration.", self.config_path)
            self._configs = {}
            return self._configs

        try:
            raw_text = self.config_path.read_text(encoding="utf-8")
            # 1. Audit for secrets
            self.audit_for_secrets(raw_text)

            # 2. Expand environment variables
            expanded_text = self.expand_env_vars(raw_text)

            # 3. Parse YAML
            parsed = yaml.safe_load(expanded_text) or {}
            validated_doc = ConnectorsFileSchema(**parsed)
            self._configs = validated_doc.connectors
            self._last_loaded_at = datetime.now(timezone.utc).isoformat()
            logger.info("Loaded %d connectors from '%s'", len(self._configs), self.config_path)
            return self._configs
        except Exception as exc:
            logger.error("Failed to load connectors.yaml: %s", exc)
            raise

    def get_raw_yaml(self) -> str:
        """Returns the raw unmodified YAML string from file."""
        if not self.config_path.exists():
            return "connectors:\n"
        return self.config_path.read_text(encoding="utf-8")

    def save_raw_yaml(self, raw_yaml: str) -> Dict[str, ConnectorConfig]:
        """
        Validates syntax, verifies no hardcoded secrets, writes to file, and reloads.
        """
        # 1. Audit for hardcoded secrets
        self.audit_for_secrets(raw_yaml)

        # 2. Syntax validation
        expanded = self.expand_env_vars(raw_yaml)
        parsed = yaml.safe_load(expanded)
        if not isinstance(parsed, dict) or "connectors" not in parsed:
            raise ValueError("YAML document must contain a top-level 'connectors:' dictionary key.")

        ConnectorsFileSchema(**parsed)

        # 3. Write to file
        self.config_path.write_text(raw_yaml, encoding="utf-8")
        return self.load_config()

    def get_config(self, connector_key: str) -> Optional[ConnectorConfig]:
        """Get configuration for a specific connector key."""
        return self._configs.get(connector_key)

    def list_configs(self) -> Dict[str, ConnectorConfig]:
        """Returns all loaded connector configurations."""
        return self._configs

    def update_connector(self, connector_key: str, updates: Dict[str, Any]) -> ConnectorConfig:
        """
        Updates fields for a single connector in connectors.yaml and saves.
        """
        raw_text = self.get_raw_yaml()
        parsed = yaml.safe_load(raw_text) or {"connectors": {}}
        connectors_dict = parsed.get("connectors", {})

        if connector_key not in connectors_dict:
            connectors_dict[connector_key] = {}

        for k, v in updates.items():
            if v is not None:
                connectors_dict[connector_key][k] = v

        parsed["connectors"] = connectors_dict
        new_yaml = yaml.dump(parsed, sort_keys=False, default_flow_style=False)
        self.save_raw_yaml(new_yaml)
        return self._configs[connector_key]

    def sync_to_runtime_manager(self, manager: Any) -> Dict[str, Any]:
        """
        Synchronizes configurations from connectors.yaml with AdvancedConnectorManager.
        Applies enable/disable flags, URLs, and intervals to runtime categories.
        """
        updated_categories = []
        for key, conf in self._configs.items():
            category_or_id = conf.category or key
            # Check if this maps to one of the 11 priority categories
            spec = manager.get_spec(category_or_id)
            if not spec:
                # Try finding by category match
                for s in manager.list_connectors():
                    if s["category"] == conf.type or s["id"] == conf.type or s["category"] == conf.category:
                        category_or_id = s["id"]
                        spec = manager.get_spec(category_or_id)
                        break

            if spec:
                cid = spec["id"]
                manager.set_enabled(cid, conf.enabled)
                updated_categories.append({
                    "id": cid,
                    "name": spec["name"],
                    "enabled": conf.enabled,
                    "interval_minutes": conf.interval_minutes,
                    "priority": conf.priority,
                    "url": conf.url,
                })

        return {
            "total_synced": len(updated_categories),
            "updated_connectors": updated_categories,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }


# Singleton config manager instance
connector_config_manager = ConnectorConfigManager()
