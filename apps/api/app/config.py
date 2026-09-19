"""
Application Configuration Module
Loads environment variables and validates platform runtime settings using Pydantic Settings.
"""

import os
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform runtime settings with secure defaults and environment loading."""

    # Project metadata
    PROJECT_NAME: str = "Cybersecurity OSINT Intelligence Platform API"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"

    # Runtime environment
    ENVIRONMENT: str = Field(default="development", description="Current environment (development, staging, production)")
    DEBUG: bool = Field(default=True, description="Enable debug mode")
    LOG_LEVEL: str = Field(default="INFO", description="Application log level")

    # Server settings
    API_HOST: str = Field(default="0.0.0.0", description="API bind host")
    API_PORT: int = Field(default=8000, description="API bind port")
    SECRET_KEY: str = Field(
        default="development_secret_key_please_change_in_production_32_chars_min",
        description="Cryptographic secret key for signing tokens",
    )
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    # CORS Settings
    CORS_ORIGINS: Union[str, List[str]] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:8000"],
        description="Allowed CORS origin domains",
    )

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    # PostgreSQL Database Configuration
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "cyber_osint"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres_secure_pass"
    DATABASE_URL: str = Field(
        default="postgresql://postgres:postgres_secure_pass@localhost:5432/cyber_osint",
        description="Full SQLAlchemy database connection string",
    )

    # Fallback SQLite support for offline testing without running PostgreSQL
    USE_SQLITE_FALLBACK: bool = Field(
        default=True,
        description="Fallback to SQLite when PostgreSQL is unreachable during offline test runs",
    )
    SQLITE_DATABASE_URL: str = "sqlite:///./cyber_osint_dev.db"

    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_URL: str = "redis://localhost:6379/0"

    # OpenSearch Configuration (Step 17 / Section 18)
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    OPENSEARCH_URL: str = Field(
        default="http://localhost:9200",
        description="OpenSearch cluster connection URL",
    )
    OPENSEARCH_INDEX: str = "cyber_osint_content"
    OPENSEARCH_ENABLED: bool = Field(
        default=True,
        description="Enable OpenSearch indexing (falls back gracefully if offline)",
    )

    # Section 36 (Step 35: Secret Management) Core Environment Variables
    SEARCH_URL: Optional[str] = Field(
        default=None,
        description="Search cluster connection URL (aliases OPENSEARCH_URL per IMPLEMENT.md Section 36)",
    )
    AI_API_KEY: Optional[str] = Field(
        default=None,
        description="API key for AI LLM intelligence synthesis and threat analysis",
    )
    MISTRAL_API_KEY: Optional[str] = Field(
        default=None,
        description="API key for Mistral AI LLM intelligence synthesis and summarization",
    )
    MISTRAL_MODEL: str = Field(
        default="auto",
        description="Mistral AI model name or 'auto' for automatic capability detection",
    )
    VIDEO_API_KEY: Optional[str] = Field(
        default=None,
        description="API key for video platform integration",
    )
    GITHUB_TOKEN: Optional[str] = Field(
        default=None,
        description="GitHub Personal Access Token for advisories and exploit PoCs",
    )
    SECRET_BACKEND: str = Field(
        default="env",
        description="Active secret manager backend: env, vault, aws, or encrypted_file",
    )

    # Ingestion Controls
    INGESTION_CONCURRENCY: int = 5
    DEFAULT_FETCH_TIMEOUT_SECONDS: int = 30
    MAX_CONTENT_PAYLOAD_SIZE_MB: int = 10
    DEFAULT_USER_AGENT: str = "CyberOSINT-Intelligence-Bot/1.0 (+https://cyber-osint.local/bot)"

    # Security Controls (Section 37 Step 36)
    SSRF_PROTECTION_ENABLED: bool = True
    ALLOW_PRIVATE_SUBNETS: bool = False
    MAX_REDIRECTS: int = 3
    AUTH_ENFORCED: bool = Field(default=False, description="Enforce mandatory authentication on all endpoints")
    RATE_LIMIT_ENABLED: bool = Field(default=True, description="Enforce tiered sliding window rate limiting")
    SECURITY_HEADERS_ENABLED: bool = Field(default=True, description="Inject OWASP defensive security headers")

    # Scheduler Settings
    ENABLE_SCHEDULER: bool = Field(default=True, description="Enable periodic background scheduler")
    SCHEDULER_RSS_INTERVAL_MINUTES: int = Field(default=30, description="Periodic RSS ingestion interval in minutes")
    SCHEDULER_CHECK_INTERVAL_SECONDS: float = Field(default=5.0, description="Scheduler loop resolution in seconds")

    @field_validator("SEARCH_URL", mode="after")
    @classmethod
    def set_search_url_default(cls, v: Optional[str]) -> str:
        if v:
            return v
        return "http://localhost:9200"

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieves a secret dynamically via the active SecretManager backend."""
        try:
            from services.secrets import secret_manager
            val = secret_manager.get_secret(key, default)
            return val if val is not None else getattr(self, key, default)
        except Exception:
            return getattr(self, key, default)

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()

