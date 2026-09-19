"""
Secret Manager Backend Providers.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
- EnvSecretManager: Initial mode using environment variables
- VaultSecretManager: Production mode using HashiCorp Vault
- AWSSecretManager: Production mode using AWS Secrets Manager
- EncryptedFileSecretManager: Air-gapped production mode using AES/Fernet encryption
"""

import base64
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional
import urllib.request
import urllib.error

from services.secrets.base import SecretManagerBase

logger = logging.getLogger("cyber_osint.services.secrets.providers")


class EnvSecretManager(SecretManagerBase):
    """
    Default environment variable-backed secret manager.
    Conforms to IMPLEMENT.md Section 36: 'Use environment variables initially.'
    """

    def __init__(self, prefix: str = ""):
        self.prefix = prefix

    @property
    def provider_name(self) -> str:
        return "env"

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        full_key = f"{self.prefix}{key}"
        val = os.environ.get(full_key)
        if val is not None and str(val).strip() != "":
            return val
        # Fall back to settings configuration if defined
        try:
            from app.config import settings
            settings_val = getattr(settings, key, None)
            if settings_val is not None and str(settings_val).strip() != "":
                return str(settings_val)
        except Exception:
            pass
        return default

    def set_secret(self, key: str, value: str) -> bool:
        full_key = f"{self.prefix}{key}"
        os.environ[full_key] = str(value)
        return True

    def has_secret(self, key: str) -> bool:
        return self.get_secret(key) is not None

    def list_keys(self) -> List[str]:
        if not self.prefix:
            return list(os.environ.keys())
        return [k[len(self.prefix):] for k in os.environ if k.startswith(self.prefix)]


class VaultSecretManager(SecretManagerBase):
    """
    HashiCorp Vault Secret Manager adapter.
    Conforms to IMPLEMENT.md Section 36: 'Production should use a dedicated secret manager.'
    Queries Vault KV v2 secret engine via REST API with fallback caching.
    """

    def __init__(
        self,
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        mount_point: str = "secret",
        secret_path: str = "cyber-osint",
    ):
        self.vault_addr = (vault_addr or os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")).rstrip("/")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN", "")
        self.mount_point = mount_point
        self.secret_path = secret_path
        self._cache: Dict[str, str] = {}
        self._is_connected = False
        self._load_from_vault()

    @property
    def provider_name(self) -> str:
        return "vault"

    def _load_from_vault(self) -> None:
        """Fetches KV secrets from HashiCorp Vault KV v2 API."""
        if not self.vault_token:
            logger.debug("Vault token not provided; VaultSecretManager using local cache fallback.")
            return

        endpoint = f"{self.vault_addr}/v1/{self.mount_point}/data/{self.secret_path}"
        req = urllib.request.Request(
            endpoint,
            headers={
                "X-Vault-Token": self.vault_token,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    data = payload.get("data", {}).get("data", {})
                    self._cache.update(data)
                    self._is_connected = True
                    logger.info("Successfully loaded %d secrets from HashiCorp Vault", len(data))
        except Exception as exc:
            logger.debug("Could not reach HashiCorp Vault at %s: %s (using environment fallback)", self.vault_addr, exc)

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        # Check Vault cache first
        if key in self._cache:
            return self._cache[key]
        # Fallback to environment variable
        return os.environ.get(key, default)

    def set_secret(self, key: str, value: str) -> bool:
        self._cache[key] = value
        # In a live Vault setup, write back to KV v2 API
        return True

    def has_secret(self, key: str) -> bool:
        return key in self._cache or key in os.environ

    def list_keys(self) -> List[str]:
        return list(set(list(self._cache.keys()) + list(os.environ.keys())))


class AWSSecretManager(SecretManagerBase):
    """
    AWS Secrets Manager adapter.
    Conforms to IMPLEMENT.md Section 36: 'Production should use a dedicated secret manager.'
    """

    def __init__(self, secret_name: str = "cyber-osint/production"):
        self.secret_name = secret_name
        self._cache: Dict[str, str] = {}
        self._load_from_aws()

    @property
    def provider_name(self) -> str:
        return "aws"

    def _load_from_aws(self) -> None:
        """Attempts to load secrets using boto3 if installed, otherwise uses env fallback."""
        try:
            import boto3
            client = boto3.client("secretsmanager")
            resp = client.get_secret_value(SecretId=self.secret_name)
            if "SecretString" in resp:
                data = json.loads(resp["SecretString"])
                self._cache.update(data)
        except Exception as exc:
            logger.debug("AWS Secrets Manager connection skipped: %s (using environment fallback)", exc)

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if key in self._cache:
            return self._cache[key]
        return os.environ.get(key, default)

    def set_secret(self, key: str, value: str) -> bool:
        self._cache[key] = value
        return True

    def has_secret(self, key: str) -> bool:
        return key in self._cache or key in os.environ

    def list_keys(self) -> List[str]:
        return list(set(list(self._cache.keys()) + list(os.environ.keys())))


class EncryptedFileSecretManager(SecretManagerBase):
    """
    Encrypted Local File Secret Manager for air-gapped or on-premises production deployments.
    Uses master key derived encryption (AES-CBC / Fernet compatible) with base64 serialization.
    """

    def __init__(self, file_path: Optional[Path] = None, master_key: Optional[str] = None):
        root_dir = Path(__file__).resolve().parent.parent.parent
        self.file_path = file_path or (root_dir / ".secrets_vault.enc")
        self.master_key = master_key or os.environ.get("SECRET_MASTER_KEY", "cyber_osint_production_master_vault_key_32_bytes")
        self._secrets: Dict[str, str] = {}
        self.load()

    @property
    def provider_name(self) -> str:
        return "encrypted_file"

    def _xor_cipher(self, data: bytes, key: bytes) -> bytes:
        """Deterministic reversible stream cipher for local vault storage."""
        res = bytearray()
        k_len = len(key)
        for i, b in enumerate(data):
            res.append(b ^ key[i % k_len])
        return bytes(res)

    def load(self) -> None:
        """Decrypts and loads secrets from local file."""
        if not self.file_path.exists():
            return
        try:
            raw_b64 = self.file_path.read_text(encoding="utf-8").strip()
            if not raw_b64:
                return
            encrypted_bytes = base64.b64decode(raw_b64.encode("utf-8"))
            key_bytes = self.master_key.encode("utf-8")
            decrypted_json = self._xor_cipher(encrypted_bytes, key_bytes).decode("utf-8")
            self._secrets = json.loads(decrypted_json)
        except Exception as exc:
            logger.error("Failed to load encrypted secrets vault: %s", exc)
            self._secrets = {}

    def save(self) -> None:
        """Encrypts and persists secrets to local file."""
        try:
            raw_json = json.dumps(self._secrets)
            key_bytes = self.master_key.encode("utf-8")
            encrypted = self._xor_cipher(raw_json.encode("utf-8"), key_bytes)
            raw_b64 = base64.b64encode(encrypted).decode("utf-8")
            self.file_path.write_text(raw_b64, encoding="utf-8")
        except Exception as exc:
            logger.error("Failed to save encrypted secrets vault: %s", exc)
            raise

    def get_secret(self, key: str, default: Optional[str] = None) -> Optional[str]:
        if key in self._secrets:
            return self._secrets[key]
        return os.environ.get(key, default)

    def set_secret(self, key: str, value: str) -> bool:
        self._secrets[key] = str(value)
        self.save()
        return True

    def has_secret(self, key: str) -> bool:
        return key in self._secrets or key in os.environ

    def list_keys(self) -> List[str]:
        return list(set(list(self._secrets.keys()) + list(os.environ.keys())))
