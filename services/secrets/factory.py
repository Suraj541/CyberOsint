"""
Secret Manager Factory.
Instantiates the configured Secret Manager backend based on runtime configuration.
Conforms to IMPLEMENT.md Section 36: 'Production should use a dedicated secret manager.'
"""

import logging
import os
from typing import Optional

from services.secrets.base import SecretManagerBase
from services.secrets.providers import (
    AWSSecretManager,
    EncryptedFileSecretManager,
    EnvSecretManager,
    VaultSecretManager,
)

logger = logging.getLogger("cyber_osint.services.secrets.factory")


def get_secret_manager(backend: Optional[str] = None) -> SecretManagerBase:
    """
    Factory function returning the active secret manager implementation.
    Supported backends:
      - 'env': Environment variables (default)
      - 'vault': HashiCorp Vault KV v2 secret engine
      - 'aws': AWS Secrets Manager
      - 'encrypted_file': Local encrypted secret file
    """
    selected_backend = (backend or os.environ.get("SECRET_BACKEND", "env")).lower().strip()

    if selected_backend == "vault":
        logger.info("Initializing VaultSecretManager backend")
        return VaultSecretManager()
    elif selected_backend == "aws":
        logger.info("Initializing AWSSecretManager backend")
        return AWSSecretManager()
    elif selected_backend in {"encrypted_file", "file", "encrypted"}:
        logger.info("Initializing EncryptedFileSecretManager backend")
        return EncryptedFileSecretManager()
    else:
        logger.debug("Initializing EnvSecretManager backend (default)")
        return EnvSecretManager()
