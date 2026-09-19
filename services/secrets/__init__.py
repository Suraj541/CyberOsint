"""
Secret Management Package.
Conforms to IMPLEMENT.md Section 36 (Step 35: Secret Management).
"""

from services.secrets.base import MANDATORY_SECRETS, SecretManagerBase, SecretMetadata
from services.secrets.factory import get_secret_manager
from services.secrets.masking import mask_connection_url, mask_secret
from services.secrets.providers import (
    AWSSecretManager,
    EncryptedFileSecretManager,
    EnvSecretManager,
    VaultSecretManager,
)
from services.secrets.scanner import (
    RepositorySecretScanner,
    ScanFinding,
    SecretAuditReport,
)

# Global singleton secret manager instance
secret_manager = get_secret_manager()

__all__ = [
    "MANDATORY_SECRETS",
    "SecretManagerBase",
    "SecretMetadata",
    "EnvSecretManager",
    "VaultSecretManager",
    "AWSSecretManager",
    "EncryptedFileSecretManager",
    "get_secret_manager",
    "secret_manager",
    "mask_secret",
    "mask_connection_url",
    "RepositorySecretScanner",
    "ScanFinding",
    "SecretAuditReport",
]
