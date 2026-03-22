"""
Credential storage and encryption
"""
from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage, SecretsManagerStorage

# Note: EncryptionService is deprecated - credentials are now encrypted by AWS KMS via Secrets Manager
# Kept for backward compatibility only
from engine_onboarding.storage.encryption import EncryptionService

__all__ = [
    'secrets_manager_storage',
    'SecretsManagerStorage',
    'EncryptionService'  # Deprecated - use Secrets Manager instead
]

