"""
Encryption utilities for credentials
"""
from cryptography.fernet import Fernet
import os
import base64
from engine_onboarding.config import settings


class EncryptionService:
    """Service for encrypting/decrypting credentials"""
    
    def __init__(self, key: str = None):
        """
        Initialize encryption service
        
        Args:
            key: Fernet encryption key (base64 encoded). If None, uses settings or generates new.
        """
        if key:
            self.key = key.encode() if isinstance(key, str) else key
        else:
            # Note: Encryption is now handled by AWS KMS via Secrets Manager
            # This service is kept for backward compatibility but is not used
            # Generate a dummy key for initialization
            self.key = Fernet.generate_key()
            print(f"WARNING: EncryptionService is deprecated. Credentials are now encrypted by AWS KMS via Secrets Manager.")
        
        self.cipher = Fernet(self.key)
    
    def encrypt(self, data: str) -> bytes:
        """
        Encrypt data
        
        Args:
            data: String data to encrypt
            
        Returns:
            Encrypted bytes
        """
        return self.cipher.encrypt(data.encode())
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """
        Decrypt data
        
        Args:
            encrypted_data: Encrypted bytes
            
        Returns:
            Decrypted string
        """
        return self.cipher.decrypt(encrypted_data).decode()
    
    def get_key_base64(self) -> str:
        """Get encryption key as base64 string"""
        return base64.b64encode(self.key).decode()


# Global encryption service instance
encryption_service = EncryptionService()

