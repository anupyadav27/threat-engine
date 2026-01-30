"""
AWS Secrets Manager integration for credential storage
"""
import boto3
import json
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
import os
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Secrets Manager client
secrets_client = boto3.client('secretsmanager', region_name=os.getenv('AWS_REGION', 'ap-south-1'))

# KMS Key ID for encryption (optional - Secrets Manager uses default if not specified)
KMS_KEY_ID = os.getenv('SECRETS_MANAGER_KMS_KEY_ID')

# Secret name prefix
SECRET_NAME_PREFIX = os.getenv('SECRETS_MANAGER_PREFIX', 'threat-engine')


class SecretsManagerStorage:
    """Service for storing and retrieving credentials from AWS Secrets Manager"""
    
    def __init__(self):
        self.secrets_client = secrets_client
        self.kms_key_id = KMS_KEY_ID
        self.prefix = SECRET_NAME_PREFIX
    
    def _get_secret_name(self, account_id: str) -> str:
        """Generate secret name for account"""
        return f"{self.prefix}/account/{account_id}"
    
    def store(
        self,
        account_id: str,
        credential_type: str,
        credentials: Dict[str, Any],
        expires_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Store credentials in Secrets Manager
        
        Args:
            account_id: Account UUID
            credential_type: Type of credential (e.g., 'aws_iam_role')
            credentials: Credential data dictionary
            expires_at: Optional expiration timestamp (ISO format)
            
        Returns:
            Dict with secret ARN and metadata
        """
        secret_name = self._get_secret_name(account_id)
        
        # Prepare secret value
        secret_value = {
            'credential_type': credential_type,
            'credentials': credentials,
            'account_id': account_id,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': expires_at
        }
        
        try:
            # Try to update existing secret
            response = self.secrets_client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(secret_value),
                Description=f"Threat Engine credentials for account {account_id}"
            )
            logger.info(f"Updated secret: {secret_name}")
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                # Create new secret
                create_params = {
                    'Name': secret_name,
                    'SecretString': json.dumps(secret_value),
                    'Description': f"Threat Engine credentials for account {account_id}"
                }
                
                # Use KMS key if specified
                if self.kms_key_id:
                    create_params['KmsKeyId'] = self.kms_key_id
                
                response = self.secrets_client.create_secret(**create_params)
                logger.info(f"Created secret: {secret_name}")
            else:
                raise
        
        return {
            'secret_arn': response['ARN'],
            'secret_name': secret_name,
            'account_id': account_id,
            'credential_type': credential_type
        }
    
    def retrieve(self, account_id: str) -> Dict[str, Any]:
        """
        Retrieve credentials from Secrets Manager
        
        Args:
            account_id: Account UUID
            
        Returns:
            Decrypted credentials dictionary
            
        Raises:
            ValueError: If secret not found
        """
        secret_name = self._get_secret_name(account_id)
        
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response['SecretString'])
            
            # Check expiration
            if secret_data.get('expires_at'):
                expires_at = datetime.fromisoformat(secret_data['expires_at'].replace('Z', '+00:00'))
                if expires_at < datetime.utcnow().replace(tzinfo=expires_at.tzinfo):
                    raise ValueError(f"Credentials for account {account_id} have expired")
            
            # Return credentials
            credentials = secret_data.get('credentials', {})
            credentials['credential_type'] = secret_data.get('credential_type')
            
            # Update last_used_at (store in metadata, not in secret itself)
            # Note: Secrets Manager doesn't support metadata updates easily
            # Consider storing last_used_at in DynamoDB instead
            
            return credentials
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise ValueError(f"No credentials found for account {account_id}")
            raise
    
    def delete(self, account_id: str) -> bool:
        """
        Delete credentials from Secrets Manager
        
        Args:
            account_id: Account UUID
            
        Returns:
            True if deleted, False if not found
        """
        secret_name = self._get_secret_name(account_id)
        
        try:
            # Schedule deletion (7 days recovery window)
            self.secrets_client.delete_secret(
                SecretId=secret_name,
                RecoveryWindowInDays=7  # Allows recovery within 7 days
            )
            logger.info(f"Scheduled deletion of secret: {secret_name}")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                logger.warning(f"Secret not found: {secret_name}")
                return False
            raise
    
    def rotate_secret(self, account_id: str) -> Dict[str, Any]:
        """
        Rotate secret (if automatic rotation is enabled)
        
        Args:
            account_id: Account UUID
            
        Returns:
            Rotation status
        """
        secret_name = self._get_secret_name(account_id)
        
        try:
            response = self.secrets_client.rotate_secret(SecretId=secret_name)
            return {
                'arn': response['ARN'],
                'name': response['Name'],
                'version_id': response.get('VersionId')
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidRequestException':
                logger.warning(f"Rotation not enabled for secret: {secret_name}")
                return {'error': 'Rotation not enabled'}
            raise
    
    def get_secret_metadata(self, account_id: str) -> Dict[str, Any]:
        """
        Get secret metadata (without retrieving the secret value)
        
        Args:
            account_id: Account UUID
            
        Returns:
            Secret metadata
        """
        secret_name = self._get_secret_name(account_id)
        
        try:
            response = self.secrets_client.describe_secret(SecretId=secret_name)
            return {
                'arn': response['ARN'],
                'name': response['Name'],
                'created_date': response['CreatedDate'].isoformat(),
                'last_changed_date': response.get('LastChangedDate', response['CreatedDate']).isoformat(),
                'last_accessed_date': response.get('LastAccessedDate'),
                'rotation_enabled': response.get('RotationEnabled', False),
                'kms_key_id': response.get('KmsKeyId')
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                raise ValueError(f"No credentials found for account {account_id}")
            raise


# Global instance
secrets_manager_storage = SecretsManagerStorage()

