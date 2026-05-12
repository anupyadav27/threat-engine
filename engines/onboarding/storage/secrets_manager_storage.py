"""
AWS Secrets Manager integration for credential storage
"""
import boto3
import json
from typing import Dict, Any, Optional
from botocore.exceptions import ClientError
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Secrets Manager client — built lazily so region is read at call time, not import time
def _make_secrets_client():
    region = os.getenv('AWS_REGION')
    if not region:
        raise RuntimeError("AWS_REGION env var is required for Secrets Manager")
    return boto3.client('secretsmanager', region_name=region)

secrets_client = _make_secrets_client()

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
    
    def _get_secret_name(self, account_id: str, tenant_id: Optional[str] = None) -> str:
        """Generate secret name scoped by tenant and account.

        New format: {prefix}/account/{tenant_id}/{account_id}
        Legacy format (no tenant_id): {prefix}/account/{account_id}
        """
        if tenant_id:
            return f"{self.prefix}/account/{tenant_id}/{account_id}"
        return f"{self.prefix}/account/{account_id}"

    def store(
        self,
        account_id: str,
        credential_type: str,
        credentials: Dict[str, Any],
        tenant_id: Optional[str] = None,
        expires_at: Optional[str] = None,
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
        secret_name = self._get_secret_name(account_id, tenant_id)

        # Prepare secret value
        secret_value = {
            'credential_type': credential_type,
            'credentials': credentials,
            'account_id': account_id,
            'tenant_id': tenant_id,
            'created_at': datetime.now(timezone.utc).isoformat(),
            'expires_at': expires_at,
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
    
    def retrieve(self, account_id: str, tenant_id: Optional[str] = None, credential_ref: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve credentials from Secrets Manager.

        Lookup order:
        1. ``credential_ref`` — full SM path stored in the DB (most specific, handles both formats)
        2. ``tenant_id`` + ``account_id`` — new tenant-scoped path
        3. ``account_id`` alone — legacy path for backwards compatibility

        Raises:
            ValueError: If secret not found or expired
        """
        # Use the stored credential_ref directly when available — it is the authoritative path.
        if credential_ref and "/" in credential_ref:
            secret_name = credential_ref
        else:
            secret_name = self._get_secret_name(account_id, tenant_id)

        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response['SecretString'])

            if secret_data.get('expires_at'):
                expires_at = datetime.fromisoformat(secret_data['expires_at'].replace('Z', '+00:00'))
                if expires_at < datetime.now(timezone.utc).replace(tzinfo=expires_at.tzinfo):
                    raise ValueError(f"Credentials for account {account_id} have expired")

            credentials = secret_data.get('credentials', {})
            credentials['credential_type'] = secret_data.get('credential_type')
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

    def store_agent_token(self, account_id: str, raw_token: str, tenant_id: Optional[str] = None) -> Dict[str, Any]:
        """Store an agent registration token in Secrets Manager.

        The raw token is stored at ``threat-engine/account/{tenant_id}/{account_id}`` under
        the key ``agent_token``.  The hash is NOT stored here — only the DB
        holds the SHA-256 digest.  This is the ONLY place the raw token lives
        after the HTTP response is sent to the caller.

        Args:
            account_id: UUID of the cloud_account the agent registers against.
            raw_token: The UUID4 raw agent token string.  NEVER log this value.
            tenant_id: Tenant that owns the account — scopes the SM path.

        Returns:
            Dict with ``secret_arn``, ``secret_name``, ``account_id``.
        """
        secret_name = self._get_secret_name(account_id, tenant_id)

        # Merge agent_token into existing secret or create a new one.
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_name)
            existing: Dict[str, Any] = json.loads(response["SecretString"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                existing = {}
            else:
                raise

        existing["agent_token"] = raw_token
        existing["agent_token_updated_at"] = datetime.now(timezone.utc).isoformat()

        try:
            result = self.secrets_client.update_secret(
                SecretId=secret_name,
                SecretString=json.dumps(existing),
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                create_params: Dict[str, Any] = {
                    "Name": secret_name,
                    "SecretString": json.dumps(existing),
                    "Description": f"Threat Engine agent token for account {account_id}",
                }
                if self.kms_key_id:
                    create_params["KmsKeyId"] = self.kms_key_id
                result = self.secrets_client.create_secret(**create_params)
            else:
                raise

        logger.info("Agent token stored in SM for account %s", account_id)
        return {
            "secret_arn": result["ARN"],
            "secret_name": secret_name,
            "account_id": account_id,
        }


# Global instance
secrets_manager_storage = SecretsManagerStorage()

