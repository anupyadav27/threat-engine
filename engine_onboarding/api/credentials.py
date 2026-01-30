"""
Credential management API endpoints
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime

from engine_onboarding.database import get_account, get_provider, update_account
from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
from engine_onboarding.validators import (
    AWSValidator, AzureValidator, GCPValidator,
    AliCloudValidator, OCIValidator, IBMValidator
)


def get_validator(provider_type: str, credential_type: str):
    """Get appropriate validator"""
    provider_lower = provider_type.lower()
    
    if provider_lower == 'aws':
        return AWSValidator()
    elif provider_lower == 'azure':
        return AzureValidator()
    elif provider_lower == 'gcp':
        return GCPValidator()
    elif provider_lower == 'alicloud':
        return AliCloudValidator()
    elif provider_lower == 'oci':
        return OCIValidator()
    elif provider_lower == 'ibm':
        return IBMValidator()
    else:
        raise ValueError(f"Unsupported provider: {provider_type}")

router = APIRouter(prefix="/api/v1/accounts", tags=["credentials"])


@router.post("/{account_id}/credentials")
async def store_credentials(
    account_id: str,
    request: Dict[str, Any]
):
    """Store credentials for an account"""
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    credential_type = request.get("credential_type")
    credentials = request.get("credentials")
    
    if not credential_type or not credentials:
        raise HTTPException(400, "Missing credential_type or credentials")
    
    # Get provider to determine provider_type
    provider = get_provider(account['provider_id'])
    if not provider:
        raise HTTPException(404, f"Provider not found for account {account_id}")
    
    # Normalize credential_type for AWS (users often send "access_key")
    normalized_credential_type = credential_type
    if provider.get("provider_type", "").lower() == "aws" and credential_type == "access_key":
        normalized_credential_type = "aws_access_key"

    # Validate credentials first
    validator = get_validator(provider['provider_type'], normalized_credential_type)
    validation_result = await validator.validate(credentials)
    
    if not validation_result.success:
        raise HTTPException(400, detail={
            "message": validation_result.message,
            "errors": validation_result.errors
        })
    
    # Store credentials in Secrets Manager
    secrets_manager_storage.store(
        account_id=account_id,
        credential_type=normalized_credential_type,
        credentials=credentials
    )
    
    # Update account
    update_account(account_id, {
        'account_number': validation_result.account_number,
        'last_validated_at': datetime.utcnow().isoformat()
    })
    
    return {"status": "stored", "account_id": account_id}


@router.get("/{account_id}/credentials/validate")
async def revalidate_credentials(
    account_id: str
):
    """Re-validate stored credentials"""
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    # Get credentials from Secrets Manager
    try:
        credentials = secrets_manager_storage.retrieve(account_id)
    except ValueError as e:
        raise HTTPException(404, str(e))
    
    # Get provider
    provider = get_provider(account['provider_id'])
    if not provider:
        raise HTTPException(404, f"Provider not found for account {account_id}")
    
    # Validate
    credential_type = credentials.get('credential_type')
    validator = get_validator(provider['provider_type'], credential_type)
    validation_result = await validator.validate(credentials)
    
    if validation_result.success:
        update_account(account_id, {
            'last_validated_at': datetime.utcnow().isoformat(),
            'status': 'active'
        })
    else:
        update_account(account_id, {'status': 'error'})
    
    return {
        "success": validation_result.success,
        "message": validation_result.message,
        "errors": validation_result.errors
    }


@router.delete("/{account_id}/credentials")
async def delete_credentials(
    account_id: str
):
    """Delete credentials for an account"""
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    deleted = secrets_manager_storage.delete(account_id)
    
    if deleted:
        update_account(account_id, {'status': 'pending'})
        return {"status": "deleted", "account_id": account_id}
    else:
        raise HTTPException(404, "No credentials found to delete")

