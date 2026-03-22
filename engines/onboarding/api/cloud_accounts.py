"""
Cloud Accounts API - NEW Schema
Manages cloud accounts using the cloud_accounts table
"""
from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional
from datetime import datetime, timezone
import sys
import os

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger

logger = setup_logger(__name__, engine_name="onboarding")

from engine_onboarding.database.cloud_accounts_operations import (
    create_cloud_account,
    get_cloud_account,
    list_cloud_accounts,
    update_cloud_account,
    delete_cloud_account
)

router = APIRouter(prefix="/api/v1/cloud-accounts", tags=["cloud-accounts"])


@router.post("", status_code=201)
async def create_account(account_data: dict):
    """
    Create a new cloud account

    Phase 1: Initial account creation with pending status
    """
    try:
        logger.info(f"Creating cloud account: {account_data.get('account_id')}")
        account = create_cloud_account(account_data)
        logger.info(f"Cloud account created: {account['account_id']}")
        return account
    except ValueError as e:
        logger.error(f"Validation error creating account: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{account_id}")
async def get_account(account_id: str):
    """
    Get cloud account by ID
    """
    try:
        account = get_cloud_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
        return account
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_accounts(
    customer_id: Optional[str] = Query(None),
    tenant_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000)
):
    """
    List cloud accounts with optional filters
    """
    try:
        filters = {}
        if customer_id:
            filters['customer_id'] = customer_id
        if tenant_id:
            filters['tenant_id'] = tenant_id
        if provider:
            filters['provider'] = provider
        if status:
            filters['account_status'] = status

        accounts = list_cloud_accounts(filters=filters, limit=limit)
        return {
            "accounts": accounts,
            "count": len(accounts)
        }
    except Exception as e:
        logger.error(f"Error listing accounts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{account_id}")
async def update_account(account_id: str, updates: dict):
    """
    Update cloud account
    """
    try:
        account = update_cloud_account(account_id, updates)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
        logger.info(f"Cloud account updated: {account_id}")
        return account
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error updating account: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{account_id}/deployment")
async def deploy_account(account_id: str, deployment_data: dict):
    """
    Phase 2: Deploy account with credentials

    Updates:
    - credential_ref (from Secrets Manager or IAM role ARN)
    - onboarding_id (CloudFormation stack ID or deployment ID)
    - account_onboarding_status = 'deployed'
    """
    try:
        # Extract deployment fields
        updates = {
            'account_onboarding_status': 'deployed',
            'updated_at': datetime.now(timezone.utc)
        }

        if 'credential_ref' in deployment_data:
            updates['credential_ref'] = deployment_data['credential_ref']

        if 'onboarding_id' in deployment_data:
            updates['account_onboarding_id'] = deployment_data['onboarding_id']

        # If credentials provided, store in Secrets Manager
        if 'credentials' in deployment_data:
            from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage

            result = secrets_manager_storage.store(
                account_id=account_id,
                credential_type=deployment_data.get('credential_type', 'aws_access_key'),
                credentials=deployment_data['credentials']
            )

            updates['credential_ref'] = result['secret_name']
            logger.info(f"Credentials stored in Secrets Manager: {result['secret_name']}")

        account = update_cloud_account(account_id, updates)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

        logger.info(f"Cloud account deployed: {account_id}")
        return account
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deploying account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{account_id}/validate-credentials")
async def validate_credentials(account_id: str):
    """
    Phase 2.5: Validate credentials
    """
    try:
        account = get_cloud_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

        # Get credentials from Secrets Manager
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        from engine_onboarding.validators.aws_validator import AWSValidator

        credentials = secrets_manager_storage.retrieve(account_id)
        if not credentials:
            raise HTTPException(status_code=400, detail="No credentials found for account")

        # Validate based on provider
        if account['provider'] == 'aws':
            validator = AWSValidator()
        elif account['provider'] == 'azure':
            from engine_onboarding.validators.azure_validator import AzureValidator
            validator = AzureValidator()
        elif account['provider'] == 'gcp':
            from engine_onboarding.validators.gcp_validator import GCPValidator
            validator = GCPValidator()
        elif account['provider'] == 'ibm':
            from engine_onboarding.validators.ibm_validator import IBMValidator
            validator = IBMValidator()
        elif account['provider'] == 'oci':
            from engine_onboarding.validators.oci_validator import OCIValidator
            validator = OCIValidator()
        elif account['provider'] == 'k8s':
            from engine_onboarding.validators.k8s_validator import K8sValidator
            validator = K8sValidator()
        else:
            raise HTTPException(status_code=400, detail=f"Provider {account['provider']} not yet supported")

        result = await validator.validate(credentials)

        # Update validation status and account_number if returned
        updates = {
            'credential_validation_status': 'valid' if result.success else 'invalid',
            'credential_validation_message': result.message,
            'credential_validated_at': datetime.now(timezone.utc)
        }
        if result.success and hasattr(result, 'account_number') and result.account_number:
            updates['account_number'] = result.account_number

        update_cloud_account(account_id, updates)

        return {
            "success": result.success,
            "account_id": account_id,
            "status": "valid" if result.success else "invalid",
            "message": result.message,
            "errors": getattr(result, 'errors', []),
            "validated_at": datetime.now(timezone.utc).isoformat()
        }

    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error validating credentials for {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{account_id}/validate")
async def validate_and_schedule(account_id: str, validation_data: dict):
    """
    Phase 3: Final validation and schedule creation

    Updates:
    - account_status = 'active'
    - account_onboarding_status = 'validated'
    - schedule_cron_expression
    - schedule_enabled = true
    - schedule_next_run_at (calculated from cron)
    """
    try:
        # Validate credentials first
        creds_validation = await validate_credentials(account_id)
        if not creds_validation['success']:
            raise HTTPException(status_code=400, detail="Credential validation failed")

        # Update with schedule
        from croniter import croniter

        cron_expr = validation_data.get('cron_expression', '0 2 * * *')
        base_time = datetime.now(timezone.utc)
        next_run = croniter(cron_expr, base_time).get_next(datetime)

        updates = {
            'account_status': 'active',
            'account_onboarding_status': 'validated',
            'schedule_cron_expression': cron_expr,
            'schedule_enabled': True,
            'schedule_next_run_at': next_run,
            'schedule_include_regions': validation_data.get('include_regions', []),
            'schedule_include_services': validation_data.get('include_services', []),
            'schedule_engines_requested': validation_data.get('engines_requested', []),
            'updated_at': datetime.now(timezone.utc)
        }

        account = update_cloud_account(account_id, updates)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

        logger.info(f"Cloud account validated and scheduled: {account_id}")
        return account

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating and scheduling account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{account_id}/status")
async def get_account_status(account_id: str):
    """
    Get the onboarding and scan status for a cloud account.

    Returns a focused status summary without the full account record.
    """
    try:
        account = get_cloud_account(account_id)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

        return {
            "account_id": account_id,
            "account_status": account.get("account_status"),
            "onboarding_status": account.get("account_onboarding_status"),
            "credential_validation_status": account.get("credential_validation_status"),
            "credential_validated_at": account.get("credential_validated_at"),
            "schedule_enabled": account.get("schedule_enabled"),
            "schedule_next_run_at": account.get("schedule_next_run_at"),
            "last_scan_at": account.get("last_scan_at"),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving status for account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{account_id}")
async def delete_account(account_id: str):
    """
    Delete (soft delete) cloud account

    Sets account_status = 'deleted'
    """
    try:
        updates = {
            'account_status': 'deleted',
            'updated_at': datetime.now(timezone.utc)
        }

        account = update_cloud_account(account_id, updates)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

        logger.info(f"Cloud account deleted: {account_id}")
        return {"message": f"Account {account_id} deleted successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
