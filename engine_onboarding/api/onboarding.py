"""
Account onboarding API endpoints
"""
import uuid
import json
import sys
import os
from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime

# Add common to path for logger import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger, LogContext

logger = setup_logger(__name__, engine_name="onboarding")

from engine_onboarding.database import (
    get_tenant, create_tenant, get_provider_by_tenant_and_type,
    create_provider, create_account, get_account, update_account,
    list_accounts_by_tenant
)
from engine_onboarding.models.account import AccountCreate, AccountResponse, AccountUpdate, OnboardingInitRequest
from engine_onboarding.validators import (
    AWSValidator, AzureValidator, GCPValidator,
    AliCloudValidator, OCIValidator, IBMValidator
)
from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
from engine_onboarding.utils.helpers import generate_external_id
from engine_onboarding.config import settings

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])


def get_validator(provider_type: str, credential_type: str):
    """Get appropriate validator for provider and credential type"""
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


@router.get("/{provider}/auth-methods")
async def get_available_auth_methods(provider: str):
    """Get available authentication methods for a provider"""
    methods = {
        "aws": [
            {
                "method": "iam_role",
                "name": "IAM Role (Recommended)",
                "description": "Secure cross-account role assumption",
                "requires": ["role_arn", "external_id", "account_number"],
                "cloudformation_supported": True
            },
            {
                "method": "access_key",
                "name": "Access Key",
                "description": "IAM user access key and secret",
                "requires": ["access_key_id", "secret_access_key"],
                "cloudformation_supported": False
            }
        ],
        "azure": [
            {
                "method": "service_principal",
                "name": "Service Principal",
                "description": "Azure AD service principal with client secret",
                "requires": ["client_id", "client_secret", "tenant_id", "subscription_id"]
            }
        ],
        "gcp": [
            {
                "method": "service_account",
                "name": "Service Account JSON",
                "description": "Service account key file (JSON)",
                "requires": ["service_account_json"]
            }
        ],
        "alicloud": [
            {
                "method": "access_key",
                "name": "Access Key",
                "description": "AliCloud AccessKey ID and Secret",
                "requires": ["access_key_id", "access_key_secret"]
            }
        ],
        "oci": [
            {
                "method": "user_principal",
                "name": "User Principal",
                "description": "OCI user OCID with API key",
                "requires": ["user_ocid", "tenancy_ocid", "fingerprint", "private_key", "region"]
            }
        ],
        "ibm": [
            {
                "method": "api_key",
                "name": "API Key",
                "description": "IBM Cloud API key",
                "requires": ["api_key"]
            }
        ]
    }
    
    if provider.lower() not in methods:
        raise HTTPException(404, f"Provider {provider} not supported")
    
    return {"provider": provider, "methods": methods[provider.lower()]}


@router.post("/{provider}/init")
async def init_onboarding(
    provider: str,
    request: OnboardingInitRequest
):
    """Initialize onboarding for any provider"""
    tenant_id = request.tenant_id
    account_name = request.account_name
    auth_method = request.auth_method or ("iam_role" if provider.lower() == "aws" else "service_principal")
    
    with LogContext(tenant_id=tenant_id):
        logger.info("Initializing onboarding", extra={
            "extra_fields": {
                "provider": provider,
                "account_name": account_name,
                "auth_method": auth_method
            }
        })
        
        if not all([tenant_id, account_name]):
            logger.warning("Missing required fields", extra={
                "extra_fields": {"tenant_id": tenant_id, "account_name": account_name}
            })
            raise HTTPException(400, "Missing required fields: tenant_id, account_name")
        
        # Verify tenant exists
        tenant = get_tenant(tenant_id)
        if not tenant:
            logger.warning("Tenant not found", extra={"extra_fields": {"tenant_id": tenant_id}})
            raise HTTPException(404, f"Tenant {tenant_id} not found")
    
    # Get or create provider
    # Use provider_id from request if provided, otherwise get/create by tenant and type
    if request.provider_id:
        from engine_onboarding.database import get_provider
        provider_obj = get_provider(request.provider_id)
        if not provider_obj:
            raise HTTPException(404, f"Provider {request.provider_id} not found")
    else:
        provider_obj = get_provider_by_tenant_and_type(tenant_id, provider.lower())
        if not provider_obj:
            provider_obj = create_provider(tenant_id, provider.lower())
    
    # Generate onboarding data
    onboarding_id = str(uuid.uuid4())
    external_id = generate_external_id() if provider.lower() == "aws" and auth_method == "iam_role" else None
    
    # Create account record
    account = create_account(
        provider_id=provider_obj['provider_id'],
        tenant_id=tenant_id,
        account_name=account_name
    )
    
    # Update account with onboarding_id
    update_account(account['account_id'], {'onboarding_id': onboarding_id})
    
    onboarding_data = {
        "onboarding_id": onboarding_id,
        "account_id": account['account_id'],
        "provider": provider.lower(),
        "auth_method": auth_method,
        "account_name": account_name,
        "external_id": external_id
    }
    
    if provider.lower() == "aws" and auth_method == "iam_role" and external_id:
        onboarding_data["cloudformation_template_url"] = (
            f"/api/v1/onboarding/aws/cloudformation-template?external_id={external_id}"
        )
    
    return onboarding_data


@router.get("/aws/cloudformation-template")
async def get_cloudformation_template(external_id: str):
    """Get CloudFormation template for AWS IAM role"""
    template_path = Path(__file__).parent.parent / "templates" / "aws_cloudformation.yaml"
    
    if not template_path.exists():
        raise HTTPException(500, "CloudFormation template not found")
    
    template_content = template_path.read_text()
    
    # Replace placeholders
    template_content = template_content.replace(
        '{{EXTERNAL_ID}}', external_id
    ).replace(
        '{{PLATFORM_ACCOUNT_ID}}', settings.platform_aws_account_id or 'YOUR_PLATFORM_ACCOUNT_ID'
    )
    
    return {
        "template": template_content,
        "external_id": external_id,
        "platform_account_id": settings.platform_aws_account_id or 'YOUR_PLATFORM_ACCOUNT_ID'
    }


@router.post("/{provider}/validate")
async def validate_and_activate_account(
    provider: str,
    request: Dict[str, Any]
):
    """Validate credentials and activate account"""
    account_id = request.get("account_id")
    auth_method = request.get("auth_method")
    credentials_data = request.get("credentials")
    
    if not all([account_id, auth_method, credentials_data]):
        raise HTTPException(400, "Missing required fields: account_id, auth_method, credentials")
    
    # Get account
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    # Get provider to determine provider_type
    from engine_onboarding.database import get_provider
    provider_obj = get_provider(account['provider_id'])
    if not provider_obj:
        raise HTTPException(404, f"Provider not found for account {account_id}")
    
    # Determine credential type
    credential_type_map = {
        "aws": {
            "iam_role": "aws_iam_role",
            "access_key": "aws_access_key"
        },
        "azure": {
            "service_principal": "azure_service_principal"
        },
        "gcp": {
            "service_account": "gcp_service_account"
        },
        "alicloud": {
            "access_key": "alicloud_access_key"
        },
        "oci": {
            "user_principal": "oci_user_principal"
        },
        "ibm": {
            "api_key": "ibm_api_key"
        }
    }
    
    credential_type = credential_type_map.get(provider.lower(), {}).get(auth_method)
    if not credential_type:
        raise HTTPException(400, f"Invalid auth method {auth_method} for provider {provider}")
    
    # Add credential type to credentials
    credentials_data['credential_type'] = credential_type
    
    # Validate credentials
    validator = get_validator(provider, credential_type)
    validation_result = await validator.validate(credentials_data)
    
    if not validation_result.success:
        update_account(account_id, {
            'status': 'error',
            'onboarding_status': 'failed'
        })
        raise HTTPException(400, detail={
            "message": validation_result.message,
            "errors": validation_result.errors
        })
    
    # Store credentials in Secrets Manager (with error handling)
    from engine_common.logger import audit_log
    
    with LogContext(tenant_id=account.get('tenant_id'), account_id=account_id):
        try:
            secrets_manager_storage.store(
                account_id=account_id,
                credential_type=credential_type,
                credentials=credentials_data
            )
            credentials_stored = True
            logger.info("Credentials stored successfully")
            audit_log(
                logger,
                "credentials_stored",
                f"account:{account_id}",
                tenant_id=account.get('tenant_id'),
                result="success",
                details={
                    "credential_type": credential_type,
                    "account_number": validation_result.account_number
                }
            )
        except Exception as e:
            logger.warning("Failed to store credentials in Secrets Manager", exc_info=True, extra={
                "extra_fields": {"error": str(e)}
            })
            logger.warning("Account will be activated but credentials not stored. IRSA may not be configured.")
            credentials_stored = False
            audit_log(
                logger,
                "credentials_storage_failed",
                f"account:{account_id}",
                tenant_id=account.get('tenant_id'),
                result="failure",
                details={"error": str(e)}
            )
    
    # Update account
    update_account(account_id, {
        'status': 'active',
        'onboarding_status': 'completed',
        'account_number': validation_result.account_number,
        'last_validated_at': datetime.utcnow().isoformat()
    })
    
    response = {
        "success": True,
        "message": "Account successfully onboarded and validated",
        "account_id": account_id,
        "account_number": validation_result.account_number
    }
    
    if not credentials_stored:
        response["warning"] = "Credentials validated but not stored in Secrets Manager (IRSA not configured)"
    
    return response


@router.post("/{provider}/validate-json")
async def validate_from_json(
    provider: str,
    request: Dict[str, Any]
):
    """Validate account using JSON output from CloudFormation"""
    try:
        onboarding_json = request.get("onboarding_json")
        if isinstance(onboarding_json, str):
            cf_output = json.loads(onboarding_json)
        else:
            cf_output = onboarding_json
        
        # Extract values
        account_number = cf_output.get('account_id') or cf_output.get('AccountId')
        role_arn = cf_output.get('role_arn') or cf_output.get('RoleArn')
        external_id = cf_output.get('external_id') or cf_output.get('ExternalId')
        
        if not all([account_number, role_arn, external_id]):
            raise HTTPException(400, "Invalid JSON format - must contain: account_id, role_arn, external_id")
        
        # Find account by external_id (stored in onboarding_id or lookup)
        # For now, require account_id in request
        account_id = request.get("account_id")
        if not account_id:
            raise HTTPException(400, "account_id required in request")
        
        account = get_account(account_id)
        if not account:
            raise HTTPException(404, f"Account {account_id} not found")
        
        # Prepare credentials
        credentials = {
            "credential_type": "aws_iam_role",
            "role_arn": role_arn,
            "external_id": external_id,
            "account_number": account_number
        }
        
        # Validate
        return await validate_and_activate_account(
            provider="aws",
            request={
                "account_id": account_id,
                "auth_method": "iam_role",
                "credentials": credentials
            }
        )
        
    except json.JSONDecodeError as e:
        raise HTTPException(400, f"Invalid JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(500, f"Validation error: {str(e)}")


@router.get("/accounts")
async def list_accounts(
    tenant_id: str = None,
    provider_type: str = None
):
    """List accounts with optional filters"""
    if tenant_id:
        accounts = list_accounts_by_tenant(tenant_id)
    else:
        # If no tenant_id, we'd need to scan - for now require tenant_id
        raise HTTPException(400, "tenant_id is required")
    
    # Filter by provider_type if specified
    if provider_type:
        from engine_onboarding.database import get_provider
        accounts = [
            a for a in accounts
            if get_provider(a['provider_id']) and 
            get_provider(a['provider_id'])['provider_type'] == provider_type.lower()
        ]
    
    return {
        "accounts": [
            {
                "account_id": a['account_id'],
                "account_name": a['account_name'],
                "account_number": a.get('account_number'),
                "provider_type": get_provider(a['provider_id'])['provider_type'] if get_provider(a['provider_id']) else None,
                "status": a['status'],
                "onboarding_status": a.get('onboarding_status', 'pending'),
                "created_at": a.get('created_at', '')
            }
            for a in accounts
        ]
    }


@router.get("/accounts/{account_id}")
async def get_account_details(account_id: str):
    """Get account details"""
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    from engine_onboarding.database import get_provider
    provider = get_provider(account['provider_id'])
    
    return {
        "account_id": account['account_id'],
        "account_name": account['account_name'],
        "account_number": account.get('account_number'),
        "provider_type": provider['provider_type'] if provider else None,
        "status": account['status'],
        "onboarding_status": account.get('onboarding_status', 'pending'),
        "created_at": account.get('created_at', ''),
        "updated_at": account.get('updated_at', ''),
        "last_validated_at": account.get('last_validated_at')
    }


@router.delete("/accounts/{account_id}")
async def delete_account(account_id: str):
    """Delete account and associated credentials"""
    from engine_common.logger import audit_log
    
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    tenant_id = account.get('tenant_id')
    
    with LogContext(tenant_id=tenant_id, account_id=account_id):
        logger.info("Deleting account")
        
        # Delete credentials from Secrets Manager
        try:
            secrets_manager_storage.delete(account_id)
            logger.info("Credentials deleted from Secrets Manager")
        except ValueError:
            pass  # Credentials may not exist
        except Exception as e:
            logger.warning("Failed to delete credentials from Secrets Manager", exc_info=True)
        
        # Delete account from PostgreSQL
        from engine_onboarding.database.connection import get_db_session
        from engine_onboarding.database.models import Account
        
        with get_db_session() as db:
            account_obj = db.query(Account).filter(Account.account_id == account_id).first()
            if account_obj:
                db.delete(account_obj)
                db.commit()
        
        audit_log(
            logger,
            "account_deleted",
            f"account:{account_id}",
            tenant_id=tenant_id,
            result="success",
            details={
                "account_name": account.get('account_name'),
                "provider_type": account.get('provider_type')
            }
        )
        
        logger.info("Account deleted successfully")
        
        return {"status": "deleted", "account_id": account_id}


# ==================== TENANT ENDPOINTS ====================

@router.post("/tenants", status_code=201)
async def create_tenant_endpoint(request: Dict[str, Any]):
    """Create a new tenant"""
    from engine_common.logger import audit_log
    
    tenant_name = request.get("tenant_name")
    description = request.get("description")
    
    if not tenant_name:
        raise HTTPException(400, "tenant_name is required")
    
    # Check if tenant with same name already exists
    from engine_onboarding.database import get_tenant_by_name
    existing = get_tenant_by_name(tenant_name)
    if existing:
        logger.warning("Tenant creation failed - name already exists", extra={
            "extra_fields": {"tenant_name": tenant_name}
        })
        raise HTTPException(409, f"Tenant with name '{tenant_name}' already exists")
    
    tenant = create_tenant(tenant_name, description)
    
    with LogContext(tenant_id=tenant.get('tenant_id')):
        audit_log(
            logger,
            "tenant_created",
            f"tenant:{tenant.get('tenant_id')}",
            tenant_id=tenant.get('tenant_id'),
            result="success",
            details={
                "tenant_name": tenant_name,
                "description": description
            }
        )
        logger.info("Tenant created successfully")
    
    return tenant


@router.get("/tenants")
async def list_tenants_endpoint():
    """List all tenants"""
    from engine_onboarding.database import list_tenants
    tenants = list_tenants()
    return {"tenants": tenants}


@router.get("/tenants/{tenant_id}")
async def get_tenant_endpoint(tenant_id: str):
    """Get tenant by ID"""
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, f"Tenant {tenant_id} not found")
    return tenant


# ==================== PROVIDER ENDPOINTS ====================

@router.post("/providers", status_code=201)
async def create_provider_endpoint(request: Dict[str, Any]):
    """Create a new provider for a tenant"""
    tenant_id = request.get("tenant_id")
    provider_type = request.get("provider_type")
    
    if not tenant_id or not provider_type:
        raise HTTPException(400, "tenant_id and provider_type are required")
    
    # Verify tenant exists
    tenant = get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(404, f"Tenant {tenant_id} not found")
    
    # Valid provider types
    valid_providers = ["aws", "azure", "gcp", "alicloud", "oci", "ibm"]
    if provider_type.lower() not in valid_providers:
        raise HTTPException(400, f"Invalid provider_type. Must be one of: {', '.join(valid_providers)}")
    
    # Create or get existing provider
    provider = create_provider(tenant_id, provider_type.lower())
    return provider


@router.get("/providers")
async def list_providers_endpoint(tenant_id: str = None):
    """List providers, optionally filtered by tenant_id"""
    from engine_onboarding.database import list_providers, list_providers_by_tenant
    
    if tenant_id:
        providers = list_providers_by_tenant(tenant_id)
    else:
        providers = list_providers()
    
    return {"providers": providers}


@router.get("/providers/{provider_id}")
async def get_provider_endpoint(provider_id: str):
    """Get provider by ID"""
    from engine_onboarding.database import get_provider
    provider = get_provider(provider_id)
    if not provider:
        raise HTTPException(404, f"Provider {provider_id} not found")
    return provider


# ==================== ACCOUNT HEALTH & STATISTICS ====================

@router.get("/accounts/{account_id}/health")
async def get_account_health(account_id: str):
    """Get account health status"""
    from engine_onboarding.database import get_account, list_executions_by_account
    from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
    
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    # Check credentials validity
    credentials_valid = False
    last_validation = account.get('last_validated_at')
    
    try:
        # Try to retrieve credentials (if they exist, they're stored)
        secrets_manager_storage.get(account_id)
        credentials_valid = True
    except ValueError:
        # Credentials don't exist
        credentials_valid = False
    except Exception:
        # Other error - assume invalid
        credentials_valid = False
    
    # Get last scan status (via schedules)
    from engine_onboarding.database import list_schedules_by_account, list_executions_by_schedule
    schedules = list_schedules_by_account(account_id)
    all_executions = []
    for schedule in schedules:
        schedule_executions = list_executions_by_schedule(schedule['schedule_id'])
        all_executions.extend(schedule_executions)
    
    # Get most recent execution
    if all_executions:
        all_executions.sort(key=lambda x: x.get('started_at', ''), reverse=True)
        last_scan = all_executions[0]
    else:
        last_scan = None
    last_scan_status = last_scan.get('status') if last_scan else None
    last_scan_time = last_scan.get('completed_at') if last_scan else None
    
    # Determine health status
    if not credentials_valid:
        health_status = "unhealthy"
    elif last_scan_status == "failed":
        health_status = "degraded"
    elif last_scan_status == "success":
        health_status = "healthy"
    else:
        health_status = "unknown"
    
    issues = []
    if not credentials_valid:
        issues.append("Credentials not stored or invalid")
    if last_scan_status == "failed":
        issues.append(f"Last scan failed: {last_scan.get('error_message', 'Unknown error')}")
    
    return {
        "account_id": account_id,
        "health_status": health_status,
        "credentials_valid": credentials_valid,
        "last_validation": last_validation,
        "last_scan": last_scan_time,
        "last_scan_status": last_scan_status,
        "issues": issues
    }


@router.get("/accounts/{account_id}/statistics")
async def get_account_statistics(account_id: str):
    """Get account statistics"""
    from engine_onboarding.database import get_account
    
    account = get_account(account_id)
    if not account:
        raise HTTPException(404, f"Account {account_id} not found")
    
    # Get all executions for this account (via schedules)
    from engine_onboarding.database import list_schedules_by_account, list_executions_by_schedule
    schedules = list_schedules_by_account(account_id)
    all_executions = []
    for schedule in schedules:
        schedule_executions = list_executions_by_schedule(schedule['schedule_id'])
        all_executions.extend(schedule_executions)
    
    # Remove duplicates by execution_id
    seen_ids = set()
    executions = []
    for e in all_executions:
        exec_id = e.get('execution_id')
        if exec_id and exec_id not in seen_ids:
            seen_ids.add(exec_id)
            executions.append(e)
    
    total_scans = len(executions)
    successful_scans = len([e for e in executions if e.get('status') == 'success'])
    failed_scans = len([e for e in executions if e.get('status') == 'failed'])
    success_rate = (successful_scans / total_scans * 100) if total_scans > 0 else 0.0
    
    # Calculate average duration
    durations = [e.get('execution_time_seconds', 0) for e in executions if e.get('execution_time_seconds')]
    avg_duration = sum(durations) / len(durations) if durations else 0
    
    # Count scans in last 7 and 30 days
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)
    thirty_days_ago = now - timedelta(days=30)
    
    last_7_days = len([
        e for e in executions
        if e.get('started_at') and datetime.fromisoformat(e['started_at'].replace('Z', '+00:00')) >= seven_days_ago
    ])
    
    last_30_days = len([
        e for e in executions
        if e.get('started_at') and datetime.fromisoformat(e['started_at'].replace('Z', '+00:00')) >= thirty_days_ago
    ])
    
    return {
        "account_id": account_id,
        "total_scans": total_scans,
        "successful_scans": successful_scans,
        "failed_scans": failed_scans,
        "success_rate": round(success_rate, 2),
        "average_scan_duration_seconds": round(avg_duration, 2),
        "last_7_days_scans": last_7_days,
        "last_30_days_scans": last_30_days
    }

