"""
Cloud Accounts API
Manages the cloud_accounts table (post migration-004 schema).
"""
import uuid
import os
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger

from engine_onboarding.database.cloud_accounts_operations import (
    create_cloud_account,
    get_cloud_account,
    list_cloud_accounts,
    update_cloud_account,
    soft_delete_cloud_account,
)
from engine_onboarding.database.tenant_operations import get_tenant

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/cloud-accounts", tags=["cloud-accounts"])

# ── CloudFormation template path ─────────────────────────────────────────────
_CF_TEMPLATE = os.path.join(
    os.path.dirname(__file__), '..', 'templates', 'aws_cloudformation.yaml'
)


# ── Pydantic models ───────────────────────────────────────────────────────────

class CloudAccountCreate(BaseModel):
    customer_id:    str = Field(..., description="Customer identity")
    tenant_id:      str = Field(..., description="Tenant workspace ID")
    account_name:   str = Field(..., min_length=1, max_length=255)
    provider:       str = Field(..., pattern="^(aws|azure|gcp|oci|alicloud|ibm|k8s)$")
    account_number: Optional[str] = Field(None, description="Cloud account/subscription/project ID")


class CredentialStore(BaseModel):
    """Body for POST /cloud-accounts/{id}/credentials"""
    credential_type: str = Field(
        ...,
        description="iam_role | access_key | service_principal | service_account | api_key | kubeconfig"
    )
    credentials: dict = Field(..., description="Provider-specific credential fields")


class ValidateCredentialsResponse(BaseModel):
    success: bool
    valid:   bool          # alias of success — UI reads either field
    status:  str           # 'valid' | 'invalid'
    message: str
    errors:  list
    account_number: Optional[str]
    validated_at: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/aws/cloudformation-template", include_in_schema=True)
async def get_cf_template():
    """
    Download the CloudFormation template that creates the IAM role
    for cross-account scanning. Used by the onboarding wizard.
    """
    path = os.path.abspath(_CF_TEMPLATE)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="CloudFormation template not found")
    return FileResponse(
        path,
        media_type="application/x-yaml",
        filename="threat-engine-iam-role.yaml",
    )


@router.post("", status_code=201)
async def create_account(body: CloudAccountCreate):
    """
    Phase 1 — create account record with pending status.
    account_id is auto-generated.
    """
    # Validate tenant exists
    tenant = get_tenant(body.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant {body.tenant_id} not found")

    data = {
        "account_id":    str(uuid.uuid4()),
        "customer_id":   body.customer_id,
        "tenant_id":     body.tenant_id,
        "account_name":  body.account_name.strip(),
        "provider":      body.provider,
        "account_number": body.account_number,
    }
    try:
        account = create_cloud_account(data)
        logger.info(f"Account created: {account['account_id']} ({body.provider})")
        return account
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating account: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_accounts(
    customer_id: Optional[str] = Query(None),
    tenant_id:   Optional[str] = Query(None),
    provider:    Optional[str] = Query(None),
    status:      Optional[str] = Query(None),
    limit:       int           = Query(100, ge=1, le=1000),
    offset:      int           = Query(0, ge=0),
):
    """List cloud accounts with optional filters and pagination."""
    filters = {}
    if customer_id: filters["customer_id"]    = customer_id
    if tenant_id:   filters["tenant_id"]      = tenant_id
    if provider:    filters["provider"]        = provider
    if status:      filters["account_status"]  = status

    try:
        accounts = list_cloud_accounts(filters=filters, limit=limit, offset=offset)
        return {"accounts": accounts, "count": len(accounts)}
    except Exception as e:
        logger.error(f"Error listing accounts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{account_id}/status")
async def get_account_status(account_id: str):
    """Focused status summary — onboarding + credential + last scan."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return {
        "account_id":                   account_id,
        "account_status":               account.get("account_status"),
        "onboarding_status":            account.get("account_onboarding_status"),
        "credential_validation_status": account.get("credential_validation_status"),
        "credential_validated_at":      account.get("credential_validated_at"),
        "schedule_enabled":             account.get("schedule_enabled"),
        "schedule_next_run_at":         account.get("schedule_next_run_at"),
        "last_scan_at":                 account.get("last_scan_at"),
    }


@router.get("/{account_id}")
async def get_account(account_id: str):
    """Get full account record (enriched with tenant_name + latest schedule)."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return account


@router.patch("/{account_id}")
async def update_account(account_id: str, updates: dict):
    """Generic field update."""
    try:
        account = update_cloud_account(account_id, updates)
        if not account:
            raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
        return account
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{account_id}/credentials", status_code=200)
async def store_credentials(account_id: str, body: CredentialStore):
    """
    Phase 2 — store credentials in AWS Secrets Manager.
    Calls the provider validator, stores on success, updates cloud_accounts.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    provider = account["provider"]

    try:
        # Resolve validator
        validator = _get_validator(provider, body.credential_type)

        # Validate against real cloud provider
        creds_with_type = {**body.credentials, "credential_type": body.credential_type}
        result = await validator.validate(creds_with_type)

        if not result.success:
            return {
                "success": False,
                "valid": False,
                "status": "invalid",
                "message": result.message,
                "errors": getattr(result, "errors", []),
                "account_number": None,
                "validated_at": datetime.now(timezone.utc).isoformat(),
            }

        # Store in Secrets Manager
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        secrets_manager_storage.store(
            account_id=account_id,
            credential_type=body.credential_type,
            credentials=body.credentials,
        )
        credential_ref = f"threat-engine/account/{account_id}"

        # Update account record
        updates = {
            "credential_type":             body.credential_type,
            "credential_ref":              credential_ref,
            "account_onboarding_status":   "deployed",
            "credential_validation_status": "valid",
            "credential_validated_at":     datetime.now(timezone.utc),
        }
        if getattr(result, "account_number", None):
            updates["account_number"] = result.account_number

        update_cloud_account(account_id, updates)
        logger.info(f"Credentials stored for {account_id} ({provider}/{body.credential_type})")

        return {
            "success": True,
            "valid": True,
            "status": "valid",
            "message": result.message or "Credentials validated and stored successfully",
            "errors": [],
            "account_number": getattr(result, "account_number", None),
            "validated_at": datetime.now(timezone.utc).isoformat(),
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Credential storage error for {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{account_id}/validate-credentials")
async def validate_credentials(account_id: str):
    """
    Phase 2.5 — re-validate credentials already stored in Secrets Manager.
    Returns same shape as /credentials so UI can use either endpoint.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    try:
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        creds = secrets_manager_storage.retrieve(account_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    provider        = account["provider"]
    credential_type = creds.get("credential_type", account.get("credential_type", ""))

    try:
        validator = _get_validator(provider, credential_type)
        result    = await validator.validate(creds)

        updates = {
            "credential_validation_status":  "valid" if result.success else "invalid",
            "credential_validation_message": result.message,
            "credential_validated_at":       datetime.now(timezone.utc),
        }
        if result.success and getattr(result, "account_number", None):
            updates["account_number"] = result.account_number

        update_cloud_account(account_id, updates)

        return {
            "success":        result.success,
            "valid":          result.success,
            "status":         "valid" if result.success else "invalid",
            "message":        result.message,
            "errors":         getattr(result, "errors", []),
            "account_number": getattr(result, "account_number", None),
            "validated_at":   datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error(f"Validation error for {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{account_id}/log-sources")
async def configure_log_sources(account_id: str, log_sources: dict):
    """Configure CIEM log source locations (CloudTrail, VPC Flow, ALB, WAF, S3)."""
    valid_types = {"cloudtrail", "vpc_flow", "alb", "waf", "s3_access", "dns", "cloudfront", "rds_audit"}
    for stype, entries in log_sources.items():
        if stype not in valid_types:
            raise HTTPException(status_code=400, detail=f"Unknown source type: {stype}")
        if not isinstance(entries, list):
            raise HTTPException(status_code=400, detail=f"'{stype}' must be a list")
        for entry in entries:
            if not entry.get("bucket"):
                raise HTTPException(status_code=400, detail=f"Each '{stype}' entry needs a 'bucket' field")

    account = update_cloud_account(account_id, {"log_sources": log_sources or None})
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return {"account_id": account_id, "log_sources": log_sources}


@router.get("/{account_id}/log-sources")
async def get_log_sources(account_id: str):
    """Get configured log sources."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return {
        "account_id":  account_id,
        "log_sources": account.get("log_sources"),
        "mode":        "user-configured" if account.get("log_sources") else "auto-discovery",
    }


@router.delete("/{account_id}", status_code=200)
async def delete_account(account_id: str):
    """Soft-delete a cloud account (sets status = deleted)."""
    deleted = soft_delete_cloud_account(account_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return {"message": f"Account {account_id} deleted successfully"}


# ── Validator helper ──────────────────────────────────────────────────────────

def _get_validator(provider: str, credential_type: str):
    p = provider.lower()
    if p == "aws":
        from engine_onboarding.validators.aws_validator import AWSValidator
        return AWSValidator()
    if p == "azure":
        from engine_onboarding.validators.azure_validator import AzureValidator
        return AzureValidator()
    if p == "gcp":
        from engine_onboarding.validators.gcp_validator import GCPValidator
        return GCPValidator()
    if p == "oci":
        from engine_onboarding.validators.oci_validator import OCIValidator
        return OCIValidator()
    if p == "alicloud":
        from engine_onboarding.validators.alicloud_validator import AliCloudValidator
        return AliCloudValidator()
    if p == "ibm":
        from engine_onboarding.validators.ibm_validator import IBMValidator
        return IBMValidator()
    if p == "k8s":
        from engine_onboarding.validators.k8s_validator import K8sValidator
        return K8sValidator()
    raise ValueError(f"Unsupported provider: {provider}")
