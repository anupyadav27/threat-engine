"""
Cloud Accounts API
Manages the cloud_accounts table (post migration-004 schema).
"""
import hashlib
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger

try:
    from engine_auth.fastapi.dependencies import require_permission, get_auth_context
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = Any
    def require_permission(perm: str):  # type: ignore[misc]
        async def _noop():
            return None
        return _noop
    async def get_auth_context():  # type: ignore[misc]
        return None

from engine_onboarding.database.cloud_accounts_operations import (
    create_cloud_account,
    get_cloud_account,
    list_cloud_accounts,
    update_cloud_account,
    soft_delete_cloud_account,
)
from engine_onboarding.database.tenant_operations import get_tenant
from engine_onboarding.constants import (
    VALID_ACCOUNT_TYPES,
    DEFAULT_VALID_ACCOUNT_TYPES,
    PROVIDER_TO_ACCOUNT_TYPE,
)

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/cloud-accounts", tags=["cloud-accounts"])

# ── CloudFormation template path ─────────────────────────────────────────────
_CF_TEMPLATE = os.path.join(
    os.path.dirname(__file__), '..', 'templates', 'aws_cloudformation.yaml'
)


# ── Pydantic models ───────────────────────────────────────────────────────────

_CLOUD_PROVIDERS    = "aws|azure|gcp|oci|alicloud|ibm|k8s"
_DB_PROVIDERS       = "postgres|mysql|mssql|mongodb|oracle"
_ALL_PROVIDERS_RE   = f"^({_CLOUD_PROVIDERS}|{_DB_PROVIDERS}|agent)$"

_DB_PROVIDER_SET    = {"postgres", "mysql", "mssql", "mongodb", "oracle"}

# account_type values — agent-based types use 'agent' as provider
_ACCOUNT_TYPES      = {"cloud_csp", "vulnerability", "secops", "database", "middleware"}

# Agent bootstrap token TTL (15 minutes)
_BOOTSTRAP_TOKEN_TTL_MINUTES = 15


class CloudAccountUpdate(BaseModel):
    """Allow-listed fields for PATCH /cloud-accounts/{id}.

    Explicitly excluded (must NOT be patchable via API):
      - credential_ref  (managed by /credentials endpoint only)
      - tenant_id       (immutable once set)
      - customer_id     (immutable)
      - account_id      (primary key)
    """
    account_name:   Optional[str] = Field(None, min_length=1, max_length=255)
    account_status: Optional[str] = Field(None, pattern="^(active|inactive|pending)$")
    log_sources:    Optional[Dict[str, Any]] = None
    account_type:   Optional[str] = Field(None, description="cloud_csp|vulnerability|secops|database|middleware")
    auth_config:    Optional[Dict[str, Any]] = None


class CloudAccountCreate(BaseModel):
    customer_id:    str = Field(..., description="Customer identity")
    tenant_id:      str = Field(..., description="Tenant workspace ID")
    account_name:   str = Field(..., min_length=1, max_length=255)
    provider:       str = Field(..., pattern=_ALL_PROVIDERS_RE)
    account_type:   Optional[str] = Field(
        None,
        description="cloud_csp | vulnerability | secops | database | middleware — inferred if omitted",
    )
    account_category: Optional[str] = Field(None, description="Legacy: cloud | database")
    account_number: Optional[str] = Field(None, description="Cloud account/subscription/project ID")
    auth_config:    Optional[Dict[str, Any]] = Field(
        None,
        description="Type-specific auth metadata (repo_url, scanner_type, etc.)",
    )


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
async def create_account(
    body: CloudAccountCreate,
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """
    Phase 1 — create account record with pending status.
    account_id is auto-generated.
    """
    # Validate tenant exists
    tenant = get_tenant(body.tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant {body.tenant_id} not found")

    # Resolve account_type — explicit > legacy category > inferred from provider
    if body.account_type and body.account_type in _ACCOUNT_TYPES:
        account_type = body.account_type
    elif body.account_category == "database" or body.provider in _DB_PROVIDER_SET:
        account_type = "database"
    else:
        account_type = PROVIDER_TO_ACCOUNT_TYPE.get(body.provider, "cloud_csp")

    # Validate account_type against tenant_type
    tenant_type = tenant.get("tenant_type") or "cloud"
    valid_types = VALID_ACCOUNT_TYPES.get(tenant_type, DEFAULT_VALID_ACCOUNT_TYPES)
    if account_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=(
                f"account_type '{account_type}' is not valid for tenant_type '{tenant_type}'. "
                f"Valid types: {sorted(valid_types)}"
            ),
        )

    data = {
        "account_id":    str(uuid.uuid4()),
        "customer_id":   body.customer_id,
        "tenant_id":     body.tenant_id,
        "account_name":  body.account_name.strip(),
        "account_type":  account_type,
        "provider":      body.provider,
        "account_number": body.account_number,
        "auth_config":   body.auth_config or {},
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
    customer_id:      Optional[str] = Query(None),
    tenant_id:        Optional[str] = Query(None),
    provider:         Optional[str] = Query(None),
    account_category: Optional[str] = Query(None),
    status:           Optional[str] = Query(None),
    limit:            int           = Query(100, ge=1, le=1000),
    offset:           int           = Query(0, ge=0),
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
    """List cloud accounts with optional filters and pagination."""
    filters = {}
    if customer_id:      filters["customer_id"]   = customer_id
    if tenant_id:        filters["tenant_id"]     = tenant_id
    if provider:         filters["provider"]       = provider
    if account_category: filters["account_type"]  = account_category  # backward-compat
    if status:           filters["account_status"] = status

    try:
        accounts = list_cloud_accounts(filters=filters, limit=limit, offset=offset)
        return {"accounts": accounts, "count": len(accounts)}
    except Exception as e:
        logger.error(f"Error listing accounts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{account_id}/status")
async def get_account_status(
    account_id: str,
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
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
async def get_account(
    account_id: str,
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
    """Get full account record (enriched with tenant_name + latest schedule)."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return account


@router.patch("/{account_id}")
async def update_account(
    account_id: str,
    body: CloudAccountUpdate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """Update allow-listed cloud account fields."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    updates = body.model_dump(exclude_none=True)
    try:
        result = update_cloud_account(account_id, updates)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating account {account_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{account_id}/credentials", status_code=200)
async def store_credentials(
    account_id: str,
    body: CredentialStore,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """
    Phase 2 — store credentials in AWS Secrets Manager.
    Calls the provider validator, stores on success, updates cloud_accounts.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

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
async def delete_account(
    account_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """Soft-delete a cloud account (sets status = deleted)."""
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")
    deleted = soft_delete_cloud_account(account_id)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    return {"message": f"Account {account_id} deleted successfully"}


# ── Ad-hoc scan endpoint ──────────────────────────────────────────────────────

class AdHocScanRequest(BaseModel):
    """Optional overrides for a manual on-demand scan."""
    engines:          Optional[list] = Field(None, description="Engine names to run — defaults to account_type set")
    include_regions:  Optional[list] = Field(None, description="Restrict scan to these regions")
    include_services: Optional[list] = Field(None, description="Restrict scan to these services")
    exclude_services: Optional[list] = Field(None, description="Services to skip")
    scan_name:        Optional[str]  = Field(None, max_length=255)


def _get_default_engines(account_type: str) -> list:
    """Return the default engine list for a given account_type."""
    _MAP = {
        "cloud_csp":    ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec", "network-security", "risk"],
        "vulnerability": ["vulnerability"],
        "secops":        ["secops"],
        "database":      ["dbsec"],
        "middleware":    ["check"],
    }
    return _MAP.get(account_type, ["discovery", "check", "inventory", "threat"])


@router.post("/{account_id}/scan", status_code=202)
async def trigger_adhoc_scan(
    account_id: str,
    body: AdHocScanRequest,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("scans:create")),
):
    """
    Trigger an on-demand (ad-hoc) scan for a cloud account.

    Creates a scan_run record with trigger_type='manual' and schedule_id=NULL,
    then submits the Argo workflow.  Returns scan_run_id so the caller can poll
    /scans/{scan_run_id}/pipeline for progress.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    credential_ref  = account.get("credential_ref")
    credential_type = account.get("credential_type")
    if not credential_ref or not credential_type:
        raise HTTPException(
            status_code=409,
            detail="Account has no stored credentials. Complete credential setup first.",
        )

    account_type   = account.get("account_type", "cloud_csp")
    engines        = body.engines or _get_default_engines(account_type)
    scan_run_id    = str(uuid.uuid4())

    # Write scan_run record
    try:
        from engine_onboarding.database.scan_run_operations import create_scan_run
        create_scan_run({
            "scan_run_id":       scan_run_id,
            "customer_id":       account["customer_id"],
            "tenant_id":         account["tenant_id"],
            "account_id":        account_id,
            "provider":          account["provider"],
            "credential_type":   credential_type,
            "credential_ref":    credential_ref,
            "engines_requested": engines,
            "scan_type":         "full",
            "trigger_type":      "manual",
            "scan_name":         body.scan_name or f"Manual scan — {account.get('account_name', account_id)}",
            "include_regions":   body.include_regions,
            "include_services":  body.include_services,
            "exclude_services":  body.exclude_services,
        })
    except Exception as exc:
        logger.error("Failed to create scan_run for ad-hoc scan %s: %s", account_id, exc)
        raise HTTPException(status_code=500, detail="Failed to create scan record")

    # Submit Argo workflow
    try:
        from engine_onboarding.scheduler.argo_client import ArgoClient
        argo = ArgoClient()
        argo.submit_pipeline(
            scan_run_id=scan_run_id,
            tenant_id=account["tenant_id"],
            account_id=account_id,
            provider=account["provider"],
            credential_type=credential_type,
            credential_ref=credential_ref,
            include_regions=body.include_regions,
            include_services=body.include_services,
        )
    except Exception as exc:
        logger.warning("Argo submission failed for ad-hoc scan %s: %s", scan_run_id, exc)
        # Not fatal — scan_run record exists; caller can monitor or retry

    logger.info("Ad-hoc scan triggered: scan_run_id=%s account=%s", scan_run_id, account_id)
    return {
        "scan_run_id":  scan_run_id,
        "account_id":   account_id,
        "status":       "pending",
        "engines":      engines,
        "trigger_type": "manual",
    }


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
    # Self-hosted database providers
    if p == "postgres":
        from engine_onboarding.validators.db_postgres_validator import DBPostgresValidator
        return DBPostgresValidator()
    if p == "mysql":
        from engine_onboarding.validators.db_mysql_validator import DBMysqlValidator
        return DBMysqlValidator()
    if p == "mssql":
        from engine_onboarding.validators.db_mssql_validator import DBMssqlValidator
        return DBMssqlValidator()
    if p == "mongodb":
        from engine_onboarding.validators.db_mongodb_validator import DBMongodbValidator
        return DBMongodbValidator()
    if p == "oracle":
        from engine_onboarding.validators.db_oracle_validator import DBOracleValidator
        return DBOracleValidator()
    raise ValueError(f"Unsupported provider: {provider}")


# ── Agent registration token endpoints ───────────────────────────────────────

class AgentTokenRequest(BaseModel):
    account_id:  str = Field(..., description="cloud_accounts.account_id this agent will register under")
    customer_id: str = Field(..., description="Customer identity for audit")
    tenant_id:   str = Field(..., description="Tenant workspace ID")


@router.post("/{account_id}/agent-token", status_code=201)
async def issue_agent_token(
    account_id: str,
    body: AgentTokenRequest,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """
    Issue a one-time bootstrap token for an agent-based account.

    The token is valid for 15 minutes. The agent exchanges it for a 30-day
    session JWT via the bootstrap endpoint. Token is stored as a SHA-256 hash
    — the plaintext is returned once and never stored.

    Applicable account_types: vulnerability | database | middleware
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")
    if auth and getattr(auth, "engine_tenant_id", None):
        if account.get("tenant_id") != auth.engine_tenant_id:
            raise HTTPException(status_code=403, detail="Forbidden")

    account_type = account.get("account_type", "")
    if account_type not in ("vulnerability", "database", "middleware"):
        raise HTTPException(
            status_code=400,
            detail=f"Agent tokens are only issued for agent-based account types "
                   f"(vulnerability, database, middleware). Got: {account_type}",
        )

    # PKCE design: code_verifier is generated here and returned once.
    # We store SHA-256(code_verifier) as the code_challenge.
    # The agent presents the raw verifier to /agents/bootstrap — never transmitted again.
    code_verifier  = secrets.token_urlsafe(32)
    code_challenge = hashlib.sha256(code_verifier.encode()).hexdigest()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=_BOOTSTRAP_TOKEN_TTL_MINUTES)

    from engine_onboarding.database.connection import get_onboarding_connection
    try:
        with get_onboarding_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO agent_registrations
                        (account_id, tenant_id, customer_id, token_hash, status, expires_at)
                    VALUES (%s, %s, %s, %s, 'issued', %s)
                    RETURNING registration_id
                """, (account_id, body.tenant_id, body.customer_id, code_challenge, expires_at))
                registration_id = str(cur.fetchone()[0])
            conn.commit()
    except Exception as e:
        logger.error(f"Failed to create agent registration: {e}")
        raise HTTPException(status_code=500, detail="Failed to issue agent token")

    logger.info(f"Agent token issued: registration_id={registration_id} account={account_id}")
    return {
        "registration_id": registration_id,
        "expires_at":      expires_at.isoformat(),
        "ttl_minutes":     _BOOTSTRAP_TOKEN_TTL_MINUTES,
        "install_command": (
            f"curl -sSL https://get.threat-engine.io/agent | bash -s -- "
            f"--registration-id {registration_id} "
            f"--verifier {code_verifier} "
            f"--account-id {account_id} "
            f"--tenant-id {body.tenant_id}"
        ),
    }
