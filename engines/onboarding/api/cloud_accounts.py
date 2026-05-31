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
from fastapi import APIRouter, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
import sys

import psycopg2

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
    get_agent_registration_by_account,
    list_cloud_accounts,
    update_cloud_account,
    soft_delete_cloud_account,
)
from engine_onboarding.database.tenant_operations import get_tenant
from engine_onboarding.constants import (
    VALID_ACCOUNT_TYPES,
    DEFAULT_VALID_ACCOUNT_TYPES,
)
from engine_onboarding.database.reference_operations import (
    get_default_account_type,
    get_engines_for_account_type,
    get_valid_account_type_set,
)
from engine_onboarding.validators.account_type import validate_account_type_for_tenant
from engine_onboarding.utils.django_client import get_tenant_type

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/cloud-accounts", tags=["cloud-accounts"])

# ── CloudFormation template path ─────────────────────────────────────────────
_CF_TEMPLATE = os.path.join(
    os.path.dirname(__file__), '..', 'templates', 'aws_cloudformation.yaml'
)


# ── Pydantic models ───────────────────────────────────────────────────────────

_CLOUD_PROVIDERS    = "aws|azure|gcp|oci|alicloud|ibm|k8s"
_DB_PROVIDERS       = "postgres|mysql|mssql|mongodb|oracle"
_GIT_PROVIDERS      = "github|gitlab|bitbucket"
_ALL_PROVIDERS_RE   = f"^({_CLOUD_PROVIDERS}|{_DB_PROVIDERS}|{_GIT_PROVIDERS}|agent)$"

_DB_PROVIDER_SET    = {"postgres", "mysql", "mssql", "mongodb", "oracle"}
_GIT_PROVIDER_SET   = {"github", "gitlab", "bitbucket"}

# Agent bootstrap token TTL (15 minutes)
_BOOTSTRAP_TOKEN_TTL_MINUTES = 15


class CloudAccountUpdate(BaseModel):
    """Allow-listed fields for PATCH /cloud-accounts/{id}.

    Explicitly excluded (must NOT be patchable via API):
      - credential_ref  (managed by /credentials endpoint only)
      - tenant_id       (immutable once set)
      - customer_id     (immutable)
      - account_id      (primary key)

    Any extra fields sent in the request body (e.g. tenant_id, customer_id,
    credential_ref) are silently ignored — this prevents mass-assignment attacks
    (BLOCK-06).
    """
    account_name:   Optional[str] = Field(None, min_length=1, max_length=255)
    account_status: Optional[str] = Field(None, pattern="^(active|inactive|pending)$")
    provider:       Optional[str] = Field(None, pattern=_ALL_PROVIDERS_RE)
    log_sources:    Optional[Dict[str, Any]] = None
    account_type:   Optional[str] = Field(None, description="cloud_csp|vulnerability|secops|database|middleware")
    auth_config:    Optional[Dict[str, Any]] = None

    model_config = {"extra": "ignore"}  # BLOCK-06: silently drop tenant_id, customer_id, credential_ref, etc.


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
# RBAC: requires cloud_accounts:read (template contains no tenant data but requires auth)
async def get_cf_template(
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
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
# RBAC: requires cloud_accounts:write
async def create_account(
    body: CloudAccountCreate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """
    Phase 1 — create account record with pending status.
    account_id is auto-generated.

    The tenant_id used for validation is taken from the authenticated
    X-Auth-Context (auth.tenant_id) — never from the request body.  This
    prevents a caller from bypassing per-tenant account_type restrictions by
    supplying a different tenant_id in the payload.
    """
    # AC5: resolve tenant_id from auth context (X-Auth-Context), fall back to
    # body.tenant_id only when auth is not available (local/test environments).
    auth_tenant_id: Optional[str] = (
        getattr(auth, "tenant_id", None)
        or getattr(auth, "engine_tenant_id", None)
    ) if auth else None
    lookup_tenant_id = auth_tenant_id or body.tenant_id

    # AC6: surface DB connection failures as 503 (tenant service unavailable).
    try:
        tenant_type_value = get_tenant_type(lookup_tenant_id)
    except psycopg2.OperationalError as exc:
        logger.error(
            "DB unreachable when fetching tenant_type for tenant_id=%s: %s",
            lookup_tenant_id,
            exc,
        )
        raise HTTPException(
            status_code=503,
            detail="Tenant service unavailable — retry",
        )
    except LookupError:
        raise HTTPException(
            status_code=404,
            detail=f"Tenant {lookup_tenant_id} not found",
        )

    # Also verify the full tenant row exists in the local DB for FK integrity.
    tenant = get_tenant(lookup_tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant {lookup_tenant_id} not found")

    # Resolve account_type — explicit > legacy category > DB-driven default from provider
    valid_types_set = get_valid_account_type_set()
    if body.account_type and body.account_type in valid_types_set:
        account_type = body.account_type
    elif body.account_category == "database" or body.provider in _DB_PROVIDER_SET:
        account_type = "database"
    elif body.provider in _GIT_PROVIDER_SET:
        account_type = "code_security"
    else:
        account_type = get_default_account_type(body.provider)

    # AC3 + AC4: strict 1:1 compatibility check BEFORE the DB write.
    # validate_account_type_for_tenant() is in validators/account_type.py (AC7).
    if not validate_account_type_for_tenant(account_type, tenant_type_value):
        raise HTTPException(
            status_code=422,
            detail=f"account_type '{account_type}' is not permitted for tenant_type '{tenant_type_value}'",
        )

    # Broader allow-list gate (non-1:1 types such as database, middleware).
    valid_types = VALID_ACCOUNT_TYPES.get(tenant_type_value, DEFAULT_VALID_ACCOUNT_TYPES)
    if account_type not in valid_types:
        raise HTTPException(
            status_code=422,
            detail=(
                f"account_type '{account_type}' is not valid for tenant_type '{tenant_type_value}'. "
                f"Valid types: {sorted(valid_types)}"
            ),
        )

    # Build auth_config — for code_security accounts derive canonical fields from repo_url
    auth_config = body.auth_config or {}
    if account_type == "code_security":
        repo_url = auth_config.get("repo_url", "")
        project_name = (
            repo_url.rstrip("/").split("/")[-1].removesuffix(".git")
            if repo_url
            else ""
        )
        auth_config = {
            "repo_url":       repo_url,
            "default_branch": auth_config.get("default_branch", "main"),
            "project_name":   auth_config.get("project_name") or project_name,
            "vcs_platform":   body.provider,
            "scan_types":     auth_config.get("scan_types", ["sast"]),
        }

    # customer_email: use authenticated user's email; fall back to a derived value.
    customer_email = (
        getattr(auth, "email", None)
        or f"{body.customer_id}@cspm.local"
    )

    # Derive customer_id from the authenticated session when available — prevents
    # a caller from tagging an account under an arbitrary customer. Falls back to
    # the body value only when auth is unavailable (local/test).
    effective_customer_id = getattr(auth, "customer_id", None) or body.customer_id

    data = {
        "account_id":     str(uuid.uuid4()),
        "customer_id":    effective_customer_id,
        "customer_email": customer_email,
        # Store the auth-resolved canonical tenant_id (engine_tenant_id) — the SAME
        # value the listing filter, the single-account guard, and the schedule
        # ownership check use. Storing the raw body.tenant_id here caused accounts
        # to be invisible to their owner and produced "403 Forbidden" on schedule
        # creation when body.tenant_id != engine_tenant_id. Falls back to
        # body.tenant_id when auth is unavailable (local/test).
        "tenant_id":      lookup_tenant_id,
        "account_name":   body.account_name.strip(),
        "account_type":   account_type,
        "provider":       body.provider,
        "account_number": body.account_number,
        "auth_config":    auth_config,
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
# RBAC: requires cloud_accounts:read
async def list_accounts(
    customer_id:      Optional[str] = Query(None),
    tenant_id:        Optional[str] = Query(None),
    provider:         Optional[str] = Query(None),
    account_type:     Optional[str] = Query(None, description="Filter by account_type (e.g. code_security, cloud_csp)"),
    account_category: Optional[str] = Query(None, description="Alias for account_type — kept for backward compatibility"),
    status:           Optional[str] = Query(None),
    limit:            int           = Query(100, ge=1, le=1000),
    offset:           int           = Query(0, ge=0),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
    """List cloud accounts with optional filters and pagination."""
    # AC5: enforce tenant scope from auth context — prevent cross-tenant list
    if auth and getattr(auth, "engine_tenant_id", None):
        tenant_id = auth.engine_tenant_id
    filters = {}
    if customer_id:                           filters["customer_id"]   = customer_id
    if tenant_id:                             filters["tenant_id"]     = tenant_id
    if provider:                              filters["provider"]       = provider
    # account_type takes precedence; account_category is the legacy alias
    if account_type:                          filters["account_type"]  = account_type
    elif account_category:                    filters["account_type"]  = account_category
    if status:                                filters["account_status"] = status

    try:
        accounts = list_cloud_accounts(filters=filters, limit=limit, offset=offset)
        return {"accounts": accounts, "count": len(accounts)}
    except Exception as e:
        logger.error(f"Error listing accounts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{account_id}/status")
# RBAC: requires cloud_accounts:read
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
# RBAC: requires cloud_accounts:read
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
# RBAC: requires cloud_accounts:write
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
# RBAC: requires cloud_accounts:write
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

        # Store in Secrets Manager — scoped by tenant + account
        tenant_id_for_secret: str = account.get("tenant_id", "")
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        secrets_manager_storage.store(
            account_id=account_id,
            credential_type=body.credential_type,
            credentials=body.credentials,
            tenant_id=tenant_id_for_secret,
        )
        sm_prefix = os.environ.get("SECRETS_MANAGER_PREFIX", "threat-engine")
        credential_ref = f"{sm_prefix}/account/{tenant_id_for_secret}/{account_id}"

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
# RBAC: requires cloud_accounts:write
async def validate_credentials(
    account_id: str,
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """
    Phase 2.5 — re-validate credentials already stored in Secrets Manager.
    Returns same shape as /credentials so UI can use either endpoint.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    try:
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        # Use the stored credential_ref as the SM lookup key — handles both old and new path formats.
        creds = secrets_manager_storage.retrieve(
            account_id=account_id,
            tenant_id=account.get("tenant_id"),
            credential_ref=account.get("credential_ref"),
        )
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
# RBAC: requires cloud_accounts:write
async def configure_log_sources(
    account_id: str,
    log_sources: dict,
    _: Any = Depends(require_permission("cloud_accounts:write")),
):
    """Configure CDR log source locations (CloudTrail, VPC Flow, ALB, WAF, S3)."""
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
# RBAC: requires cloud_accounts:read
async def get_log_sources(
    account_id: str,
    _: Any = Depends(require_permission("cloud_accounts:read")),
):
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
# RBAC: requires cloud_accounts:write
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
    """Return the default engine list for a given account_type (DB-driven)."""
    return get_engines_for_account_type(account_type)


@router.post("/{account_id}/scan", status_code=202)
# RBAC: requires scans:create
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

    # Submit Argo workflow. submit_pipeline raises on failure.
    argo_ok = False
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
        argo_ok = True
    except Exception as exc:
        logger.warning("Argo submission failed for ad-hoc scan %s: %s", scan_run_id, exc)
        argo_ok = False

    if not argo_ok:
        # Mark the scan_run failed so it does not sit 'pending' forever, then
        # surface the failure rather than reporting a false 'pending'.
        try:
            from engine_onboarding.database.scan_run_operations import mark_scan_run_completed
            mark_scan_run_completed(
                scan_run_id, success=False,
                error_details={"stage": "argo_submit", "error": "Workflow submission failed — scan orchestrator unavailable"},
            )
        except Exception as mark_exc:
            logger.error("Failed to mark scan_run %s as failed: %s", scan_run_id, mark_exc)
        raise HTTPException(
            status_code=503,
            detail="Scan could not be started — the scan orchestrator is unavailable. Please retry.",
        )

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
    # VCS / code-repository providers
    if p in ("github", "gitlab", "bitbucket"):
        from engine_onboarding.validators.git_validator import GitValidator
        return GitValidator()
    raise ValueError(f"Unsupported provider: {provider}")


# ── Agent registration token endpoints ───────────────────────────────────────

@router.post("/{account_id}/agent-token", status_code=201)
async def issue_agent_token(
    account_id: str,
    auth: Any = Depends(get_auth_context),
    _perm: Any = Depends(require_permission("cloud_accounts:write")),
):
    """Issue a secure agent installation token for the given cloud account.

    Security contract:
    - Raw UUID4 token returned in HTTP response body only (never logged).
    - Raw token stored in AWS Secrets Manager at ``threat-engine/account/{id}``.
    - SHA-256 hash stored in ``agent_registrations.token_hash`` only.
    - Raw token NEVER written to PostgreSQL.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    # Multi-tenant guard.
    tenant_id_from_auth: Optional[str] = None
    if auth:
        tenant_id_from_auth = (
            getattr(auth, "engine_tenant_id", None)
            or getattr(auth, "tenant_id", None)
        )
    if tenant_id_from_auth and account.get("tenant_id") != tenant_id_from_auth:
        raise HTTPException(status_code=403, detail="Forbidden")

    account_type = account.get("account_type", "")

    tenant_id: str = tenant_id_from_auth or account.get("tenant_id", "")

    # Generate raw token (UUID4) — NEVER stored in DB.
    raw_token = str(uuid.uuid4())
    # Store SHA-256 hash only in agent_registrations — raw token never in DB.
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    from engine_onboarding.database.cloud_accounts_operations import create_agent_registration

    try:
        reg = create_agent_registration(account_id, tenant_id, token_hash, customer_id=account.get("customer_id"))
    except psycopg2.errors.ForeignKeyViolation:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found in DB")
    except psycopg2.errors.UniqueViolation:
        # Re-provision: rotate token for existing agent — keep same agent_id
        from engine_onboarding.database.cloud_accounts_operations import rotate_agent_token
        try:
            reg = rotate_agent_token(account_id, tenant_id, token_hash)
        except Exception as exc:
            logger.error("Token rotation failed for %s: %s", account_id, exc)
            raise HTTPException(status_code=500, detail="Failed to rotate agent token")
    except Exception as exc:
        logger.error("Failed to create agent_registrations row for %s: %s", account_id, exc)
        raise HTTPException(status_code=500, detail="Failed to create agent registration")

    registration_id = reg["registration_id"]
    agent_id = reg["agent_id"]

    # Persist raw token in AWS Secrets Manager — scoped by tenant + account.
    try:
        from engine_onboarding.storage.secrets_manager_storage import secrets_manager_storage
        secrets_manager_storage.store_agent_token(account_id, raw_token, tenant_id=tenant_id)
    except Exception as exc:
        logger.warning(
            "SM store_agent_token failed for %s (non-fatal in dev): %s", account_id, exc
        )

    # S3 agent distribution bucket — platform chosen from account_type context.
    # account_type 'vulnerability' → always linux (server-side agent).
    # Future: accept platform hint from request body.
    s3_base = os.environ.get(
        "AGENT_S3_BASE_URL",
        "https://onam-security-agents-588989875114.s3.ap-south-1.amazonaws.com/agents/latest",
    )
    platform_map = {"vulnerability": "linux", "database": "linux", "middleware": "linux"}
    agent_platform = platform_map.get(account_type, "linux")
    download_url = f"{s3_base}/{agent_platform}/onam-agent.py"

    install_cmd = (
        f"curl -sSL '{download_url}' -o onam-agent.py && "
        f"python3 onam-agent.py "
        f"--tenant {tenant_id} --token {raw_token} --agent-id {agent_id}"
    )

    logger.info(
        "Agent token issued: agent_id=%s registration_id=%s account=%s tenant=%s platform=%s",
        agent_id,
        registration_id,
        account_id,
        tenant_id,
        agent_platform,
    )
    return {
        "agent_id": agent_id,
        "registration_id": registration_id,
        "registration_token": raw_token,
        "download_url": download_url,
        "platform": agent_platform,
        "install_command": install_cmd,
        "token_expires_in": _BOOTSTRAP_TOKEN_TTL_MINUTES * 60,
        "account_id": account_id,
    }


# ── Agent status endpoint (D9: AC6) ──────────────────────────────────────────

@router.get("/{account_id}/agent-status")
async def get_agent_status(
    account_id: str,
    auth: Any = Depends(get_auth_context),
    _perm: Any = Depends(require_permission("cloud_accounts:read")),
) -> dict:
    """Return the current connection status of the agent for an account (D9 AC6).

    The platform UI polls this endpoint every 5 seconds while waiting for the
    agent to phone home after installation. No raw token is required or returned —
    status is derived solely from the ``agent_registrations`` table using the
    ``account_id`` + ``tenant_id`` pair.

    Args:
        account_id: UUID of the cloud_account to query.
        auth:       Resolved AuthContext (supplies tenant_id for isolation).

    Returns:
        Dict with ``status`` (``"pending"`` | ``"connected"``) and
        ``last_heartbeat`` (ISO-8601 or None).

    Raises:
        HTTPException 403: Caller's tenant does not own this account.
        HTTPException 404: Account not found.
    """
    account = get_cloud_account(account_id)
    if not account:
        raise HTTPException(status_code=404, detail=f"Account {account_id} not found")

    # Multi-tenant guard — enforce caller's tenant_id.
    tenant_id_from_auth: Optional[str] = None
    if auth:
        tenant_id_from_auth = (
            getattr(auth, "engine_tenant_id", None)
            or getattr(auth, "tenant_id", None)
        )
    if tenant_id_from_auth and account.get("tenant_id") != tenant_id_from_auth:
        raise HTTPException(status_code=403, detail="Forbidden")

    tenant_id: str = tenant_id_from_auth or account.get("tenant_id", "")

    reg = get_agent_registration_by_account(account_id, tenant_id)
    if reg is None:
        return {"status": "pending", "last_heartbeat": None}

    last_hb = reg.get("last_heartbeat")
    last_hb_str = last_hb.isoformat() if hasattr(last_hb, "isoformat") else last_hb
    return {"status": reg["status"], "last_heartbeat": last_hb_str}
