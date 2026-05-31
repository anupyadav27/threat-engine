"""
Tenant management API.

Every endpoint enforces authentication (X-Auth-Context from the gateway) and
RBAC (tenants:read / tenants:write). The owning customer_id is derived from the
authenticated session — scoped users may only act within their own customer;
platform-level users may target any customer via the explicit parameter.
"""
import uuid
from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from typing import Any, Optional
import sys, os

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

from engine_onboarding.database.tenant_operations import (
    create_tenant,
    get_tenant,
    list_tenants,
    update_tenant,
    delete_tenant,
)

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


def _resolve_customer_id(auth: Any, requested: Optional[str]) -> Optional[str]:
    """Derive the effective customer_id for the operation.

    - Scoped users (non-platform) are forced to their own ``customer_id``.
    - Platform-level users may target any customer via ``requested``.
    - When auth is unavailable (local/test), fall back to ``requested``.
    """
    if auth is None:
        return requested
    auth_customer = getattr(auth, "customer_id", None)
    is_platform = getattr(auth, "is_platform_level", lambda: False)()
    if auth_customer and not is_platform:
        return auth_customer
    # Platform user, or no customer on session → honour the explicit value,
    # falling back to the session's own customer.
    return requested or auth_customer


def _assert_tenant_ownership(auth: Any, tenant: dict) -> None:
    """404 if a scoped caller tries to touch a tenant outside their customer."""
    if auth is None:
        return
    auth_customer = getattr(auth, "customer_id", None)
    is_platform = getattr(auth, "is_platform_level", lambda: False)()
    if auth_customer and not is_platform:
        if tenant.get("customer_id") != auth_customer:
            # Hide existence from other customers.
            raise HTTPException(status_code=404, detail="Tenant not found")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TenantCreate(BaseModel):
    customer_id: str = Field(..., description="Customer identity (from auth session)")
    tenant_name: str = Field(..., min_length=1, max_length=255)
    tenant_description: Optional[str] = None
    tenant_id: Optional[str] = Field(None, description="Explicit UUID from platform (sync use)")
    environment: Optional[str] = Field("production", pattern="^(production|staging|development|test)$")


class TenantUpdate(BaseModel):
    tenant_name: Optional[str] = Field(None, min_length=1, max_length=255)
    tenant_description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|inactive)$")
    environment: Optional[str] = Field(None, pattern="^(production|staging|development|test)$")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def create_tenant_endpoint(
    body: TenantCreate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("tenants:write")),
):
    """
    Create a new tenant workspace.
    customer_id is derived from the authenticated session (a scoped user can
    only create under their own customer). tenant_id is auto-generated.
    """
    try:
        effective_customer = _resolve_customer_id(auth, body.customer_id)
        if not effective_customer:
            raise HTTPException(status_code=400, detail="No customer in session")
        data = {
            "tenant_id": body.tenant_id or str(uuid.uuid4()),
            "customer_id": effective_customer,
            "tenant_name": body.tenant_name.strip(),
            "tenant_description": body.tenant_description,
            "environment": body.environment or "production",
        }
        tenant = create_tenant(data)
        logger.info(f"Tenant created: {tenant['tenant_id']} for customer {effective_customer}")
        return tenant
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating tenant: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_tenants_endpoint(
    customer_id: Optional[str] = Query(None, description="Filter by customer (platform admins only)"),
    status: Optional[str] = Query(None, description="Filter by status: active | inactive"),
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("tenants:read")),
):
    """
    List tenants for the authenticated customer.
    Scoped users only ever see their own customer's tenants.
    """
    effective_customer = _resolve_customer_id(auth, customer_id)
    if not effective_customer:
        raise HTTPException(status_code=400, detail="No customer in session")
    try:
        tenants = list_tenants(customer_id=effective_customer, status=status)
        return {"tenants": tenants, "count": len(tenants)}
    except Exception as e:
        logger.error(f"Error listing tenants for customer {effective_customer}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{tenant_id}")
async def get_tenant_endpoint(
    tenant_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("tenants:read")),
):
    """Get a single tenant with its account count (own customer only)."""
    try:
        tenant = get_tenant(tenant_id)
        if not tenant:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        _assert_tenant_ownership(auth, tenant)
        return tenant
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{tenant_id}")
async def update_tenant_endpoint(
    tenant_id: str,
    body: TenantUpdate,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("tenants:write")),
):
    """Update mutable tenant fields (name, description, status) — own customer only."""
    try:
        existing = get_tenant(tenant_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        _assert_tenant_ownership(auth, existing)
        tenant = update_tenant(tenant_id, body.model_dump(exclude_none=True))
        if not tenant:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return tenant
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{tenant_id}", status_code=200)
async def delete_tenant_endpoint(
    tenant_id: str,
    auth: Any = Depends(get_auth_context),
    _: Any = Depends(require_permission("tenants:write")),
):
    """
    Soft-delete a tenant (status → deleted) — own customer only.
    Blocked if the tenant has active cloud accounts.
    """
    try:
        existing = get_tenant(tenant_id)
        if not existing:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        _assert_tenant_ownership(auth, existing)
        deleted = delete_tenant(tenant_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return {"message": f"Tenant {tenant_id} deleted successfully"}
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
