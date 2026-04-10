"""
Tenant management API.
All endpoints are scoped by customer_id — passed as a query param until
auth middleware is in place (M-auth milestone).
"""
import uuid
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Optional
import sys, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from engine_common.logger import setup_logger

from engine_onboarding.database.tenant_operations import (
    create_tenant,
    get_tenant,
    list_tenants,
    update_tenant,
    delete_tenant,
)

logger = setup_logger(__name__, engine_name="onboarding")

router = APIRouter(prefix="/api/v1/tenants", tags=["tenants"])


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class TenantCreate(BaseModel):
    customer_id: str = Field(..., description="Customer identity (from auth session)")
    tenant_name: str = Field(..., min_length=1, max_length=255)
    tenant_description: Optional[str] = None


class TenantUpdate(BaseModel):
    tenant_name: Optional[str] = Field(None, min_length=1, max_length=255)
    tenant_description: Optional[str] = None
    status: Optional[str] = Field(None, pattern="^(active|inactive)$")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def create_tenant_endpoint(body: TenantCreate):
    """
    Create a new tenant workspace.
    tenant_id is auto-generated as a UUID.
    """
    try:
        data = {
            "tenant_id": str(uuid.uuid4()),
            "customer_id": body.customer_id,
            "tenant_name": body.tenant_name.strip(),
            "tenant_description": body.tenant_description,
        }
        tenant = create_tenant(data)
        logger.info(f"Tenant created: {tenant['tenant_id']} for customer {body.customer_id}")
        return tenant
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating tenant: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("")
async def list_tenants_endpoint(
    customer_id: str = Query(..., description="Filter by customer"),
    status: Optional[str] = Query(None, description="Filter by status: active | inactive"),
):
    """
    List all tenants for a customer.
    Returns tenant rows with live account_count.
    """
    try:
        tenants = list_tenants(customer_id=customer_id, status=status)
        return {"tenants": tenants, "count": len(tenants)}
    except Exception as e:
        logger.error(f"Error listing tenants for customer {customer_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{tenant_id}")
async def get_tenant_endpoint(tenant_id: str):
    """Get a single tenant with its account count."""
    try:
        tenant = get_tenant(tenant_id)
        if not tenant:
            raise HTTPException(status_code=404, detail=f"Tenant {tenant_id} not found")
        return tenant
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving tenant {tenant_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{tenant_id}")
async def update_tenant_endpoint(tenant_id: str, body: TenantUpdate):
    """Update mutable tenant fields (name, description, status)."""
    try:
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
async def delete_tenant_endpoint(tenant_id: str):
    """
    Soft-delete a tenant (status → deleted).
    Blocked if the tenant has active cloud accounts.
    """
    try:
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
