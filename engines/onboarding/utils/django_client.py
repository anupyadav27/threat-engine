"""
Helper to retrieve tenant metadata from the local onboarding DB.

The tenant_type field is synced from Django via the Celery task that calls
POST /internal/tenants/sync whenever a tenant is created or updated on the
Django platform side.  We therefore read from the local `tenants` table
rather than making a back-channel HTTP call to Django, which avoids circular
service dependencies.

If the DB is unreachable, callers should surface HTTP 503 (Tenant service
unavailable — retry) per onboarding-C5 AC6.
"""
import logging
from typing import Optional

import psycopg2

from engine_onboarding.database.tenant_operations import get_tenant

logger = logging.getLogger(__name__)

_DEFAULT_TENANT_TYPE = "cloud"


def get_tenant_type(tenant_id: str) -> str:
    """Return the tenant_type for the given tenant_id.

    Reads from the local onboarding `tenants` table, which is kept in sync
    with Django via the tenant-sync Celery task (auth-A3).

    Args:
        tenant_id: UUID string of the tenant (from AuthContext.tenant_id).

    Returns:
        The tenant's type string (e.g. 'cloud', 'vulnerability', 'secops').
        Falls back to 'cloud' when the column is NULL.

    Raises:
        psycopg2.OperationalError: If the database is unreachable.
        LookupError: If no tenant with this tenant_id exists.
    """
    # May raise psycopg2.OperationalError — caller converts to HTTP 503.
    tenant = get_tenant(tenant_id)
    if tenant is None:
        raise LookupError(f"Tenant {tenant_id!r} not found in onboarding DB")
    tenant_type: Optional[str] = tenant.get("tenant_type")
    if not tenant_type:
        logger.warning(
            "tenant_type is NULL for tenant_id=%s — defaulting to 'cloud'",
            tenant_id,
        )
        return _DEFAULT_TENANT_TYPE
    return tenant_type
