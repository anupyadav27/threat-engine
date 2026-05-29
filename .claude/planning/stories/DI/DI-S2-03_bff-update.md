# DI-S2-03 — BFF Update (asset_inventory Reads + DI Views)
**Sprint**: DI-S2 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Add BFF view handlers that read from `asset_inventory` (DI DB) when `DI_ENGINE_ENABLED=true`.
Existing BFF handlers reading from `discovery_findings` or `inventory_findings` keep the old path.
The DI path adds: `/views/di/assets`, `/views/di/asset/{uid}`, and updated `/views/inventory`
fallthrough to DI DB. No mock data, no fallbacks — if DI DB is empty, return empty list.

## Files to Modify
- `shared/api_gateway/bff/di_assets.py` — CREATE: new BFF view handlers for DI assets
- `shared/api_gateway/bff/_shared.py` — add `get_di_conn()` helper
- `shared/api_gateway/main.py` — register new `/views/di/` routes

## di_assets.py
```python
"""BFF view handlers for engine-di asset_inventory reads."""
import os
import logging
from typing import Optional
from fastapi import Depends, HTTPException
from engine_common.auth import require_permission, AuthContext

logger = logging.getLogger('bff.di_assets')

DI_ENGINE_ENABLED = os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true"


async def get_di_assets(
    scan_run_id: Optional[str] = None,
    provider: Optional[str] = None,
    service: Optional[str] = None,
    resource_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 100,
    auth: AuthContext = Depends(require_permission("discoveries:read")),
):
    """Return paginated asset_inventory rows for the authenticated tenant."""
    if not DI_ENGINE_ENABLED:
        raise HTTPException(status_code=404,
                            detail="DI engine not enabled. Set DI_ENGINE_ENABLED=true.")
    conn = _get_di_conn()
    try:
        filters = ["tenant_id = %s"]
        params = [auth.tenant_id]
        if scan_run_id:
            filters.append("scan_run_id = %s")
            params.append(scan_run_id)
        if provider:
            filters.append("provider = %s")
            params.append(provider)
        if service:
            filters.append("service = %s")
            params.append(service)
        if resource_type:
            filters.append("resource_type = %s")
            params.append(resource_type)

        offset = (page - 1) * page_size
        where = " AND ".join(filters)

        with conn.cursor() as cur:
            cur.execute(f"""
                SELECT resource_uid, resource_type, resource_name, service,
                       provider, region, account_id, discovery_id, phase,
                       emitted_fields, drift_detected, first_seen_at, last_seen_at
                FROM asset_inventory
                WHERE {where}
                ORDER BY last_seen_at DESC
                LIMIT %s OFFSET %s
            """, params + [page_size, offset])
            rows = [dict(zip([d[0] for d in cur.description], row))
                    for row in cur.fetchall()]

            cur.execute(f"SELECT COUNT(*) FROM asset_inventory WHERE {where}", params)
            total = cur.fetchone()[0]

        return {"items": rows, "total": total, "page": page, "page_size": page_size}
    finally:
        conn.close()


async def get_di_asset_detail(
    resource_uid: str,
    auth: AuthContext = Depends(require_permission("discoveries:read")),
):
    """Return full detail for a single asset (tenant-scoped)."""
    if not DI_ENGINE_ENABLED:
        raise HTTPException(status_code=404, detail="DI engine not enabled.")
    conn = _get_di_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM asset_inventory
                WHERE resource_uid = %s AND tenant_id = %s
                LIMIT 1
            """, (resource_uid, auth.tenant_id))
            row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Asset not found")
        return dict(zip([d[0] for d in cur.description], row))
    finally:
        conn.close()


def _get_di_conn():
    """Get psycopg2 connection to threat_engine_di DB."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("DI_DB_HOST"),
        port=int(os.getenv("DI_DB_PORT", "5432")),
        database=os.getenv("DI_DB_NAME", "threat_engine_di"),
        user=os.getenv("DI_DB_USER", "postgres"),
        password=os.getenv("DI_DB_PASSWORD", ""),
    )
```

## Route Registration in main.py
```python
from bff.di_assets import get_di_assets, get_di_asset_detail

app.add_api_route("/api/v1/views/di/assets", get_di_assets, methods=["GET"])
app.add_api_route("/api/v1/views/di/asset/{resource_uid}", get_di_asset_detail, methods=["GET"])
```

## Acceptance Criteria

### Functional
- [ ] `DI_ENGINE_ENABLED=true` + `GET /views/di/assets` → paginated `asset_inventory` rows
- [ ] `DI_ENGINE_ENABLED=false` + `GET /views/di/assets` → 404 with clear message
- [ ] `GET /views/di/asset/{uid}` → full row for that UID (tenant-scoped)
- [ ] `GET /views/di/asset/{unknown-uid}` → 404
- [ ] provider/service/resource_type filters work correctly
- [ ] Empty `asset_inventory` → `{"items": [], "total": 0}` (no mock data)
- [ ] No `json.loads()` on JSONB — psycopg2 auto-deserializes

### Security
- [ ] `discoveries:read` required — viewer gets 200 (viewer has this permission)
- [ ] `tenant_id` from `AuthContext` — not from request params; no cross-tenant reads
- [ ] `DI_DB_PASSWORD` from Secret; not logged

### RBAC Matrix
| Role | GET /views/di/assets | GET /views/di/asset/{uid} |
|------|---------------------|--------------------------|
| platform_admin | 200 | 200 |
| org_admin | 200 | 200 |
| tenant_admin | 200 | 200 |
| analyst | 200 | 200 |
| viewer | 200 | 200 |

### Error Handling
- [ ] DI DB unreachable → 503 (not 500 NoneType crash)
- [ ] No fallback to old DB on DI DB failure

## Testing Requirements

**BFF contract test** (`tests/bff/test_di_assets_contract.py`):
- Mock DI DB with 3 rows; assert response shape
- `tenant_id` from auth context always applied to WHERE clause
- `DI_ENGINE_ENABLED=false` → 404 response
- `resource_uid` not in DB → 404

**Integration**: `GET /views/di/assets?provider=aws` after DI scan → items > 0

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `di_assets.py` created; routes registered in `main.py`
- [ ] 5-role RBAC matrix tests passing
- [ ] BFF contract test passing
- [ ] `GET /views/di/assets` via ELB returns real data after DI scan
- [ ] No mock data anywhere in the handler
- [ ] MEMORY.md: BFF views `/views/di/assets` + `/views/di/asset/{uid}` added

## Dependencies
- DI-S1-06 (engine-di live; `asset_inventory` populated)
- DI-S2-02 (gateway DI_ENGINE_URL set; DI_ENGINE_ENABLED=true in gateway env)

## Rollback
Remove route registrations from `main.py`; delete `bff/di_assets.py`; redeploy gateway.