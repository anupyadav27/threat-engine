# STORY-CWPP-SECURITY-00: Add AuthMiddleware to CWPP Engine

## Track
CWPP — Security Fix (Blocker for STORY-CWPP-01)

## Priority
P0 — Critical security gap. Must ship before any CWPP feature work.

## Context

The security reviewer confirmed: `engines/cwpp/cwpp_engine/api_server.py` has **zero authentication enforcement**.

- No `engine_auth` import
- No `AuthMiddleware` applied to the FastAPI app
- `tenant_id: str = Query(default="default-tenant")` on all endpoints — any pod in the cluster can read any tenant's workload data by passing an arbitrary `tenant_id` query parameter
- No `require_permission()` decorators anywhere

STORY-CWPP-01 adds a cross-engine call (CWPP → CIEM) that forwards `tenant_id`. If `tenant_id` comes from a query param, tenant A can read tenant B's CIEM behavioral events by calling CWPP with `tenant_id=tenant-b`.

## Files to Modify
- `engines/cwpp/cwpp_engine/api_server.py`
- `engines/cwpp/cwpp_engine/core/http_client.py` (for auth header forwarding pattern)

## Pattern to Follow

Exactly follow the pattern in `engines/ciem/ciem_engine/api_server.py` lines 41-49:

```python
# At top of api_server.py
try:
    from engine_common.auth import AuthMiddleware, require_permission, get_tenant_id
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    def require_permission(perm): return lambda: None
    def get_tenant_id(auth=None): return os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    class AuthMiddleware: pass
```

```python
# Apply middleware when available
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)
```

```python
# On all endpoints, replace:
tenant_id: str = Query(default="default-tenant")
# With:
auth: Any = Depends(require_permission("cwpp:read")),
tenant_id: str = Depends(get_tenant_id)
```

## Endpoints to Fix

All 5 in `api_server.py`:
1. `GET /api/v1/cwpp/dashboard`
2. `GET /api/v1/cwpp/workloads/{workload_type}`
3. `GET /api/v1/cwpp/posture`
4. `GET /api/v1/cwpp/score`
5. `GET /api/v1/cwpp/ui-data`

## Auth Header Forwarding to Upstream Engines

After CWPP extracts `tenant_id` from AuthContext, all calls to upstream engines (container-security, vul-engine, etc.) must forward the `X-Auth-Context` header so each engine enforces its own tenant isolation.

In `http_client.py`, add forwarding support:
```python
async def get(self, url: str, params: dict = None, auth_header: str = None, timeout: float = 10.0) -> dict:
    headers = {}
    if auth_header:
        headers["X-Auth-Context"] = auth_header
    ...
```

The CWPP workload handlers receive `auth_header` from the dashboard endpoint and forward it to all engine calls. No engine should receive a `tenant_id` query param from CWPP — only the forwarded `X-Auth-Context`.

## Acceptance Criteria

- [ ] `GET /api/v1/cwpp/dashboard` returns `403` when called without a valid session token
- [ ] `tenant_id` is extracted from `AuthContext` via `get_tenant_id()` on all endpoints
- [ ] No `Query(default="default-tenant")` remains in `api_server.py`
- [ ] All upstream engine calls from CWPP forward `X-Auth-Context` header
- [ ] Viewer-level token receives `403` if `cwpp:read` is not in viewer's permission set (check RBAC matrix in `.claude/documentation/RBAC.md`)
- [ ] `AuthMiddleware` import failure degrades gracefully (engine still boots with reduced auth)

## Security Checklist
- [ ] Pattern matches `ciem_engine/api_server.py` auth implementation exactly
- [ ] No `DEV_BYPASS_AUTH` added
- [ ] `tenant_id` never sourced from query param after this fix
- [ ] X-Auth-Context forwarding prevents cross-tenant reads via CWPP→engine calls

## Definition of Done
- [ ] AuthMiddleware applied to CWPP FastAPI app
- [ ] All 5 endpoints have `require_permission("cwpp:read")`
- [ ] Manual verify: unauthenticated call to `/api/v1/cwpp/dashboard` returns 401/403
- [ ] Manual verify: viewer token with `cwpp:read` permission returns 200
- [ ] CWPP engine image rebuilt and redeployed