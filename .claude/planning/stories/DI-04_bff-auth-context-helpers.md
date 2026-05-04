# DI-04: BFF — AuthContext Resolver + account_filter() Helper

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P0 — required before DI-05 (tenant_id Query removal)

## Story
As a BFF view handler, I need a `resolve_tenant_id(request)` function and an `account_filter()` helper that read from the forwarded `X-Auth-Context` header, so that views can stop accepting `tenant_id` as a query string and start enforcing server-side scoping.

## Background

All 40+ BFF view endpoints today have:
```python
tenant_id: str = Query(...)
```
This means any caller who guesses or knows a different `engine_tenant_id` can query another tenant's data. The correct pattern is to read `tenant_id` from the trusted `X-Auth-Context` header that `AuthMiddleware` injects.

The `X-Auth-Context` header carries a JSON-encoded `AuthContext` dict (see `AuthContext.to_header_json()`). After DI-02, this dict includes `engine_tenant_id`.

## File to Create

`/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_auth.py`

## Implementation

```python
"""
BFF auth helpers — read AuthContext from the X-Auth-Context header.

These helpers replace direct tenant_id: str = Query(...) parameters
in BFF view handlers. The tenant_id is resolved server-side from the
session, not accepted from the client query string.
"""

from __future__ import annotations

import json
import logging
from typing import Optional, List

from fastapi import Request, HTTPException
from engine_auth.core.models import AuthContext

logger = logging.getLogger("api-gateway.bff.auth")


def _parse_auth_context(request: Request) -> Optional[AuthContext]:
    """Parse X-Auth-Context header into AuthContext. Returns None if missing/invalid."""
    raw = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    if not raw:
        return None
    try:
        return AuthContext.from_dict(json.loads(raw))
    except Exception as exc:
        logger.warning("BFF: failed to parse X-Auth-Context: %s", exc)
        return None


def resolve_tenant_id(request: Request) -> str:
    """
    Resolve engine_tenant_id from the authenticated session.

    Priority:
      1. AuthContext.engine_tenant_id (set after DI-02)
      2. AuthContext.tenant_ids[0] (fallback for old sessions)
      3. Raise HTTP 401 if no auth context present

    Never reads tenant_id from query string.
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Platform-level users (level=1) are unrestricted — they must still pass
    # tenant_id explicitly (kept as Query param for platform_admin BFF views only).
    if ctx.engine_tenant_id:
        return ctx.engine_tenant_id

    if ctx.tenant_ids and len(ctx.tenant_ids) > 0:
        return ctx.tenant_ids[0]

    # Platform admin with no tenant selected — caller must supply tenant_id
    raise HTTPException(
        status_code=400,
        detail="No active tenant in session. Select a tenant first.",
    )


def resolve_tenant_id_optional(request: Request) -> Optional[str]:
    """
    Like resolve_tenant_id but returns None instead of raising.
    Used for platform_admin views where tenant_id is optional.
    """
    try:
        return resolve_tenant_id(request)
    except HTTPException:
        return None


def account_filter(request: Request) -> Optional[List[str]]:
    """
    Return the list of account_ids this user is restricted to, or None if unrestricted.

    Use in SQL queries as:
        WHERE ($1::text[] IS NULL OR account_id = ANY($1))

    where $1 = account_filter(request)
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        return None
    return ctx.account_ids  # None = unrestricted, list = restricted


def require_tenant_access(request: Request, tenant_id: str) -> None:
    """
    Assert that the authenticated user can access the given tenant_id.
    Raises HTTP 403 if the tenant is outside the user's scope.

    Platform admins (tenant_ids=None) always pass.
    """
    ctx = _parse_auth_context(request)
    if ctx is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    if not ctx.can_access_tenant(tenant_id):
        raise HTTPException(status_code=403, detail="Access to this tenant is not permitted")
```

## Acceptance Criteria

- [ ] `resolve_tenant_id(request)` returns correct engine_tenant_id for authenticated request
- [ ] `resolve_tenant_id(request)` raises HTTP 401 when no X-Auth-Context present
- [ ] `resolve_tenant_id(request)` raises HTTP 400 when user has no tenants (platform admin without selection)
- [ ] `account_filter(request)` returns None for unrestricted users
- [ ] `account_filter(request)` returns `["588989875114"]` for a user with one account grant
- [ ] `require_tenant_access` returns cleanly for platform admin (tenant_ids=None)
- [ ] `require_tenant_access` raises 403 when tenant not in user's list
- [ ] Module imports cleanly in BFF context (no circular imports)

## Unit Tests (write these inline in a test file)

File: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/tests/test_auth.py`

```python
from unittest.mock import MagicMock, patch
import pytest
from fastapi import HTTPException

def make_request(auth_ctx_dict=None):
    req = MagicMock()
    if auth_ctx_dict:
        import json
        req.headers = {"X-Auth-Context": json.dumps(auth_ctx_dict)}
    else:
        req.headers = {}
    req.state = MagicMock(auth_header=None)
    return req

def test_resolve_tenant_id_from_engine_tenant_id():
    from bff._auth import resolve_tenant_id
    req = make_request({"user_id": "u1", "email": "a@b.com", "role": "tenant_admin",
                        "level": 4, "scope_level": "tenant", "permissions": [],
                        "engine_tenant_id": "my-tenant", "tenant_ids": ["uuid-123"]})
    assert resolve_tenant_id(req) == "my-tenant"

def test_resolve_tenant_id_fallback_to_tenant_ids():
    from bff._auth import resolve_tenant_id
    req = make_request({"user_id": "u1", "email": "a@b.com", "role": "tenant_admin",
                        "level": 4, "scope_level": "tenant", "permissions": [],
                        "engine_tenant_id": None, "tenant_ids": ["slug-001"]})
    assert resolve_tenant_id(req) == "slug-001"

def test_resolve_tenant_id_raises_401_no_context():
    from bff._auth import resolve_tenant_id
    req = make_request(None)
    with pytest.raises(HTTPException) as exc_info:
        resolve_tenant_id(req)
    assert exc_info.value.status_code == 401
```

## Security Notes
- This helper is the security boundary — it ensures tenant_id comes from a server-signed session, not client input.
- The `X-Auth-Context` header is only trusted because it is injected by `AuthMiddleware` inside the cluster (pod-to-pod). External requests go through the gateway first.

## Definition of Done
- File created at `_auth.py`
- All 3 unit tests pass
- Module importable from any BFF view: `from ._auth import resolve_tenant_id, account_filter`
