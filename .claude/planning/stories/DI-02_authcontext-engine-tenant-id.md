# DI-02: AuthContext — Add engine_tenant_id as First-Class Field

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P0 — required before DI-05 (BFF tenant_id removal)

## Story
As the gateway middleware, I need AuthContext to carry a resolved `engine_tenant_id` string alongside `tenant_ids`, so that BFF views can read the active engine tenant directly from the auth context without accepting it from query strings.

## Background

`AuthContext` (at `/Users/apple/Desktop/threat-engine/shared/auth/core/models.py`) currently has:
```python
tenant_ids: Optional[list[str]] = None  # None = unrestricted
account_ids: Optional[list[str]] = None
```

`tenant_ids` is a list of Django UUIDs written by `compute_auth_caches()` in `auth_utils.py`. It does NOT contain `engine_tenant_id` slugs (e.g. "my-tenant"). The BFF needs the engine-format tenant ID, not the platform UUID.

The `scope_cache` dict in `user_sessions` table has keys `tenant_ids` and `account_ids`. The `tenant_ids` list currently stores Django UUID strings because `compute_auth_caches` queries `TenantUsers.tenant_id` which resolves to `Tenants.id` (the UUID primary key).

## Root Cause
`compute_auth_caches` in `auth_utils.py` line:
```python
tenant_ids = list(
    TenantUsers.objects.filter(user=user, is_active=True)
    .values_list("tenant_id", flat=True)
)
```
This fetches `tenant.id` (Django UUID), not `tenant.engine_tenant_id`.

## Files to Modify

1. `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/utils/auth_utils.py`
2. `/Users/apple/Desktop/threat-engine/shared/auth/core/models.py`

## Change 1: auth_utils.py — compute_auth_caches

Change the scope_cache to store `engine_tenant_ids` using the correct column:

```python
# Before:
tenant_ids = list(
    TenantUsers.objects.filter(user=user, is_active=True)
    .values_list("tenant_id", flat=True)
)
scope_cache = {
    "tenant_ids": [str(tid) for tid in tenant_ids],
    "account_ids": None,
}

# After:
memberships = (
    TenantUsers.objects.filter(user=user, is_active=True)
    .select_related("tenant")
)
engine_tenant_ids = []
for m in memberships:
    eid = m.tenant.engine_tenant_id or str(m.tenant.id)
    engine_tenant_ids.append(eid)
scope_cache = {
    "tenant_ids": engine_tenant_ids,       # now contains engine slugs, not UUIDs
    "engine_tenant_id": engine_tenant_ids[0] if engine_tenant_ids else None,  # primary
    "account_ids": None,
}
```

## Change 2: models.py — AuthContext dataclass

Add `engine_tenant_id` field:

```python
@dataclass
class AuthContext:
    user_id: str
    email: str
    role: str
    level: int
    scope_level: str
    permissions: list[str] = field(default_factory=list)
    org_ids: Optional[list[str]] = None
    tenant_ids: Optional[list[str]] = None
    account_ids: Optional[list[str]] = None
    engine_tenant_id: Optional[str] = None   # <-- ADD THIS
```

Update `to_dict()`:
```python
"engine_tenant_id": self.engine_tenant_id,
```

Update `from_dict()`:
```python
engine_tenant_id=data.get("engine_tenant_id"),
```

Update `from_session_cache()`:
```python
engine_tenant_id=scope_cache.get("engine_tenant_id") if scope_cache else None,
```

## Acceptance Criteria

- [ ] After login, `user_sessions.scope_cache` contains `engine_tenant_id` key with value matching `tenants.engine_tenant_id` (not Django UUID)
- [ ] `AuthContext.engine_tenant_id` is populated on every authenticated request
- [ ] `AuthContext.to_header_json()` serializes `engine_tenant_id`
- [ ] `AuthContext.from_dict()` deserializes `engine_tenant_id`
- [ ] `AuthContext.from_session_cache()` populates `engine_tenant_id` from scope_cache
- [ ] Platform admin (`scope_cache.tenant_ids = None`) gets `engine_tenant_id = None` (unrestricted)
- [ ] Old sessions with no `engine_tenant_id` in scope_cache degrade gracefully to `None` (no KeyError)
- [ ] Existing tokens remain valid after this change (no session invalidation required)

## Security Notes
- Scope cache is written server-side only (in `compute_auth_caches`) — no client input accepted
- The change affects what is stored in the already-trusted `scope_cache` field
- Session table write happens only at login/signup — no retroactive change to live sessions needed

## Migration Note
Existing live sessions will have `engine_tenant_id = None` in their scope_cache until they re-login. This is acceptable: BFF fallback in DI-05 will use `tenant_ids[0]` if `engine_tenant_id` is None.

## Definition of Done
- `compute_auth_caches` unit test: asserts `scope_cache["engine_tenant_id"] == tenant.engine_tenant_id`
- Manual test: login → inspect `user_sessions` row via kubectl exec psql → confirm scope_cache has correct value
