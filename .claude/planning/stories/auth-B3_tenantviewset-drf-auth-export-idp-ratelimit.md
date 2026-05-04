# Story: Auth-B3 — TenantViewSet DRF Auth + Export Scoping + IDP Domain Rate-Limit

## Status: ready

## Context

`TenantViewSet` in `tenant_management/views.py` uses DRF `GenericViewSet` but has NO
`authentication_classes` or `permission_classes` set. The `get_queryset()` method calls
`build_tenant_query(params, user=self.request.user)`, which calls
`user_has_developer_role(user)` and if that check passes, returns ALL tenants with no
scoping (BLOCK-07 is related; this story focuses on the DRF auth layer, BLOCK-08 and
BLOCK-09).

The export action (line 91–149) calls `self.get_queryset()` for its data source but does
NOT add an independent explicit filter. If `get_queryset` is bypassed or the user's role
check is incorrect, the export would return all tenant data (BLOCK-09).

`TenantIDPByDomainView` (line 383–414) returns `tenant_id` in an unauthenticated response
(BLOCK-10). The domain lookup endpoint is also unrate-limited, enabling enumeration of
tenant-to-domain mappings at scale.

`ACCESS_TOKEN_LIFETIME_MINUTES` change from B-2 requires `CookieTokenAuthentication` to
accept the shorter-lived tokens — no code change needed there, but the DRF backend must be
implemented to enable proper session validation.

**Points:** Medium (1–2 days). New DRF authentication backend, permission class, view
decorator changes, export filter addition, IDP response trimming.

**Dependencies:** None. Can run in parallel with Sprint A.

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV Govern  [ ] ID Identify  [x] PR Protect  [x] DE Detect  [ ] RS Respond  [ ] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: IAM-01 (Identity and Access Management), IAM-03 (User Access Restriction),
  IVS-03 (Data Segregation — tenant data export scoping), TVM-01 (Threat and Vulnerability
  Management — IDP enumeration risk)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | `TenantViewSet` unauthenticated | Request without auth cookie reaches `TenantViewSet.list()` — `request.user` is `AnonymousUser`, `user_has_developer_role` returns False, but the `tenant_ids` filter falls back to `user.tenant_users` queryset returning empty not raising 401 | `CookieTokenAuthentication` raises `AuthenticationFailed` if no valid cookie |
| Elevation of Privilege | `user_has_developer_role` bypass | Any user whose DB role name is "developer" (any case) gets unrestricted tenant list | Remove bypass entirely (deferred to B-4); this story adds the auth layer that ensures the bypass is only reachable by authenticated users |
| Info Disclosure | Export endpoint cross-tenant data | Authenticated user with `tenants:read` calls `/tenants/export/` — `get_queryset()` scoping bug → exports other orgs' tenant data | Add explicit `id__in=allowed_ids` filter in export action independent of get_queryset |
| Info Disclosure | `TenantIDPByDomainView` tenant_id leak | Unauthenticated attacker enumerates `/tenants/idp-by-domain/?domain=` for all known domains → harvests tenant UUIDs | Remove `tenant_id` from response; keep only `idp_type` and `redirect_url` |
| DoS | `TenantIDPByDomainView` enumeration flood | Script queries all dictionary domains to map domain→tenant | IP-based rate limit 5/minute |

### PASTA

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Cross-tenant data exfil | Download all tenant records | Call /tenants/export/ with a low-privilege JWT that has `tenants:read` but `get_queryset` has a bug | Double-filter in export: independent `id__in=user_tenant_ids` regardless of get_queryset result |
| Credential bypass | Reach TenantViewSet without valid session | Send request without cookie — Django REST Framework default auth falls back to session/basic which may succeed in some configs | Explicit `authentication_classes = [CookieTokenAuthentication]` rejects all non-cookie auth |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1190 | Exploit Public-Facing Application | D3-FAPA Filter Application Policy | DRF auth enforcement on TenantViewSet |
| T1078 | Valid Accounts (cross-tenant) | D3-UBA User Behavior Analytics | Export action double-filtered by caller's tenant membership |
| T1589 | Gather Victim Identity Info (IDP enumeration) | D3-OAM Object Access Monitoring | Remove tenant_id from IDP by-domain response; rate limit |

---

## Acceptance Criteria (Functional)

1. New DRF authentication class `CookieTokenAuthentication` in
   `user_auth/drf_auth.py` (new file):
   - Reads `access_token` from `request.COOKIES`.
   - Calls `_resolve_user_and_session` logic (same as `MeView`) using `token_hint` pre-filter (from B-2).
   - Returns `(user, session)` on success.
   - Returns `(None, None)` if no cookie (unauthenticated — allows DRF to continue to next backend or deny).
   - Raises `AuthenticationFailed` if cookie is present but invalid/expired.
2. `TenantViewSet` gains:
   ```python
   authentication_classes = [CookieTokenAuthentication]
   permission_classes = [IsAuthenticated, HasTenantPermission("tenants:read")]
   ```
   `HasTenantPermission` is a new DRF `BasePermission` subclass that checks
   `request.user`'s `permissions_cache` (from session) for the required key.
3. An unauthenticated request to `GET /api/v1/tenants/` returns HTTP 401, not 200 or 500.
4. A request authenticated as a user with no `tenants:read` permission returns HTTP 403.
5. The `export` action in `TenantViewSet` adds an explicit secondary filter BEFORE
   building the export data:
   ```python
   from tenant_management.models import TenantUsers
   allowed_ids = list(
       TenantUsers.objects.filter(user=request.user, is_active=True)
       .values_list("tenant_id", flat=True)
   )
   queryset = queryset.filter(id__in=allowed_ids)
   ```
   This filter is applied even if `get_queryset()` already scopes the data — defence in depth.
6. `TenantIDPByDomainView.get()` response body changes from:
   ```json
   {"tenant_id": "...", "idp_type": "google_oauth", "idp_name": "Acme Google"}
   ```
   to:
   ```json
   {"idp_type": "google_oauth", "redirect_url": "/auth/sso/google/"}
   ```
   - `tenant_id` is removed from the response entirely.
   - `idp_name` is removed (it may reveal internal naming).
   - A `redirect_url` field is computed as `/auth/sso/{idp_type}/` (static path, no tenant info).
7. `TenantIDPByDomainView` gets IP-based rate limit of 5 requests/minute. Implement as
   `IDPByDomainRateThrottle(AnonRateThrottle)` with `rate = "5/minute"`.
8. When no IDP is found for the domain, the response is:
   ```json
   {"idp_type": null, "redirect_url": null}
   ```
   (Previously `{"tenant_id": null}` — update frontend callers.)

---

## Acceptance Criteria (Security — must pass bmad-security-reviewer)

- [ ] `CookieTokenAuthentication` does NOT accept `Authorization: Bearer` header — cookie-only.
- [ ] `TenantViewSet` export action: `allowed_ids` is computed from `TenantUsers` table filtered by `request.user` — NOT derived from the request query params.
- [ ] `TenantIDPByDomainView` response contains no `tenant_id` field — confirmed by test asserting key absence.
- [ ] Rate limit throttle scope is `"idp_domain"` distinct from other throttle scopes.
- [ ] `HasTenantPermission` checks `session.permissions_cache` (server-side cached list) — NOT a client-supplied header.
- [ ] `CookieTokenAuthentication` uses `token_hint` pre-filter (B-2) for performance — no full-table PBKDF2 scan.
- [ ] No plaintext credentials in logs.
- [ ] BLOCK-08, BLOCK-09, BLOCK-10 marked closed after this story merges.
- [ ] Any frontend code that reads `response.tenant_id` from IDP-by-domain endpoint must be updated to `response.redirect_url` (grep frontend for the endpoint URL).

---

## Technical Notes

### New file: `platform/cspm-backend/user_auth/drf_auth.py`

```python
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from user_auth.models import UserSessions
from user_auth.utils.auth_utils import verify_token

class CookieTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        access_token = request.COOKIES.get("access_token")
        if not access_token:
            return None  # not an error — let DRF try next backend or deny
        hint = access_token[:8]
        sessions = UserSessions.objects.filter(
            revoked=False, token_hint=hint
        ).select_related("user")
        for session in sessions:
            if session.expires_at < timezone.now():
                continue
            if verify_token(access_token, session.token):
                return (session.user, session)
        raise AuthenticationFailed("Invalid or expired session token.")
```

### New file: `platform/cspm-backend/user_auth/drf_permissions.py`

```python
from rest_framework.permissions import BasePermission

class HasTenantPermission(BasePermission):
    def __init__(self, required_permission: str):
        self.required_permission = required_permission

    def has_permission(self, request, view):
        session = request.auth  # the session object returned by CookieTokenAuthentication
        if not session:
            return False
        cache = getattr(session, "permissions_cache", []) or []
        return self.required_permission in cache
```

DRF `permission_classes` does not support constructor args natively. Use a factory:
```python
def HasPermission(perm: str):
    class _Perm(HasTenantPermission):
        def __init__(self):
            super().__init__(perm)
    return _Perm
```

### `TenantViewSet` changes

In `tenant_management/views.py` at the class definition (line 31):
```python
from user_auth.drf_auth import CookieTokenAuthentication
from user_auth.drf_permissions import HasPermission
from rest_framework.permissions import IsAuthenticated

class TenantViewSet(...):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated, HasPermission("tenants:read")]
    ...
```

### `TenantIDPByDomainView` changes

Current response (line 409–414):
```python
return JsonResponse(
    {"tenant_id": str(config.tenant_id), "idp_type": config.idp_type, "idp_name": config.idp_name},
    status=200,
)
```

Replace with:
```python
redirect_url = f"/auth/sso/{config.idp_type}/"
return JsonResponse(
    {"idp_type": config.idp_type, "redirect_url": redirect_url},
    status=200,
)
```

Also add to `TenantIDPByDomainView`:
```python
throttle_classes = [IDPByDomainRateThrottle]
```

---

## Key Files

- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/drf_auth.py` — new file
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/drf_permissions.py` — new file
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/views.py` (lines 31–38 class definition, 91–105 export action, 383–414 TenantIDPByDomainView)
- Frontend: any file reading `response.tenant_id` from `/tenants/idp-by-domain/` endpoint

---

## Definition of Done

- [ ] Test: `test_tenantviewset_unauthenticated_returns_401`
- [ ] Test: `test_tenantviewset_no_permission_returns_403`
- [ ] Test: `test_export_scoped_to_caller_tenants` — user with 2 tenants only receives rows for those 2 even if DB has 5
- [ ] Test: `test_idp_by_domain_no_tenant_id_in_response`
- [ ] Test: `test_idp_by_domain_rate_limit_429` — 6th request in one minute returns 429
- [ ] Frontend updated: no code reads `response.tenant_id` from IDP-by-domain response
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] BLOCK-08, BLOCK-09, BLOCK-10 marked closed