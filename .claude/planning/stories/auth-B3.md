---
id: auth-B3
title: "TenantViewSet DRF auth + export filter + IDP rate limit"
sprint: B
points: 2
depends_on: [auth-B1]
blocks: []
security_blocks: [BLOCK-08, BLOCK-09, BLOCK-10]
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

Three security blocks in the Django platform backend: BLOCK-08 — `TenantViewSet` in `platform/cspm-backend/tenant_management/views.py` uses DRF's default `SessionAuthentication` which does not validate the platform's cookie-based JWT (`access_token`). This means Celery's `sync_tenant_to_onboarding` call and frontend tenant-switcher calls may bypass auth. BLOCK-09 — `TenantViewSet` list/export endpoint does not filter by `customer_id` — a tenant_admin could potentially view tenants from other orgs via the list endpoint. BLOCK-10 — IDP callback endpoints (Google, SAML, Microsoft OIDC) have no rate limiting, making them vulnerable to token stuffing attacks. This story adds `CookieTokenAuthentication` to `TenantViewSet`, adds `customer_id` scoping to `get_queryset()`, and adds rate limiting to IDP callback endpoints using the throttle classes created in B1.

## Acceptance Criteria

- [ ] AC1 (BLOCK-08): `TenantViewSet` lists `authentication_classes = [CookieTokenAuthentication]` (or the platform's JWT cookie auth class).
- [ ] AC2 (BLOCK-08): `TenantViewSet` requests without a valid `access_token` cookie return HTTP 401.
- [ ] AC3 (BLOCK-08): The Celery `sync_tenant_to_onboarding` task (auth-A3) authenticates using `X-Internal-Secret` header — verify this path is not broken by the auth class change.
- [ ] AC4 (BLOCK-09): `TenantViewSet.get_queryset()` filters by `customer_id = request.user.customer_id` for `org_admin` and `tenant_admin` roles.
- [ ] AC5 (BLOCK-09): `platform_admin` role bypasses the `customer_id` filter (sees all tenants).
- [ ] AC6 (BLOCK-09): Calling `GET /api/tenants/` as `tenant_admin` with a different user's `customer_id` cookie returns only that user's tenants — cross-org tenants are not returned.
- [ ] AC7 (BLOCK-10): Google OAuth callback endpoint `/auth/google/callback/` has `IDP_CALLBACK_RATE_LIMIT = 20/min` applied.
- [ ] AC8 (BLOCK-10): SAML callback endpoint `/auth/saml/callback/` has the same rate limit.
- [ ] AC9 (BLOCK-10): Microsoft OIDC callback endpoint (if wired) has the same rate limit.
- [ ] AC10: Unit tests: tenant_admin queryset returns only same-customer_id tenants; cross-customer request returns empty list; 401 without cookie; IDP endpoint returns 429 after threshold.

## Key Files

- `platform/cspm-backend/tenant_management/views.py` — Add auth class, fix `get_queryset()`
- `platform/cspm-backend/user_auth/drf_auth.py` — `CookieTokenAuthentication` class (check if exists, create if not)
- `platform/cspm-backend/user_auth/throttles.py` — Add `IDPCallbackRateThrottle` (20/min)
- `platform/cspm-backend/user_auth/urls.py` — Apply throttle to IDP callback URLs

## Technical Notes

**Locate existing DRF auth class:**
```bash
grep -r "CookieToken\|cookie.*auth\|authentication_classes" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
```

**CookieTokenAuthentication (if not exists):**
```python
# user_auth/drf_auth.py
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from user_auth.utils import verify_access_token  # use existing JWT verify utility

class CookieTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        token = request.COOKIES.get("access_token")
        if not token:
            return None  # allow other authenticators to try
        try:
            payload = verify_access_token(token)
        except Exception:
            raise AuthenticationFailed("Invalid or expired access token")
        user = get_user_from_payload(payload)
        return (user, token)
```

**TenantViewSet queryset fix:**
```python
class TenantViewSet(viewsets.ModelViewSet):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        qs = Tenant.objects.all()
        if not user.has_perm('platform:admin'):
            qs = qs.filter(customer_id=user.customer_id)
        return qs
```

**IDP Rate Throttle:**
```python
# throttles.py
class IDPCallbackRateThrottle(AnonRateThrottle):
    rate = '20/min'
    scope = 'idp_callback'
```

**Find IDP callback URLs:**
```bash
grep -r "google.*callback\|saml.*callback\|oidc.*callback" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" -n
```

**Verify Celery internal path is not broken:**
The `sync_tenant_to_onboarding` Celery task uses `X-Internal-Secret` header — this goes to the onboarding engine, NOT to the Django `TenantViewSet`. Verify the internal Django endpoint (if any) used by Celery uses `X-Internal-Secret` auth, not `CookieTokenAuthentication`.

## Security Checklist

- [ ] `CookieTokenAuthentication` validates JWT expiry and signature — not just presence
- [ ] `customer_id` filter uses `request.user.customer_id` from authenticated session (not request body)
- [ ] `platform_admin` bypass is role-checked, not a header or query param
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests: auth, queryset scoping, cross-org isolation, rate limit 429
- [ ] bmad-security-reviewer: no BLOCKERs (BLOCK-08, BLOCK-09, BLOCK-10 resolved)
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: frontend tenant-switcher still works; Celery sync task still reaches onboarding engine