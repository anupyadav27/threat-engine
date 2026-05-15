---
id: onboarding-D4
title: "Org profile + tenant-type API (Django)"
sprint: D
points: 1
depends_on: [auth-A1]
blocks: [onboarding-D7]
security_blocks: []
nist_csf: GV
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

Org admins and platform admins need to read and update their org profile (org name, contact email, billing tier) and see/change the `tenant_type` for each tenant. Currently there is no endpoint to read the org profile — only Django admin can access this data. The `tenant_type` column was added in auth-A1. This story adds two endpoint groups to the Django backend: (1) `GET/PATCH /api/org/profile` — reads and updates the org-level profile (customer name, contact email), (2) `GET/PATCH /api/tenants/{id}/type` — reads and updates `tenant_type` for a tenant (constrained to the caller's `customer_id`). This story also provides the internal endpoint that onboarding-C5 calls to validate tenant_type.

## Acceptance Criteria

- [ ] AC1: `GET /api/org/profile` returns the org profile for `request.user.customer_id`: `{"customer_id": str, "org_name": str, "contact_email": str, "plan": str}`. Requires `orgs:read` permission.
- [ ] AC2: `PATCH /api/org/profile` updates `org_name` and `contact_email` only. Requires `orgs:write` permission (org_admin or platform_admin).
- [ ] AC3: `PATCH /api/org/profile` does NOT allow updating `customer_id`, `plan`, or `billing_org_id` — these are read-only.
- [ ] AC4: `GET /api/tenants/{id}/type` returns `{"tenant_id": str, "tenant_type": str}`. Requires `orgs:read`. Returns 404 if tenant not in caller's org.
- [ ] AC5: `PATCH /api/tenants/{id}/type` updates `tenant_type`. Requires `orgs:write`. Valid values: `'cloud'`, `'vulnerability'`, `'secops'`.
- [ ] AC6: Attempting to set `tenant_type` to an invalid value returns HTTP 422.
- [ ] AC7: `GET /internal/tenants/{id}/type` — internal endpoint (no cookie auth, requires `X-Internal-Secret` header) returns `{"tenant_type": str}`. This is used by onboarding engine C5 to validate account_type.
- [ ] AC8: All tenant endpoints filter by `customer_id` — cross-org tenant access returns 404.
- [ ] AC9: `platform_admin` can read/patch any org's profile and any tenant's type.
- [ ] AC10: Unit tests: GET profile; PATCH name; invalid tenant_type → 422; internal endpoint with valid secret → 200; internal without secret → 401.

## Key Files

- `platform/cspm-backend/tenant_management/views.py` — Add org profile and tenant-type views
- `platform/cspm-backend/tenant_management/urls.py` — Wire new URL patterns
- `platform/cspm-backend/tenant_management/serializers.py` — Add profile and tenant-type serializers

## Technical Notes

**Org profile data model:** The org profile likely maps to the `customer_id` on either a Django `Organization` model or to the user's `customer_id` field plus a `Customer` table. Check:
```bash
grep -rn "org_name\|contact_email\|Customer\|Organisation" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" | head -20
```
If no `Customer` model exists, use `user_auth_users` fields as the org profile source (first `org_admin` user's data).

**Org profile PATCH schema:**
```python
class OrgProfilePatch(serializers.Serializer):
    org_name = serializers.CharField(max_length=255, required=False)
    contact_email = serializers.EmailField(required=False)

    # These must NOT appear in the writable schema:
    # customer_id, plan, billing_org_id
```

**Tenant type PATCH schema:**
```python
VALID_TENANT_TYPES = ['cloud', 'vulnerability', 'secops']

class TenantTypePatch(serializers.Serializer):
    tenant_type = serializers.ChoiceField(choices=VALID_TENANT_TYPES)
```

**Internal endpoint (for onboarding engine C5):**
```python
class InternalTenantTypeView(APIView):
    authentication_classes = []  # no cookie auth
    permission_classes = []

    def get(self, request, tenant_id):
        secret = request.headers.get("X-Internal-Secret")
        if secret != os.environ.get("X_INTERNAL_SECRET"):
            return Response({"detail": "Unauthorized"}, status=401)

        tenant = get_object_or_404(Tenant, id=tenant_id)
        return Response({"tenant_type": tenant.tenant_type})
```

**`X_INTERNAL_SECRET`** loaded from K8s secret `threat-engine-secrets` — same secret as used by Celery tasks in A3.

**URL patterns:**
```python
path('api/org/profile', OrgProfileView.as_view()),
path('api/tenants/<str:tenant_id>/type', TenantTypeView.as_view()),
path('internal/tenants/<str:tenant_id>/type', InternalTenantTypeView.as_view()),
```

**tenant_type column** was added in auth-A1 migration 0016. Verify it exists before implementing this story:
```bash
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py shell -c \
  "from tenant_management.models import Tenant; t = Tenant.objects.first(); print(t.tenant_type)"
```

## Security Checklist

- [ ] `orgs:read` and `orgs:write` permissions enforced on public endpoints
- [ ] Internal endpoint uses `X-Internal-Secret` — not cookie auth
- [ ] PATCH schema does not allow `customer_id` or `plan` to be modified
- [ ] Tenant queries filter by `customer_id` — cross-org returns 404
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] Internal endpoint reachable from onboarding engine (verify C5 integration)
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits
- [ ] Unit tests: 5 test cases (AC10)
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s