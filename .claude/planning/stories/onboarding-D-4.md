---
story_id: onboarding-D-4
title: Org profile + tenant-type API (Django) — read/update org profile, tenant_type
status: ready
sprint: onboarding-revamp-D
depends_on: [auth-A1]
blocks: [onboarding-D-7]
sme: Django/DRF engineer
estimate: 1 day
---

# Story: Org profile + tenant-type API (Django)

## User Story
As an `org_admin`, I want to read and update my org's profile (display name, description)
and see which tenant_type each of my tenants has, so that the wizard can show the correct
tenant-type selector and settings pages.

## Context
**CORRECT DESIGN:** There is no `organizations` table. The org is identified by
`customer_id = str(user.id)`. The "org profile" is derived from:
- Founding user's name/email (read from `user_auth_users`)
- List of tenants where `tenant.customer_id = request.user.customer_id`
- `tenant.tenant_type` for each tenant (added in A1 migration)

This story adds:
1. `GET /api/v1/org/profile/` — returns `{customer_id, display_name, email, tenants[]}`
2. `PATCH /api/v1/org/profile/` — allows updating `display_name` (stored on user.first_name or a profile field)
3. `GET /api/v1/tenants/` already works for tenant listing; add `tenant_type` to serializer output
4. `POST /api/v1/tenants/` — create a new tenant scoped to the requester's org, with explicit `tenant_type`

## Files to Create/Modify
- `platform/cspm-backend/tenant_management/views.py` — add `OrgProfileView`
- `platform/cspm-backend/tenant_management/serializers.py` — update `TenantSerializer` to include `tenant_type`
- `platform/cspm-backend/tenant_management/views.py` — update `TenantViewSet.create()` to set `customer_id`

## Implementation Notes

### `OrgProfileView`

```python
class OrgProfileView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("orgs:read")]

    def get(self, request):
        tenants = Tenants.objects.filter(
            customer_id=request.user.customer_id
        ).values("id", "name", "slug", "tenant_type", "status")
        return Response({
            "customer_id": request.user.customer_id,
            "email": request.user.email,
            "display_name": request.user.get_full_name() or request.user.email,
            "tenants": list(tenants),
        })

    def patch(self, request):
        require_permission_check(request, "orgs:write")
        name = request.data.get("display_name", "").strip()
        if name:
            parts = name.split(" ", 1)
            request.user.first_name = parts[0]
            request.user.last_name = parts[1] if len(parts) > 1 else ""
            request.user.save(update_fields=["first_name", "last_name"])
        return Response({"updated": True})
```

### `TenantViewSet.create()` — set customer_id from requester

```python
def perform_create(self, serializer):
    require_permission_check(self.request, "tenants:write")
    # customer_id comes from server-side, never from request body
    serializer.save(
        customer_id=self.request.user.customer_id,
        status="provisioning",
    )
    # Dispatch async sync task
    sync_tenant_to_onboarding.delay(
        tenant_id=str(serializer.instance.id),
        customer_id=self.request.user.customer_id,
    )
```

### URL

```
GET/PATCH /api/v1/org/profile/
```

## Acceptance Criteria
- [ ] AC1: `GET /api/v1/org/profile/` returns `customer_id`, `email`, and `tenants[]` list
- [ ] AC2: `tenants[]` only includes tenants where `tenant.customer_id = request.user.customer_id`
- [ ] AC3: `PATCH /api/v1/org/profile/` with `display_name` updates user name
- [ ] AC4: `POST /api/v1/tenants/` creates tenant with `customer_id = request.user.customer_id` (body value ignored)
- [ ] AC5: `TenantSerializer` includes `tenant_type` field in output
- [ ] AC6: viewer → 403 on `PATCH /api/v1/org/profile/`

## Definition of Done
- [ ] `OrgProfileView` implemented — read/update, scoped to customer_id
- [ ] `TenantViewSet.perform_create()` sets customer_id from server-side
- [ ] `TenantSerializer` includes tenant_type
- [ ] Tests: org profile read, patch, tenant list scoping, cross-org isolation
- [ ] `grep "org_id\|organization_id" platform/tenant_management/views.py` → 0 new hits
- [ ] bmad-security-reviewer: no BLOCKERs
