---
story_id: onboarding-D-3
title: Group access assignment API (Django) — assign groups to tenants and accounts
status: ready
sprint: onboarding-revamp-D
depends_on: [onboarding-D-1]
blocks: [onboarding-D-12]
sme: Django/DRF engineer
estimate: 1 day
---

# Story: Group access assignment API (Django)

## User Story
As an `org_admin`, I want to assign a group to a tenant with a role so that all members
of that group automatically get the assigned access level, and I can revoke access for
the whole group at once.

## Context
Story D-1 creates the group management APIs. This story adds the access assignment layer:
- `TenantGroupAccess` — grant a group access to a tenant with a role
- `AccountGroupAccess` — grant a group access to a specific cloud account with a role

**CORRECT DESIGN:** `TenantGroupAccess.group.customer_id` must match `request.user.customer_id`.
All inserts verify this cross-org boundary. The `tenant.customer_id` must also match.

## Files to Create/Modify
- `platform/cspm-backend/tenant_management/views.py` — add `TenantGroupAccessView`, `AccountGroupAccessView`
- `platform/cspm-backend/tenant_management/serializers.py` — add `TenantGroupAccessSerializer`
- `platform/cspm-backend/tenant_management/urls.py` — add routes

## Implementation Notes

### `TenantGroupAccessView`

```python
class TenantGroupAccessView(APIView):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("tenants:write")]

    def post(self, request, tenant_id):
        # Both group and tenant must belong to caller's org
        tenant = get_object_or_404(Tenants, id=tenant_id,
                                   customer_id=request.user.customer_id)
        group = get_object_or_404(CsmGroups, id=request.data["group_id"],
                                  customer_id=request.user.customer_id)
        role = get_object_or_404(Roles, name=request.data["role"])
        access, created = TenantGroupAccess.objects.get_or_create(
            group=group, tenant=tenant, defaults={"role": role},
        )
        if not created:
            access.role = role
            access.save(update_fields=["role"])
        return Response({"id": access.id, "created": created}, status=201 if created else 200)

    def delete(self, request, tenant_id, access_id):
        tenant = get_object_or_404(Tenants, id=tenant_id,
                                   customer_id=request.user.customer_id)
        access = get_object_or_404(TenantGroupAccess, id=access_id, tenant=tenant)
        access.delete()
        return Response(status=204)

    def get(self, request, tenant_id):
        tenant = get_object_or_404(Tenants, id=tenant_id,
                                   customer_id=request.user.customer_id)
        accesses = TenantGroupAccess.objects.filter(tenant=tenant).select_related("group", "role")
        return Response(TenantGroupAccessSerializer(accesses, many=True).data)
```

### Routes

```
POST/GET  /api/v1/tenants/{tenant_id}/group-access/
DELETE    /api/v1/tenants/{tenant_id}/group-access/{access_id}/
POST/GET  /api/v1/tenants/{tenant_id}/accounts/{account_id}/group-access/
DELETE    /api/v1/tenants/{tenant_id}/accounts/{account_id}/group-access/{access_id}/
```

## Acceptance Criteria
- [ ] AC1: `POST /tenants/{id}/group-access/` with valid org group → 201
- [ ] AC2: Group from foreign org (customer_id mismatch) → 404
- [ ] AC3: Tenant from foreign org → 404
- [ ] AC4: `DELETE /tenants/{id}/group-access/{access_id}/` → 204
- [ ] AC5: `GET /tenants/{id}/group-access/` → lists all group accesses for that tenant

## Definition of Done
- [ ] TenantGroupAccess and AccountGroupAccess views implemented
- [ ] All lookups include `customer_id=request.user.customer_id` filter
- [ ] Tests: valid assign, foreign group 404, foreign tenant 404, delete
- [ ] `grep "org_id\|organization_id" platform/tenant_management/views.py` → 0 hits in changed code
- [ ] bmad-security-reviewer: no BLOCKERs
