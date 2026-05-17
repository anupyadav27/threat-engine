---
id: onboarding-D3
title: "Group access assignment API (Django)"
sprint: D
points: 1
depends_on: [onboarding-D1]
blocks: [onboarding-D12]
security_blocks: []
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

With groups created (onboarding-D1), org admins need to assign groups to specific tenants or cloud accounts to grant scoped access to users in those groups. The `tenant_group_access` and `account_group_access` tables already exist in the platform DB. This story adds the API endpoints to create and delete these access assignments. A group assigned to a tenant grants all group members the ability to view/manage that tenant. A group assigned to a cloud account scopes members to that specific account. This is the enforcement mechanism that makes group-based RBAC meaningful — without it, groups exist but have no effect on access.

## Acceptance Criteria

- [ ] AC1: `POST /api/groups/{group_id}/tenants` assigns a group to a tenant. Body: `{"tenant_id": "<uuid>", "role": "tenant_admin"}`. Returns 201.
- [ ] AC2: `DELETE /api/groups/{group_id}/tenants/{tenant_id}` removes the group-tenant assignment. Returns 204.
- [ ] AC3: `POST /api/groups/{group_id}/accounts` assigns a group to a cloud account. Body: `{"account_id": "<uuid>", "role": "analyst"}`. Returns 201.
- [ ] AC4: `DELETE /api/groups/{group_id}/accounts/{account_id}` removes the group-account assignment. Returns 204.
- [ ] AC5: Before creating any assignment, verify the group belongs to `request.user.customer_id` — return 404 if not (prevents cross-org assignment).
- [ ] AC6: Before assigning a group to a tenant, verify the tenant belongs to `request.user.customer_id` — return 404 if not.
- [ ] AC7: Before assigning a group to an account, verify the account belongs to the caller's `tenant_id` or `customer_id` — return 404 if not.
- [ ] AC8: All endpoints require `users:write` permission.
- [ ] AC9: `platform_admin` can assign groups across any `customer_id` (bypasses org boundary check).
- [ ] AC10: Unit tests: valid assignment → 201; cross-org group → 404; cross-org tenant → 404; delete → 204.

## Key Files

- `platform/cspm-backend/group_management/views.py` — Add assignment endpoints (extend from D1)
- `platform/cspm-backend/group_management/urls.py` — Wire new URL patterns
- `platform/cspm-backend/group_management/serializers.py` — Add assignment serializers

## Technical Notes

**Existing table names (already in DB — use `managed = False`):**
- `tenant_group_access` — columns likely: `id`, `group_id`, `tenant_id`, `role`, `created_at`
- `account_group_access` — columns likely: `id`, `group_id`, `account_id`, `role`, `created_at`

**Verify actual column names:**
```bash
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py shell -c \
  "from django.db import connection; cur = connection.cursor(); \
   cur.execute(\"SELECT column_name FROM information_schema.columns WHERE table_name='tenant_group_access'\"); \
   print(cur.fetchall())"
```

**Models (unmanaged — tables exist):**
```python
class TenantGroupAccess(models.Model):
    class Meta:
        db_table = 'tenant_group_access'
        managed = False

    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    tenant_id = models.CharField(max_length=255)
    role = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)

class AccountGroupAccess(models.Model):
    class Meta:
        db_table = 'account_group_access'
        managed = False

    group = models.ForeignKey(Group, on_delete=models.CASCADE)
    account_id = models.CharField(max_length=255)
    role = models.CharField(max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
```

**Cross-org boundary checks:**
```python
def validate_group_ownership(group_id, user):
    group = get_object_or_404(Group, id=group_id)
    if not user.has_perm('platform:admin'):
        if group.customer_id != user.customer_id:
            raise Http404  # don't leak existence
    return group

def validate_tenant_ownership(tenant_id, user):
    from tenant_management.models import Tenant
    tenant = get_object_or_404(Tenant, id=tenant_id)
    if not user.has_perm('platform:admin'):
        if tenant.customer_id != user.customer_id:
            raise Http404
    return tenant
```

**URL patterns:**
```python
# group_management/urls.py
urlpatterns = [
    # ... existing group URLs from D1 ...
    path('<uuid:group_id>/tenants/', views.GroupTenantAssignView.as_view()),
    path('<uuid:group_id>/tenants/<str:tenant_id>/', views.GroupTenantDeleteView.as_view()),
    path('<uuid:group_id>/accounts/', views.GroupAccountAssignView.as_view()),
    path('<uuid:group_id>/accounts/<str:account_id>/', views.GroupAccountDeleteView.as_view()),
]
```

**Duplicate assignment handling:** If the group-tenant or group-account pair already exists, return 200 (idempotent) rather than 409 — use `get_or_create()`.

## Security Checklist

- [ ] All assignment endpoints require `users:write` permission
- [ ] Org boundary check on group, tenant, and account before assignment
- [ ] `platform_admin` bypass for cross-org assignments
- [ ] No `org_id` or `organizations` references
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `managed = False` on all new models — no unwanted migrations
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits
- [ ] Unit tests: 4 test cases (AC10)
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s