---
id: onboarding-D1
title: "Group management API (Django)"
sprint: D
points: 2
depends_on: [auth-A1]
blocks: [onboarding-D3, onboarding-D12]
security_blocks: []
nist_csf: PR.AC
owasp_samm: Implementation
csa_ccm: AIS-04
---

## Context

The `csm_groups`, `group_members`, `tenant_group_access`, and `account_group_access` tables already exist in the Django platform DB (verified in architecture audit 2026-05-11). However, there are no API endpoints to create, list, update, or delete groups, or to manage group membership. Org admins need groups to scope users' access to specific tenants or cloud accounts without granting them full org-level access. This story builds the CRUD API for groups in Django, using the existing table structures. The API lives in `platform/cspm-backend/` — likely a new `group_management/` Django app or views under an existing app. Endpoints require `users:write` permission (enforced via DRF permission classes or a custom decorator consistent with the existing auth pattern in this codebase).

## Acceptance Criteria

- [ ] AC1: `GET /api/groups/` returns a list of groups scoped to `request.user.customer_id` (enforced by `enforce_org_boundary()`).
- [ ] AC2: `POST /api/groups/` creates a new group with `name`, `description`, `customer_id = request.user.customer_id`. Returns 201 with the created group.
- [ ] AC3: `GET /api/groups/{id}/` returns the group — 404 if not in caller's `customer_id`.
- [ ] AC4: `PATCH /api/groups/{id}/` updates `name` and `description` only — 403 if caller is not `org_admin` or `platform_admin`.
- [ ] AC5: `DELETE /api/groups/{id}/` deletes the group and cascades to `group_members` — 403 if caller is not `org_admin` or `platform_admin`.
- [ ] AC6: `POST /api/groups/{id}/members/` adds a user to a group. Body: `{"user_id": "<uuid>"}`. Returns 201.
- [ ] AC7: `DELETE /api/groups/{id}/members/{user_id}/` removes a user from a group. Returns 204.
- [ ] AC8: All endpoints require `users:write` permission EXCEPT `GET` which requires `users:read`.
- [ ] AC9: All group queries filter by `customer_id` — cross-org group access returns 404, not group data.
- [ ] AC10: Unit tests: list scoped to customer; create; patch; delete cascades members; add/remove member; cross-org 404.

## Key Files

- `platform/cspm-backend/group_management/` — Create new Django app directory (or views file)
- `platform/cspm-backend/group_management/views.py` — Group CRUD views
- `platform/cspm-backend/group_management/urls.py` — URL routing
- `platform/cspm-backend/group_management/serializers.py` — DRF serializers
- `platform/cspm-backend/cspm_backend/urls.py` — Register group_management URLs

## Technical Notes

**Verify existing table structure:**
```bash
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py shell -c \
  "from django.db import connection; \
   cursor = connection.cursor(); \
   cursor.execute(\"SELECT column_name FROM information_schema.columns WHERE table_name='csm_groups'\"); \
   print(cursor.fetchall())"
```

**Django model (read from existing table — do NOT create migration for existing tables):**
```python
# group_management/models.py
from django.db import models

class Group(models.Model):
    class Meta:
        db_table = 'csm_groups'
        managed = False  # table already exists

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    customer_id = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

class GroupMember(models.Model):
    class Meta:
        db_table = 'group_members'
        managed = False

    group = models.ForeignKey(Group, on_delete=models.CASCADE, related_name='members')
    user_id = models.CharField(max_length=255)
    added_at = models.DateTimeField(auto_now_add=True)
```

**`managed = False`** — the tables already exist; Django should not try to create or alter them.

**Authentication pattern:** Use `CookieTokenAuthentication` from auth-B3. Permission class uses `users:write`/`users:read` from the existing RBAC system.

**enforce_org_boundary in get_queryset:**
```python
from platform.utils.rbac import enforce_org_boundary

class GroupViewSet(viewsets.ModelViewSet):
    authentication_classes = [CookieTokenAuthentication]

    def get_queryset(self):
        return enforce_org_boundary(self.request.user, Group.objects.all())

    def perform_create(self, serializer):
        serializer.save(customer_id=self.request.user.customer_id)
```

**No `org_id` or `organizations` references** — use `customer_id` throughout.

**URL registration in main urls.py:**
```python
path('api/groups/', include('group_management.urls')),
```

## Security Checklist

- [ ] All endpoints require `CookieTokenAuthentication`
- [ ] Group queries always filter by `customer_id = request.user.customer_id`
- [ ] `customer_id` set server-side on create — never from request body
- [ ] `PATCH` and `DELETE` restricted to `org_admin` or `platform_admin`
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `managed = False` on all models — no unwanted migrations
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits
- [ ] Unit tests: 6 test cases (AC10)
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: GET /api/groups/ returns 200 for org_admin; 403 for viewer