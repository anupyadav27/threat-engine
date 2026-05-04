---
story_id: onboarding-D-1
title: Group management API (Django) — CRUD for customer-scoped groups
status: ready
sprint: onboarding-revamp-D
depends_on: [auth-A1]
blocks: [onboarding-D-3, onboarding-D-12]
sme: Django/DRF engineer
estimate: 2 days
---

# Story: Group management API (Django)

## User Story
As an `org_admin`, I want to create user groups scoped to my organization, add members,
and assign groups to tenants with a role, so that I can manage access for teams without
granting permissions individually.

## Context
Sprint A1 creates 4 new group tables in the cspm DB:
- `tenant_management_csmgroups` — groups scoped by `customer_id`
- `tenant_management_groupmembers` — user membership in groups
- `tenant_management_tenantgroupaccess` — grants a group access to a tenant with a role
- `tenant_management_accountgroupaccess` — grants a group access to a specific account

**CORRECT DESIGN:** Groups are scoped by `customer_id` (the org key), NOT by an
`organization_id` or `org_id`. An org_admin can only create/read groups where
`group.customer_id = request.user.customer_id`.

This story builds the ViewSets and URLs for group management. `groups:read` and
`groups:write` permissions are seeded by A1 migration.

## Files to Create/Modify
- `platform/cspm-backend/tenant_management/views.py` — add `GroupViewSet`, `GroupMemberViewSet`
- `platform/cspm-backend/tenant_management/serializers.py` — add `GroupSerializer`, `GroupMemberSerializer`
- `platform/cspm-backend/tenant_management/urls.py` — add group routes

## Implementation Notes

### `GroupViewSet`

```python
class GroupViewSet(viewsets.ModelViewSet):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("groups:read")]

    def get_queryset(self):
        # Scoped to caller's customer_id — never cross-org
        return CsmGroups.objects.filter(
            customer_id=self.request.user.customer_id
        ).order_by("name")

    def perform_create(self, serializer):
        require_permission_check(self.request, "groups:write")
        serializer.save(
            customer_id=self.request.user.customer_id,  # always from server-side
            created_by=self.request.user,
        )

    def perform_update(self, serializer):
        require_permission_check(self.request, "groups:write")
        serializer.save()

    def perform_destroy(self, instance):
        require_permission_check(self.request, "groups:write")
        instance.delete()
```

### `GroupMemberViewSet` (nested under group)

```python
class GroupMemberViewSet(viewsets.ModelViewSet):
    authentication_classes = [CookieTokenAuthentication]
    permission_classes = [HasPermission("groups:write")]

    def get_queryset(self):
        group = get_object_or_404(
            CsmGroups,
            pk=self.kwargs["group_pk"],
            customer_id=self.request.user.customer_id,  # cross-org guard
        )
        return GroupMembers.objects.filter(group=group)

    def perform_create(self, serializer):
        group = get_object_or_404(
            CsmGroups,
            pk=self.kwargs["group_pk"],
            customer_id=self.request.user.customer_id,
        )
        serializer.save(group=group)
```

### URLs

```python
# In tenant_management/urls.py:
groups_router = routers.NestedDefaultRouter(router, r"groups", lookup="group")
groups_router.register(r"members", GroupMemberViewSet, basename="group-members")

router.register(r"groups", GroupViewSet, basename="groups")
```

Routes produced:
- `GET/POST /api/v1/groups/`
- `GET/PATCH/DELETE /api/v1/groups/{id}/`
- `GET/POST /api/v1/groups/{group_pk}/members/`
- `DELETE /api/v1/groups/{group_pk}/members/{id}/`

## Security Controls

- `customer_id` is ALWAYS taken from `request.user.customer_id` (server-side) — never from request body
- `org_admin` with no `customer_id` set → `get_queryset()` returns empty queryset (not 500)
- `platform_admin` can see all groups via `customer_id` filter bypass (role.level == 1 check)
- `groups:write` required for all mutating operations; `groups:read` for list/detail

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/groups/` with org_admin context → creates group with `customer_id = request.user.customer_id`
- [ ] AC2: `GET /api/v1/groups/` with org_admin A → only sees groups where `customer_id = A.customer_id` (cross-org isolation)
- [ ] AC3: `POST /api/v1/groups/` with viewer → 403
- [ ] AC4: `POST /api/v1/groups/{id}/members/` with valid user_id → adds member
- [ ] AC5: `POST /api/v1/groups/{id}/members/` where group.customer_id != requester.customer_id → 404
- [ ] AC6: `customer_id` in request body is ignored — always set from `request.user.customer_id`

## Definition of Done
- [ ] GroupViewSet, GroupMemberViewSet implemented with RBAC
- [ ] `customer_id` always server-side from `request.user.customer_id`
- [ ] Cross-org isolation: group lookup always includes `customer_id=request.user.customer_id` filter
- [ ] Tests: create group, add member, cross-org isolation (403/404), viewer blocked
- [ ] `grep "org_id\|organization_id" platform/tenant_management/views.py` → 0 results
- [ ] bmad-security-reviewer: no BLOCKERs
