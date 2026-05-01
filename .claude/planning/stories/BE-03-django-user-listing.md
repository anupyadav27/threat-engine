# BE-03: Django — Add `GET /api/users/` user listing

## Status
Ready for dev

## Context
`frontend/src/app/onboarding/users/page.jsx` shows a team members table but uses a fully hardcoded `MOCK_USERS` array because no API endpoint exists to list users for a tenant. The Django backend has no user-listing endpoint — there is no `GET /api/users/` route at all. This story adds the endpoint with proper tenant-scoped access control so only admins of a tenant can list its members.

## Scope
**In scope:**
- New `UserListView` class in `platform/cspm-backend/user_auth/`
- Accepts `?tenant_id=X` query param
- Returns users from `TenantUsers` join table who are members of that tenant
- Requires authentication + admin/super_admin role in the requested tenant
- Register at `GET /api/users/`

**Out of scope:**
- Pagination (keep simple: return all users up to 200, add pagination as follow-up)
- User search or filtering by name/email
- Creating, updating, or deleting users
- Listing users across all tenants (must always scope to a tenant_id)

## Technical Notes

### Files to read before implementing
```bash
# Find where auth views live:
ls /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/views/

# The TenantUsers model (join table between users and tenants):
grep -rn "class TenantUsers\|class TenantUser\b" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
# Read that file

# The Users model:
grep -rn "class Users\b\|class User\b" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" | head -10
# Read the model file

# Current URL patterns:
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/urls.py

# Tenant management models (if separate):
ls /Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/
grep -rn "class TenantUsers" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/ --include="*.py"
```

### `TenantUsers` model expected fields
Based on the tenant management architecture, `TenantUsers` likely has:
- `tenant` (FK to tenant)
- `user` (FK to Users)
- `role` (str: "admin", "member", "super_admin", etc.)
- `status` (str: "active", "inactive", "pending")

Confirm by reading the actual model file before implementing.

### `Users` model expected fields for the response
```python
{
    "id": user.id,           # UUID
    "email": user.email,
    "name": ...,             # first_name + " " + last_name, or user.name if single field
    "role": tenant_user.role,
    "status": tenant_user.status,
    "last_login": user.last_login,  # datetime or None
}
```

### Role check implementation
```python
class UserListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        tenant_id = request.query_params.get('tenant_id')
        if not tenant_id:
            return Response(
                {"error": "tenant_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify the requesting user is admin/super_admin of this tenant
        try:
            requester_membership = TenantUsers.objects.get(
                user=request.user,
                tenant__tenant_id=tenant_id  # adjust field name based on actual model
            )
        except TenantUsers.DoesNotExist:
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        if requester_membership.role not in ('admin', 'super_admin'):
            return Response({"error": "Forbidden"}, status=status.HTTP_403_FORBIDDEN)

        # Fetch all members of the tenant
        memberships = TenantUsers.objects.filter(
            tenant__tenant_id=tenant_id
        ).select_related('user')

        users = []
        for m in memberships:
            u = m.user
            name = getattr(u, 'name', None) or f"{getattr(u,'first_name','')} {getattr(u,'last_name','')}".strip()
            users.append({
                "id": str(u.id),
                "email": u.email,
                "name": name,
                "role": m.role,
                "status": m.status,
                "last_login": u.last_login.isoformat() if u.last_login else None,
            })

        return Response({"users": users}, status=status.HTTP_200_OK)
```

Note: adjust `tenant__tenant_id` FK traversal path based on actual model relationships.

### Unknown tenant_id
If the `tenant_id` does not match any tenant, `TenantUsers.objects.filter(tenant__tenant_id=tenant_id)` returns an empty queryset. Do NOT return 404. Return HTTP 200 with `{"users": []}`. This is the spec requirement.

### URL registration
Add to `user_auth/urls.py`:
```python
from .views.user_management import UserListView  # or local_auth.py, wherever you put it

urlpatterns = [
    # existing...
    path('users/', UserListView.as_view(), name='user-list'),
]
```

Or if there is a separate `urls.py` in a `users/` sub-app, register there. Follow the existing URL registration pattern in the project.

**Note on URL prefix:** The endpoint is `GET /api/users/`, not `/api/auth/users/`. Make sure the URL is registered under the correct prefix. Check the project's root `urls.py` to understand how `user_auth/urls.py` is included:
```bash
cat /Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_backend/urls.py
```

## Implementation Steps

1. Read root `urls.py` to understand URL prefixes — confirm where `/api/users/` should be registered
2. Read `TenantUsers` model (including FK to tenant and user)
3. Read `Users` model — note `name` vs `first_name`/`last_name` fields
4. Read `user_auth/urls.py` for existing URL patterns
5. Decide which views file to put `UserListView` in (new file `views/user_management.py` is cleanest)
6. Implement `UserListView` with role check + query
7. Register the URL
8. Restart Django
9. Run curl tests

## Acceptance Criteria

**Given** an admin user sends `GET /api/users/?tenant_id=<t>` with a valid token
**When** Django processes the request
**Then** HTTP 200 is returned with `{ "users": [...] }` where each user has `id, email, name, role, status, last_login`

**Given** a non-admin member sends `GET /api/users/?tenant_id=<t>`
**When** Django processes the request
**Then** HTTP 403 is returned

**Given** an admin sends `GET /api/users/?tenant_id=<nonexistent_tenant>`
**When** Django processes the request
**Then** HTTP 200 is returned with `{ "users": [] }` (not 404)

**Given** `tenant_id` query param is missing
**When** Django processes the request
**Then** HTTP 400 is returned

**Given** an unauthenticated request
**When** Django processes the request
**Then** HTTP 401 or 403 is returned

**Given** there are 3 users in the tenant
**When** `SELECT COUNT(*) FROM tenant_users WHERE tenant_id='<t>'` runs
**Then** the count matches `users` array length in the API response

## Test / Validation
```bash
# Step 1: Get admin token
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8008/api/auth/login/ \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@cspm.local","password":"Admin@12345"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Step 2: Get tenant_id from /api/auth/me/
TENANT_ID=$(curl -s -b "access_token=$ADMIN_TOKEN" http://localhost:8008/api/auth/me/ \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['tenants'][0]['tenant_id'])")
echo "Using tenant: $TENANT_ID"

# Step 3: List users
curl -s -b "access_token=$ADMIN_TOKEN" \
  "http://localhost:8008/api/users/?tenant_id=$TENANT_ID" \
  | python3 -m json.tool
# Expected: HTTP 200, users array

# Step 4: Count check
# Compare array length with: SELECT COUNT(*) FROM tenant_users WHERE tenant_id='...'

# Step 5: Forbidden check (if you have a non-admin user token)
# curl -s -b "access_token=$MEMBER_TOKEN" "http://localhost:8008/api/users/?tenant_id=$TENANT_ID"
# Expected: HTTP 403

# Step 6: Unknown tenant
curl -s -b "access_token=$ADMIN_TOKEN" \
  "http://localhost:8008/api/users/?tenant_id=00000000-0000-0000-0000-000000000000" \
  | python3 -m json.tool
# Expected: HTTP 200, {"users": []}

# Step 7: Missing tenant_id
curl -s -b "access_token=$ADMIN_TOKEN" "http://localhost:8008/api/users/" | python3 -m json.tool
# Expected: HTTP 400
```

## Definition of Done
- [ ] `UserListView` class implemented with authentication check
- [ ] Admin/super_admin role check enforced before returning user list
- [ ] Returns `{ "users": [...] }` with fields: `id, email, name, role, status, last_login`
- [ ] Unknown `tenant_id` returns HTTP 200 `{"users": []}` (not 404)
- [ ] Missing `tenant_id` returns HTTP 400
- [ ] Unauthenticated request returns 401/403
- [ ] Non-admin request returns 403
- [ ] `GET /api/users/` registered in URL routing
- [ ] Curl tests pass for all 5 scenarios above

## Points
3

## Dependencies
None — this is a Wave 1 story, start immediately.
