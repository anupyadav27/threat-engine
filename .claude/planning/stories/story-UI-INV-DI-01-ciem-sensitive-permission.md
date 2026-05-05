# Story DI-01: Django Migration — `ciem:sensitive` Permission

**Epic:** UI Investigation Journeys Sprint
**Status:** Ready for Dev
**Story Points:** 2
**Depends On:** None
**Blocks:** DI-05, DI-10

## Context

The CIEM tab on the Asset Investigation Journey (`/inventory/[assetId]`) must be gated behind a permission that prevents `viewer` role from seeing raw identity entitlement data. The existing permission system (migration `0009`) seeds 27 permissions across 5 roles. This story adds `ciem:sensitive` as migration `0011` (migration `0010` adds billing permissions — confirmed by reading `platform/cspm-backend/user_auth/migrations/0010_billing_permissions.py`).

## Scope

Add one new permission (`ciem:sensitive`) to the Django identity platform, assign it to the correct roles, and update the RBAC documentation.

**Out of scope:** BFF endpoint implementation (DI-05), frontend CIEM tab (DI-10), any CIEM engine changes.

## Files to Create/Modify

- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/migrations/0011_ciem_sensitive_permission.py` — new migration (create)
- `/Users/apple/Desktop/threat-engine/.claude/documentation/RBAC.md` — add `ciem:sensitive` row to the permission matrix

## Implementation Notes

**Migration file pattern:** Mirror `0010_billing_permissions.py` exactly. The migration must:
1. Define `NEW_PERMISSIONS` dict with entry: `"ciem:sensitive": ("ciem", "sensitive", False, "View identity entitlement data for a resource")`
2. Define `ROLE_GRANTS` dict mapping role names to their new permissions:
   - `"platform_admin"` → `["ciem:sensitive"]`
   - `"org_admin"` → `["ciem:sensitive"]`
   - `"tenant_admin"` → `["ciem:sensitive"]`
   - `"analyst"` → `["ciem:sensitive"]`
   - `"viewer"` → `[]` (no grant)
3. `dependencies` must be `[("user_auth", "0010_billing_permissions")]`
4. Use `uuid.uuid4()` for new permission `id` field (same as `0010`)
5. The `forward` function: upsert permission row into `user_auth_permission`, then upsert `user_auth_role_permissions` rows for each granted role. Look up role by `name` field.
6. The `reverse` function: delete the `user_auth_role_permissions` rows for `ciem:sensitive`, then delete the `user_auth_permission` row.

**DB tables involved:** `user_auth_permission`, `user_auth_role`, `user_auth_role_permissions` — these are the Django model tables for `Permission`, `Role`, and their M2M through table.

**Permission format:** `feature:action` — feature=`ciem`, action=`sensitive`. The `is_sensitive` column (3rd tuple element) is `False` because the permission gate itself is the control; the data behind it is sensitive.

**RBAC.md update:** Add a new row under "Feature Permissions" table:
```
| ciem:sensitive | View identity entitlement data | platform_admin, org_admin, tenant_admin, analyst | viewer |
```

**BFF enforcement pattern (for reference — implemented in DI-05):** After this migration runs, BFF endpoints call `require_permission("ciem:sensitive")` which reads from the `X-Auth-Context` header's `permissions` list. The header is populated by the Django middleware using this DB table. The permission check returns HTTP 403 with `detail="You need Analyst access to view identity entitlements"` for viewer sessions.

**Check latest migration number before running:**
```bash
ls /Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/migrations/ | sort | tail -5
```
Confirmed latest is `0010`. Next is `0011`.

## Acceptance Criteria

- [ ] `python manage.py migrate` runs migration `0011` without error from a clean state
- [ ] After migration: `SELECT p.key FROM user_auth_permission p JOIN user_auth_role_permissions rp ON rp.permission_id = p.id JOIN user_auth_role r ON r.id = rp.role_id WHERE r.name = 'analyst' AND p.key = 'ciem:sensitive'` returns 1 row
- [ ] After migration: same query for `viewer` role returns 0 rows
- [ ] `python manage.py migrate user_auth 0010` (reverse) removes the `ciem:sensitive` permission and all role grants cleanly
- [ ] `RBAC.md` has been updated with the new permission row
- [ ] Migration file has `dependencies = [("user_auth", "0010_billing_permissions")]`

## Security Gates

- **B-1 (AuthContext-only):** Permission is enforced via `X-Auth-Context` header populated server-side from session — viewer cannot self-grant via query param
- **No DEV_BYPASS_AUTH:** Migration does not add any bypass; standard `require_permission()` enforces it at the BFF layer

## Definition of Done

- [ ] Code written and passes linter (`black`, `pylint`)
- [ ] `python manage.py migrate` succeeds forward and backward
- [ ] RBAC.md updated
- [ ] bmad-security-reviewer approved (auth/DB change)
- [ ] bmad-qa acceptance test run
