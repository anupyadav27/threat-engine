# DI-01: Fix Header — "Workspace" Terminology and Tenant Switch Bug

## Track
Track 1 — Auth Context + Tenant Scoping

## Priority
P0 — blocks UX clarity for all other tenant-scoped stories

## Story
As a user switching between tenants in the header, I need the UI to use consistent "Tenant" naming and to pass the engine_tenant_id (not the Django UUID) when switching, so that data loads correctly after a switch.

## Current State (the bug)

`Header.jsx` line 33:
```
const currentTenantName = activeTenant?.tenant_name || 'Select Workspace';
```

Line 123:
```
<div className="text-[10px] mt-0.5">No workspaces found</div>
```

Line 135:
```
+ Manage workspaces
```

These UI strings say "Workspace" but all code variables (`tenant_id`, `engine_tenant_id`) and system concepts say "Tenant". The inconsistency caused the original bug where a developer saw "Workspace" in the UI and `tenant_id` in the code and assumed they meant different things.

Additionally: `switchTenant(t.engine_tenant_id || t.tenant_id)` — the `|| t.tenant_id` fallback used to be `t.tenant_id` alone (before the fix in v-threat-tenant-fix1). This story confirms and hardens the correct form.

## Files to Modify
- `/Users/apple/Desktop/threat-engine/frontend/src/components/layout/Header.jsx`

## Exact Changes

1. Line 33: `'Select Workspace'` → `'Select Tenant'`
2. Line 123 (inside dropdown, empty state): `'No workspaces found'` → `'No tenants found'`
3. Line 135 (manage link): `'+ Manage workspaces'` → `'+ Manage tenants'`

These are 3 string literals. No logic change.

## Acceptance Criteria

- [ ] Header dropdown label reads "Select Tenant" when no tenant is active
- [ ] Header dropdown empty state reads "No tenants found"
- [ ] "Manage" link text reads "+ Manage tenants"
- [ ] `switchTenant()` call passes `t.engine_tenant_id || t.tenant_id` (confirm current code already does this — do NOT revert to `t.tenant_id` alone)
- [ ] No TypeScript or lint errors
- [ ] Visual regression: dropdown opens, shows tenant names, active tenant is highlighted

## Security Notes
No auth logic change. String cosmetic only.

## Definition of Done
- PR with only the 3 string changes
- Reviewed diff confirms `switchTenant` passes `engine_tenant_id` not `tenant_id`
- Frontend builds without error
