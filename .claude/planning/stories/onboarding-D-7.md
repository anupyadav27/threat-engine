---
story_id: onboarding-D-7
title: Frontend — tenant-type selector + org/tenant switcher
status: ready
sprint: onboarding-revamp-D
depends_on: [auth-A2]
blocks: [onboarding-D-8, onboarding-D-12]
sme: React/Next.js 15 engineer
estimate: 2 days
---

# Story: Frontend — tenant-type selector + org/tenant switcher

## User Story
As a user, I want to switch between my tenants in the top nav and see a tenant-type
badge on each, so that I know which cloud environment I'm currently viewing security
data for.

## Context
**CORRECT DESIGN:** A user has exactly ONE org (identified by `customer_id`). Users can
have access to MULTIPLE tenants within that org (or via cross-org invites). The switcher
shows `tenants[]` — there is no org switcher (single org).

`AuthContext` in `frontend/src/lib/auth-context.js` already has `selectedTenant` and
`switchTenant()`. This story:
1. Ensures `tenants[]` from `/api/auth/me/` includes `tenant_type` field.
2. Adds `tenant_type` badge to the tenant switcher dropdown.
3. Creates `TenantSwitcher` component for the nav header.
4. Adds a "Add Tenant" button in the switcher that opens the new tenant creation modal.
5. Displays `customer_id` (shortened) in the user profile dropdown as the "Org ID".

## Files to Create/Modify
- `frontend/src/components/nav/TenantSwitcher.jsx` — new component
- `frontend/src/lib/auth-context.js` — ensure `tenants[]` include `tenant_type`
- `frontend/src/components/nav/UserMenu.jsx` — add Org ID display, Add Tenant button

## Implementation Notes

### `TenantSwitcher` component

```jsx
export function TenantSwitcher({ tenants, selectedTenant, onSwitch, onAddTenant }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger>
        <span>{selectedTenant?.name}</span>
        <TenantTypeBadge type={selectedTenant?.tenant_type} />
        <ChevronDown />
      </DropdownMenuTrigger>
      <DropdownMenuContent>
        {tenants.map(t => (
          <DropdownMenuItem key={t.id} onClick={() => onSwitch(t)}>
            <span>{t.name}</span>
            <TenantTypeBadge type={t.tenant_type} />
          </DropdownMenuItem>
        ))}
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={onAddTenant}>
          <Plus size={14} /> Add Tenant
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function TenantTypeBadge({ type }) {
  const colors = {
    cloud: "blue", secops: "purple", vulnerability: "orange",
    database: "teal", middleware: "gray", technology: "green",
  };
  return <Badge color={colors[type] || "gray"}>{type}</Badge>;
}
```

### Auth context update

The `/api/auth/me/` response must include `tenant_type` on each tenant. Ensure
`shared/api_gateway/bff/auth_bff.py` (or wherever the me/ view is) includes it:
```python
# In the tenants list building:
{
  "id": t["id"],
  "name": t["name"],
  "engine_tenant_id": t["id"],
  "tenant_type": t.get("tenant_type", "cloud"),
}
```

### No "selectedOrg" — correct design

There is no org switcher. The "org" is the user's `customer_id`. The UI shows:
- Top nav: TenantSwitcher (which tenant are you viewing)
- User menu: "Org ID: {customer_id[:8]}..." (informational only)

## Acceptance Criteria
- [ ] AC1: Tenant switcher shows all tenants the user has access to
- [ ] AC2: Each tenant shows `tenant_type` badge (cloud / secops / vulnerability / etc.)
- [ ] AC3: Selecting a tenant updates `selectedTenant` in AuthContext and re-fetches all dashboard data
- [ ] AC4: User menu shows "Org ID: {first 8 chars of customer_id}" for informational display
- [ ] AC5: "Add Tenant" button opens a modal (modal stub acceptable — full wizard in D8)
- [ ] AC6: No `organizations[]` array in frontend state (correct single-org design)

## Definition of Done
- [ ] `TenantSwitcher` component renders with tenant_type badges
- [ ] `/api/auth/me/` BFF response includes `tenant_type` on each tenant
- [ ] `switchTenant()` in AuthContext works correctly after this story
- [ ] No references to `selectedOrg`, `organizations[]`, or `org_id` in changed files
- [ ] Storybook story or manual browser test showing switcher with 2+ tenants
- [ ] bmad-security-reviewer: no BLOCKERs
