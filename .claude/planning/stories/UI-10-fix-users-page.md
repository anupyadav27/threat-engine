# UI-10: Fix onboarding/users page

## Status
Ready for dev

## Context
`frontend/src/app/onboarding/users/page.jsx` displays a team management table but the entire data set is a hardcoded `MOCK_USERS` array defined at the top of the file. No API call is made — every user sees the same fake names and roles regardless of which tenant they belong to. This story replaces the mock with real data from the `GET /api/users/` endpoint added in BE-03.

## Scope
**In scope:**
- Remove `MOCK_USERS` array and all references
- Call `fetchFromCspm('/api/users/?tenant_id=' + activeTenant.tenant_id)` on mount
- Map the API response fields to the table columns
- Wire the "Add User" / "Invite" button to `POST /cspm/api/auth/invite/create/`
- Add loading state and empty state

**Out of scope:**
- Edit or delete user functionality
- Role change UI (display only)
- Pagination
- Search/filter input
- Changing the Django backend (BE-03 handles that)

## Technical Notes

### Files to read before implementing
```bash
# The page file:
cat /Users/apple/Desktop/threat-engine/frontend/src/app/onboarding/users/page.jsx

# The tenant context:
cat /Users/apple/Desktop/threat-engine/frontend/src/lib/tenant-context.js

# The API lib to understand fetchFromCspm:
cat /Users/apple/Desktop/threat-engine/frontend/src/lib/api.js

# Find the invite endpoint to confirm it exists:
grep -rn "invite" /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py" -l
grep -rn "invite/create" /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
```

### API response shape (from BE-03)
```json
{
  "users": [
    {
      "id": "<uuid>",
      "email": "user@example.com",
      "name": "Jane Smith",
      "role": "admin",
      "status": "active",
      "last_login": "2026-04-29T10:00:00Z"
    }
  ]
}
```

### Table column mapping
| Column header (current in UI) | API field |
|-------------------------------|-----------|
| Name (or Email) | `name` and `email` |
| Role | `role` |
| Status | `status` |
| Last Login | `last_login` (format: `new Date(last_login).toLocaleDateString()`) |

Read the JSX to see the actual column headers — use whatever the current column structure is. Only the data source changes.

### Data fetching pattern
```jsx
'use client';
import { useState, useEffect } from 'react';
import { fetchFromCspm } from '@/lib/api';
import { useTenantContext } from '@/lib/tenant-context';  // confirm hook name

export default function UsersPage() {
  const { activeTenant } = useTenantContext();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!activeTenant?.tenant_id) return;
    setLoading(true);
    fetchFromCspm(`/api/users/?tenant_id=${activeTenant.tenant_id}`)
      .then(res => res.json())
      .then(data => {
        setUsers(data.users ?? []);
        setLoading(false);
      })
      .catch(err => {
        setError('Failed to load users');
        setLoading(false);
      });
  }, [activeTenant?.tenant_id]);
  ...
}
```

Note: `fetchFromCspm` may return a parsed object or a raw Response — read `api.js` to confirm. Adjust `.then(res => res.json())` if `fetchFromCspm` already parses.

### Empty state
```jsx
{!loading && users.length === 0 && (
  <div className="...">
    <p>No users in this tenant — invite someone to get started.</p>
    <button onClick={handleInvite}>Invite User</button>
  </div>
)}
```

### "Add User" / "Invite" button
Read the current button to see what it does (likely nothing or shows a modal). The backend invite endpoint is at `POST /api/auth/invite/create/` — confirm it exists:
```bash
grep -rn "invite/create\|InviteCreate\|invite_create" \
  /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
```
If it exists, wire the button to it. If it does not exist, add a TODO comment and disable the button (do not remove the button from the UI). Expected body:
```json
{ "email": "newuser@example.com", "tenant_id": "<t>", "role": "member" }
```
If wiring the invite, add a simple modal or prompt for email input.

### fetchFromCspm base URL prefix
The `fetchFromCspm` function in `api.js` likely prepends `/cspm` to the path. The path passed to it should be `/api/users/?tenant_id=...` (not `/cspm/api/users/...`). Read `api.js` to confirm the prefix logic and adjust accordingly.

## Implementation Steps

1. Read `onboarding/users/page.jsx` in full — note `MOCK_USERS` definition, all references, table JSX, and button handlers
2. Read `tenant-context.js` to confirm hook name and `activeTenant` shape
3. Read `api.js` to confirm `fetchFromCspm` return type
4. Check if invite endpoint exists in Django
5. Remove `MOCK_USERS` array and all references
6. Add the `useEffect` fetch block as shown above
7. Wire table rows to API response fields
8. Add loading state (spinner or skeleton)
9. Add empty state
10. Wire "Invite" button to invite endpoint (or add TODO/disabled if endpoint absent)
11. Run grep check

## Acceptance Criteria

**Given** `grep -n MOCK_USERS frontend/src/app/onboarding/users/page.jsx`
**When** the command runs
**Then** 0 matches are returned

**Given** a logged-in admin navigates to `/onboarding/users`
**When** the page loads
**Then** the table shows the real users from the DB for the active tenant

**Given** `SELECT COUNT(*) FROM tenant_users WHERE tenant_id='<t>'` returns N
**When** the page renders
**Then** the table has N rows

**Given** there are no users in the tenant (or `activeTenant` is null)
**When** the page renders
**Then** an empty state message is shown ("No users in this tenant — invite someone")

**Given** the page is loading data
**When** the fetch is in-flight
**Then** a loading indicator is visible (not a blank table)

## Test / Validation
```bash
# CI grep check:
grep -n "MOCK_USERS" /Users/apple/Desktop/threat-engine/frontend/src/app/onboarding/users/page.jsx
# Expected: 0 matches

# DB count vs UI count check:
# 1. Get tenant_id from /api/auth/me/
# 2. Run: kubectl exec deployment/engine-onboarding -- psql ... \
#         -c "SELECT COUNT(*) FROM tenant_users WHERE tenant_id='<t>'"
# 3. Compare with the rendered table row count in the browser

# Build check:
cd /Users/apple/Desktop/threat-engine/frontend && npm run build 2>&1 | grep -i error
# Expected: no errors
```

## Definition of Done
- [ ] `MOCK_USERS` array removed from `onboarding/users/page.jsx`
- [ ] All references to `MOCK_USERS` removed
- [ ] `useEffect` fetches `GET /api/users/?tenant_id=<activeTenantId>`
- [ ] Table rows populated from API response
- [ ] Loading state shown during fetch
- [ ] Empty state shown when `users.length === 0`
- [ ] `grep -n MOCK_USERS onboarding/users/page.jsx` → 0 matches
- [ ] Row count in UI matches DB `COUNT(*)` for the tenant
- [ ] `npm run build` passes

## Points
3

## Dependencies
BE-03 (`GET /api/users/`) must be merged first. This is a Wave 3 story.