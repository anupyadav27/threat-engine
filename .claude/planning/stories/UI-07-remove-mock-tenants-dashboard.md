# UI-07: Remove `MOCK_TENANTS` from dashboard

## Status
Ready for dev

## Context
`frontend/src/app/dashboard/page.jsx` lines 38–255 contain a large `MOCK_TENANTS` array and two helper functions `DS()` and `DC()` that generate fake domain scores and domain checks. The tenant switcher, IAM summary table, security group table, and risk score cards all read from this mock data. Real users see the same fabricated numbers regardless of which tenant they select or what their actual scan results are. This story deletes the mock data and wires all dashboard widgets to real data from `useViewFetch('dashboard')`.

## Scope
**In scope:**
- Delete `MOCK_TENANTS` array, `DS()`, `DC()` helper functions and ALL their references
- Wire the tenant switcher to `TenantContext.tenants` (real tenants from auth)
- Wire domain score cards, IAM summary table, SG table, risk table to BFF response fields
- Add empty state when `tenants.length === 0`

**Out of scope:**
- Changing the BFF `view_dashboard` handler or its response shape (treat the response as-is)
- Redesigning the dashboard layout or adding new widgets
- Changing what data the BFF returns

## Technical Notes

### Read these files first
```bash
# The dashboard page itself:
cat -n /Users/apple/Desktop/threat-engine/frontend/src/app/dashboard/page.jsx | head -300

# The tenant context shape:
cat /Users/apple/Desktop/threat-engine/frontend/src/lib/tenant-context.js

# BFF dashboard handler to understand response shape:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/dashboard.py
# OR if it is view_dashboard in a combined file:
grep -rn "view_dashboard\|def dashboard" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/
```

### `TenantContext.tenants` shape
From the `GET /api/auth/me/` response, tenants look like:
```json
[{ "tenant_id": "...", "tenant_name": "...", "role": "...", "status": "..." }]
```
The tenant switcher dropdown should list `tenant_name` values and call `setActiveTenant(tenant)` on selection.

### BFF `view_dashboard` response shape
Read the BFF handler before coding to map fields correctly. Based on what other engines return, expect something like:
```json
{
  "kpiGroups": [...],
  "domainScores": { "iam": 72, "network": 85, "data": 60, ... },
  "openFindings": 142,
  "criticalFindings": 23,
  "iamSummary": [...],
  "sgSummary": [...],
  "riskSummary": [...],
  "recentScans": [...]
}
```
The exact field names are in the BFF handler — read it before writing JSX data bindings.

### Tenant switcher wiring
```jsx
// BEFORE (mock):
const [selectedTenant, setSelectedTenant] = useState(MOCK_TENANTS[0]);

// AFTER (real):
const { tenants, activeTenant, setActiveTenant } = useTenantContext();
// Use activeTenant in the switcher's current value display
// Call setActiveTenant(tenant) on selection change
```
Find the actual hook name by reading `tenant-context.js`.

### Re-fetch on tenant change
`useViewFetch` already re-fetches when `activeTenant.tenant_id` changes (implemented in UI-01). So after wiring `setActiveTenant`, the data will refresh automatically. No extra `useEffect` needed.

### Empty state
When `tenants.length === 0`, render:
```jsx
<div className="...existing container classes...">
  <p>No cloud accounts onboarded.</p>
  <a href="/onboarding">Go to Onboarding</a>
</div>
```
Place this check after the `loading`/`error` guards, before the main dashboard render.

### Split recommendation (if needed)
If the story feels too large, split into:
- Part A (2pt): Delete mock data, wire tenant switcher, add empty state, add basic loading/error guards
- Part B (3pt): Wire all KPI/domain score/table widgets to real BFF response fields

## Implementation Steps

1. Read `dashboard/page.jsx` in full to map every use of `MOCK_TENANTS`, `DS()`, `DC()`
2. Read `shared/api_gateway/bff/` to find and read the dashboard handler — record all response field names
3. Read `frontend/src/lib/tenant-context.js` — note exact export names for `tenants`, `activeTenant`, `setActiveTenant`
4. Delete lines containing `MOCK_TENANTS`, the `DS` function, and the `DC` function
5. Replace the tenant switcher's data source with `TenantContext.tenants`
6. Add empty state render when `tenants.length === 0`
7. Map each widget's data binding to the corresponding BFF response field:
   - Domain score cards → `data.domainScores`
   - IAM table → `data.iamSummary`
   - SG table → `data.sgSummary`
   - Risk table → `data.riskSummary`
   - KPI numbers → `data.openFindings`, `data.criticalFindings`, etc.
   (Exact field names from step 2)
8. Verify `npm run build` passes
9. Run the CI grep check

## Acceptance Criteria

**Given** `MOCK_TENANTS` is searched in the file
**When** `grep -n MOCK_TENANTS frontend/src/app/dashboard/page.jsx` runs
**Then** 0 matches are returned

**Given** a user with two real tenants logs in
**When** they open the dashboard
**Then** the tenant switcher lists those two tenants by name (from `TenantContext.tenants`)

**Given** the user selects a different tenant in the switcher
**When** `setActiveTenant` fires
**Then** `useViewFetch` re-fetches and all dashboard widgets update with data for the new tenant

**Given** a user with zero tenants (no cloud accounts onboarded) logs in
**When** they open the dashboard
**Then** the empty state renders with a link to `/onboarding`

**Given** the BFF returns `openFindings: 142`
**When** the dashboard KPI card renders
**Then** it displays "142" (not a hardcoded mock value)

## Test / Validation
```bash
# CI check — no mock data remains:
grep -n "MOCK_TENANTS\|function DS\|function DC" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/dashboard/page.jsx
# Expected: 0 matches

# Build check:
cd /Users/apple/Desktop/threat-engine/frontend && npm run build 2>&1 | tail -10
# Expected: compiled successfully

# Runtime check:
# 1. Port-forward gateway: kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines
# 2. Open dashboard, open DevTools Network
# 3. Find the /api/v1/views/dashboard request
# 4. Compare "openFindings" value in response to dashboard KPI card displayed number
# Expected: they match
```

## Definition of Done
- [ ] `MOCK_TENANTS` array removed from `dashboard/page.jsx`
- [ ] `DS()` and `DC()` helper functions removed
- [ ] Zero references to the deleted symbols in the file
- [ ] Tenant switcher reads from `TenantContext.tenants`
- [ ] `setActiveTenant` called on tenant selection
- [ ] Empty state renders when `tenants.length === 0` with link to `/onboarding`
- [ ] All KPI cards, domain score cards, IAM table, SG table, risk table bound to real BFF fields
- [ ] `grep -n MOCK_TENANTS dashboard/page.jsx` → 0 matches
- [ ] `npm run build` passes

## Points
5 (split into 2pt Part A + 3pt Part B if needed)

## Dependencies
UI-01 must be merged first (`useViewFetch` hook must exist, as this page uses it to pull real data).