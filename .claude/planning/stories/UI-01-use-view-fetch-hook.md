# UI-01: Create `useViewFetch` hook

## Status
Ready for dev

## Context
All pages currently call `fetchView(viewName, params)` directly from `frontend/src/lib/api.js`. The `tenant_id` injected into those calls comes from a static build-time environment variable (`TENANT_ID` in `constants.js`), not from the authenticated user's session. This means a user who belongs to multiple tenants always sees data for the hardcoded tenant regardless of which tenant they have selected. This story creates a single hook that injects the correct runtime `tenant_id` — and global filter values — before every BFF call.

## Scope
**In scope:**
- New file `frontend/src/lib/use-view-fetch.js` (the hook itself)
- The hook reads `activeTenant.tenant_id` from `TenantContext`
- The hook reads `provider`, `account`, `region` from `GlobalFilterContext`
- Falls back to the `TENANT_ID` env constant when no active tenant is set
- Exposes `{ data, loading, error, refetch }` — same shape callers expect today

**Out of scope:**
- Wiring the hook into any page (that is UI-02)
- Changing any BFF endpoint behaviour
- Modifying `fetchView()` itself (leave it as the raw HTTP function)

## Technical Notes

### Files to read before implementing
- `frontend/src/lib/api.js` — `fetchView(viewName, params)` signature. It appends params as query string to `/api/v1/views/{viewName}` and returns parsed JSON.
- `frontend/src/lib/constants.js` — `TENANT_ID` fallback value (build-time env)
- `frontend/src/lib/tenant-context.js` — `TenantContext`; `activeTenant` shape: `{ tenant_id, tenant_name, role, status }`
- `frontend/src/lib/auth-context.js` — `AuthContext`; check if global filter lives here or in a separate context
- Look for `GlobalFilterContext` — it may be in `frontend/src/lib/global-filter-context.js` or similar; grep the codebase to find it

### Hook contract
```js
// Usage signature (what pages will call in UI-02):
const { data, loading, error, refetch } = useViewFetch('dashboard', { extraParam: 'value' });

// The hook must internally do:
// 1. Get activeTenant from TenantContext
// 2. Get { provider, account, region } from GlobalFilterContext (if it exists)
// 3. Build params = { tenant_id: activeTenant?.tenant_id ?? TENANT_ID, provider, account, region, ...callerExtraParams }
// 4. Call fetchView(viewName, params) inside a useEffect
// 5. Re-fetch when activeTenant.tenant_id changes (dependency array)
// 6. Re-fetch when any global filter value changes
```

### Tenant ID resolution order
1. `TenantContext.activeTenant.tenant_id` (runtime, from auth session)
2. `sessionStorage['auth_session']` parsed → `.selectedTenant` (fallback if context not yet hydrated)
3. `TENANT_ID` from `constants.js` (last resort / SSR fallback)

### Error handling
- If `fetchView` throws, set `error` state and leave `data` as null
- Do not swallow errors silently — surface them so pages can show error UI

## Implementation Steps

1. Locate `GlobalFilterContext` by running: `grep -r "GlobalFilterContext\|useGlobalFilter" frontend/src --include="*.js" --include="*.jsx" -l`
2. Read `frontend/src/lib/api.js` to confirm `fetchView` signature
3. Read `frontend/src/lib/tenant-context.js` to confirm `activeTenant` shape
4. Create `frontend/src/lib/use-view-fetch.js`:
   - Import `useState`, `useEffect`, `useCallback` from React
   - Import `useContext` and both contexts
   - Import `fetchView` from `./api`
   - Import `TENANT_ID` from `./constants`
   - Implement hook as described above
5. Export as both default and named export: `export default useViewFetch; export { useViewFetch };`
6. Write a simple Jest unit test in `frontend/src/__tests__/use-view-fetch.test.js`:
   - Mock `fetchView` and both contexts
   - Assert that when `activeTenant.tenant_id = 'tenant-abc'`, `fetchView` is called with `tenant_id: 'tenant-abc'`
   - Assert that when `activeTenant` is null, `fetchView` is called with `tenant_id: TENANT_ID`
   - Assert that changing `activeTenant` triggers a new `fetchView` call

## Acceptance Criteria

**Given** a user is logged in and `TenantContext.activeTenant.tenant_id` is `"t-123"`
**When** any page calls `useViewFetch('dashboard')`
**Then** the outgoing HTTP request includes `?tenant_id=t-123` in the query string

**Given** the user switches active tenant to `"t-456"` via the tenant switcher
**When** the hook re-renders (dependency change)
**Then** a new fetch fires with `?tenant_id=t-456` and the page data updates

**Given** no active tenant is set (e.g. first load before context hydrates)
**When** `useViewFetch` executes
**Then** it falls back to the `TENANT_ID` env constant and does not throw

**Given** `fetchView` returns a network error
**When** the hook catches it
**Then** `error` is non-null and `loading` is false, `data` remains null

## Test / Validation
```bash
# Unit tests
cd /Users/apple/Desktop/threat-engine/frontend
npm test -- --testPathPattern=use-view-fetch --watchAll=false

# Runtime check (after UI-02 wires pages): open DevTools → Network tab
# Filter by /api/v1/views/ — every request must include tenant_id param
# Switch tenant in UI → verify subsequent requests show new tenant_id
```

## Definition of Done
- [ ] `frontend/src/lib/use-view-fetch.js` exists and exports `useViewFetch`
- [ ] Hook reads `tenant_id` from `TenantContext` at runtime, not from env var
- [ ] Hook reads `provider/account/region` from `GlobalFilterContext` and merges into params
- [ ] Falls back to `TENANT_ID` constant when no active tenant
- [ ] Exposes `{ data, loading, error, refetch }` interface
- [ ] Re-fetches when `activeTenant.tenant_id` changes (useEffect dependency)
- [ ] Unit test file exists with at least 3 passing test cases
- [ ] No console errors in browser when hook is used

## Points
2

## Dependencies
None — this is a Wave 1 story, start immediately.
