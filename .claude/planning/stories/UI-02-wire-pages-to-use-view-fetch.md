# UI-02: Wire all pages to `useViewFetch`

## Status
Ready for dev

## Context
Every page in the frontend calls `fetchView(viewName, params)` directly, either inside a `useEffect` or inline. Because `fetchView` does not read from the auth context, the `tenant_id` it sends is the static build-time env var. UI-01 created `useViewFetch` which injects the correct runtime `tenant_id`. This story mechanically replaces every direct `fetchView` call across all 15 data pages with `useViewFetch`.

## Scope
**In scope:**
- Replace `fetchView` with `useViewFetch` in all 15 pages listed below
- Remove any local `useState`/`useEffect` blocks that replicated loading/error state — the hook handles that
- Keep existing JSX rendering logic exactly as-is; only the data-fetching layer changes

**Out of scope:**
- Changing BFF response shapes
- Changing how the data is rendered (that is other stories)
- The dashboard mock data removal (that is UI-07)
- The profile page (that is UI-09)
- The onboarding/users page (that is UI-10)

## Technical Notes

### Pages to update (all under `frontend/src/app/`)
| Page file | Current view name | Notes |
|-----------|-------------------|-------|
| `dashboard/page.jsx` | `'dashboard'` | Keep MOCK_TENANTS for now (UI-07 removes them) — only replace the fetchView call |
| `threats/page.jsx` | `'threats'` | |
| `iam/page.jsx` | `'iam'` | |
| `ciem/page.jsx` | `'ciem'` | |
| `network-security/page.jsx` | `'network-security'` | |
| `risk/page.jsx` | `'risk'` | |
| `inventory/page.jsx` | `'inventory'` | |
| `ai-security/page.jsx` | `'ai-security'` | Also pass `{ provider }` from `useGlobalFilter()` — see UI-05 for full fix |
| `cnapp/page.jsx` | `'cnapp'` | |
| `cwpp/page.jsx` | `'cwpp'` | |
| `datasec/page.jsx` | `'datasec'` | |
| `encryption/page.jsx` | `'encryption'` | |
| `misconfig/page.jsx` | `'misconfig'` | |
| `container-security/page.jsx` | `'container-security'` | |
| `database-security/page.jsx` | `'database-security'` | |

### Import change per page
```js
// BEFORE (remove this):
import { fetchView } from '@/lib/api';
// ... inside component:
useEffect(() => {
  fetchView('dashboard', { tenant_id: TENANT_ID }).then(setData);
}, []);

// AFTER (replace with):
import { useViewFetch } from '@/lib/use-view-fetch';
// ... inside component:
const { data, loading, error } = useViewFetch('dashboard');
// Remove the useEffect and local useState for data/loading/error
```

### Handling loading and error states
If the page currently does not show a loading state or error state, add minimal stubs:
```jsx
if (loading) return <div className="p-8 text-center">Loading...</div>;
if (error) return <div className="p-8 text-center text-red-500">Failed to load data.</div>;
```
Use whatever loading/error component pattern already exists in the codebase — grep for existing `Spinner` or `LoadingState` components first.

### Pages that pass extra params
Some pages may pass additional query params to `fetchView` (e.g. `{ limit: 50 }` or `{ account_id: X }`). Preserve those as the second argument to `useViewFetch`:
```js
const { data } = useViewFetch('threats', { limit: 50 });
```

### Do not change
- Any JSX that consumes `data.someField` — leave the rendering logic alone
- The `GlobalFilterContext` wiring for non-ai-security pages (full global filter wiring is a separate story)

## Implementation Steps

1. Confirm `frontend/src/lib/use-view-fetch.js` exists (UI-01 must be merged)
2. For each of the 15 pages:
   a. Read the file to understand its current fetch pattern
   b. Remove the `import { fetchView }` line (or keep if fetchView is used for other calls in the same file)
   c. Add `import { useViewFetch } from '@/lib/use-view-fetch';`
   d. Remove the `useEffect` + `setState` blocks that perform the main view fetch
   e. Replace with `const { data, loading, error } = useViewFetch('view-name');`
   f. Add loading/error guard renders if not present
3. Run the Next.js dev server and navigate to each page — confirm no React hook errors in console
4. Check DevTools Network tab on 3 pages to verify `tenant_id` is present in query params

## Acceptance Criteria

**Given** a user is authenticated with `activeTenant.tenant_id = "t-abc"`
**When** they navigate to any of the 15 pages
**Then** the outgoing `/api/v1/views/*` request contains `tenant_id=t-abc`

**Given** the user changes active tenant to `"t-xyz"`
**When** a page re-renders
**Then** the next BFF request contains `tenant_id=t-xyz`

**Given** a BFF call fails (simulated via Network throttle → Offline)
**When** the page renders
**Then** an error message is displayed (not a blank screen or unhandled exception)

**Given** a BFF call is in-flight
**When** the component renders
**Then** a loading indicator is shown (not a blank screen)

## Test / Validation
```bash
# Verify no raw fetchView calls remain in the 15 pages:
grep -rn "fetchView" \
  /Users/apple/Desktop/threat-engine/frontend/src/app/dashboard/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/threats/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/iam/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/ciem/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/network-security/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/risk/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/inventory/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/ai-security/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/cnapp/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/cwpp/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/datasec/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/encryption/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/misconfig/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/container-security/page.jsx \
  /Users/apple/Desktop/threat-engine/frontend/src/app/database-security/page.jsx
# Expected: 0 matches (or only matches that are NOT the main view fetch)

# Verify useViewFetch import in all 15:
grep -rn "useViewFetch" /Users/apple/Desktop/threat-engine/frontend/src/app/ | grep "page.jsx"
# Expected: 15 matches

# Build check:
cd /Users/apple/Desktop/threat-engine/frontend && npm run build 2>&1 | tail -20
# Expected: no compilation errors
```

## Definition of Done
- [ ] All 15 pages import and use `useViewFetch` instead of direct `fetchView`
- [ ] No raw `fetchView` calls remain in the 15 target page files for the primary view fetch
- [ ] Each page has a loading state and an error state
- [ ] `npm run build` succeeds with no errors
- [ ] DevTools Network tab on dashboard, threats, and iam pages confirms `tenant_id` param is present
- [ ] No React hook rule violations in browser console

## Points
3

## Dependencies
UI-01 must be merged first (`frontend/src/lib/use-view-fetch.js` must exist).