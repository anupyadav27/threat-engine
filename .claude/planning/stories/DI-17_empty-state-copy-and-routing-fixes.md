# DI-17: UI — Fix Wrong Queries, Missing Routes, and Empty State Copy

## Track
Track 4 — Empty State Audit

## Priority
P1 — depends on DI-16 (audit results)

## Story
As a user, I need "no data" states to be honest — either showing the correct "run a scan first" message for legitimate empties, or actually fetching and displaying data for states that should have data but don't due to wrong queries or missing routes.

## Depends On

DI-16 classification table. This story implements the Class C (wrong query), Class D (missing route), and Class A (correct empty state copy) fixes identified there.

## Pre-Known Fixes (Class C — Wrong Query)

### Fix 1: Policies page

File: `/Users/apple/Desktop/threat-engine/frontend/src/app/policies/page.jsx` line 49

```js
// Current (uses build-time TENANT_ID constant):
const res = await fetchView('policies', { tenant_id: TENANT_ID });

// Fix (DI-07 will clean tenant_id; ensure scan_run_id is passed):
const res = await fetchView('policies', { scan_run_id: 'latest' });
```

### Fix 2: Threats/toxic-combinations page

File: `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/toxic-combinations/page.jsx`

Verify it uses `useViewFetch('threats/toxic-combinations')` or `fetchView('threats/toxic-combinations')`. If the view name doesn't match the BFF route exactly, the request returns 404 which may not surface as an error.

Check the registered view names in `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/__init__.py`:
```python
# Verify these routes are registered:
from .threat_toxic_combos import router as toxic_combos_router
from .threat_command_room import router as command_room_router
```

### Fix 3: Scan Status page empty state

File: look in `/Users/apple/Desktop/threat-engine/frontend/src/app/scan*/` or `/status/`

The `scan_status.py` BFF view takes `tenant_id: str = Query(..., description="Tenant UUID")` — this uses the word "UUID" in the description, suggesting it expected a Django UUID, not an engine slug. Verify the conversion in DI-05/DI-06 fixes this.

## Pre-Known Fixes (Class A — Empty State Copy)

The following components show an empty state but use generic "No data" text. Replace with honest context-aware copy:

### Attack Paths empty state
Current: "No attack paths found"
Correct: "No multi-step attack paths detected in this scan. Attack paths appear when a resource is reachable from the internet AND has a critical misconfiguration."

### MITRE ATT&CK empty state (pre-DI-15 fix)
Current: blank grid
Correct (while DI-15 backfill is pending): "MITRE technique data is being loaded. If this persists after a scan refresh, contact support."

### Compliance empty state
Current: blank frameworks list
Correct: "No compliance frameworks are mapped for this account. Ensure check rules have been seeded and a scan has completed."

## Pre-Known Fixes (Class D — Missing Route)

### Check BFF router registration

File: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/__init__.py`

Verify all 40 view files are actually imported and their routers registered. A view file can exist in the bff/ directory but not be included in the main router, making all its endpoints 404.

```python
# Check this file includes all expected views:
# grep "from\." /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/__init__.py
```

If any view is missing from the import list, add it.

## Implementation of Empty State Fixes

For each React component with a Class A empty state, find the empty state render and replace:

```jsx
// Before (generic):
{data.threats.length === 0 && <div>No data</div>}

// After (honest):
{data.threats.length === 0 && (
  <div className="empty-state">
    <p>No threats detected in this scan.</p>
    <p className="hint">
      {data.scanMeta?.scanRunId
        ? "This scan completed but found no threats matching the configured rules."
        : "Run a scan to see threat detection results here."}
    </p>
  </div>
)}
```

## Acceptance Criteria

- [ ] DI-16 audit table reviewed before starting
- [ ] All Class C items (wrong query) fixed
- [ ] All Class D items (missing route) fixed — BFF routes verified in __init__.py
- [ ] Class A items have honest, context-aware empty state copy (not generic "No data")
- [ ] Empty state copy differentiates: "no scan run" vs "scan ran but found nothing"
- [ ] Policies page loads policy data correctly after fix
- [ ] All BFF view routes in __init__.py verified as registered

## Definition of Done
- Class C, D fixes deployed
- Empty state copy updated for at least 5 major pages
- Manual walkthrough confirms no more generic "No data" text on pages that have data
