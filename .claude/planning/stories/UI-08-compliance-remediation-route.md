# UI-08: Fix `compliance/remediation` dead route

## Status
Ready for dev

## Context
The compliance section sidebar contains a "Remediation Queue" navigation link pointing to `/compliance/remediation`. The page file `frontend/src/app/compliance/remediation/page.jsx` does not exist, so clicking the link produces a Next.js 404 error. The BFF already computes the data needed — `view_compliance` returns an `accountMatrix` field that contains per-account control results. This story creates the missing page and the corresponding BFF sub-route using data that is already available.

## Scope
**In scope:**
- Create `frontend/src/app/compliance/remediation/page.jsx`
- Add `GET /api/v1/views/compliance/remediation` route to `shared/api_gateway/bff/compliance.py`
- The BFF route filters `accountMatrix` (or equivalent field) to status=FAIL, sorts by severity
- Page renders a table: framework name, control ID, severity, affected account count

**Out of scope:**
- Changing the compliance engine
- Implementing remediation actions (create ticket, assign owner) — display only
- Changing the `view_compliance` main handler

## Technical Notes

### Read these files first
```bash
# Find the compliance BFF handler:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/compliance.py

# See what view_compliance returns — specifically what accountMatrix contains:
grep -n "accountMatrix\|account_matrix\|FAIL\|failing" \
  /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/compliance.py

# Find the existing compliance page to understand current structure:
ls /Users/apple/Desktop/threat-engine/frontend/src/app/compliance/

# Read the navigation component to confirm the link href:
grep -rn "remediation" /Users/apple/Desktop/threat-engine/frontend/src/app/ --include="*.jsx" --include="*.tsx"
```

### BFF route to add in `compliance.py`
Add a new route in the same router as `view_compliance`. The route re-uses the same data but filters it:

```python
@router.get("/views/compliance/remediation")
async def view_compliance_remediation(
    tenant_id: str,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),   # optional filter by severity
    limit: int = Query(100),
):
    # Fetch the full compliance view (or call the compliance engine directly for failing controls)
    # Filter to status=FAIL
    # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    # Return failingControls array

    return standard_envelope({
        "failingControls": [
            {
                "framework": "CIS AWS Foundations",
                "control_id": "1.4",
                "control_title": "...",
                "severity": "HIGH",
                "affected_accounts": ["account-123"],
                "affected_account_count": 1,
                "last_checked": "2026-04-29T10:00:00Z"
            },
            ...
        ],
        "totalFailing": N,
        "bySeverity": { "CRITICAL": N, "HIGH": N, "MEDIUM": N, "LOW": N }
    })
```

The exact field names in `accountMatrix` depend on what `view_compliance` returns — read the handler to map them correctly. Do not invent field names.

**Severity sort order for Python:**
```python
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
failing_controls.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "INFO"), 99))
```

### Frontend page structure
```jsx
// frontend/src/app/compliance/remediation/page.jsx
'use client';
import { useViewFetch } from '@/lib/use-view-fetch';

export default function ComplianceRemediationPage() {
  const { data, loading, error } = useViewFetch('compliance/remediation');

  if (loading) return <LoadingState />;
  if (error)   return <ErrorState />;

  const { failingControls = [], totalFailing = 0, bySeverity = {} } = data ?? {};

  return (
    <div>
      <h1>Remediation Queue ({totalFailing} failing controls)</h1>
      {/* Summary row: CRITICAL=N HIGH=N MEDIUM=N LOW=N */}
      {/* Table: Framework | Control ID | Title | Severity | Affected Accounts | Last Checked */}
      <table>
        <thead>...</thead>
        <tbody>
          {failingControls.map((ctrl) => (
            <tr key={ctrl.control_id + ctrl.framework}>
              <td>{ctrl.framework}</td>
              <td>{ctrl.control_id}</td>
              <td>{ctrl.control_title}</td>
              <td>{ctrl.severity}</td>
              <td>{ctrl.affected_account_count}</td>
              <td>{ctrl.last_checked}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
```

Match the styling conventions of other compliance pages (read `frontend/src/app/compliance/page.jsx` for class name patterns).

### Route registration
The new BFF route is added to the **same** `router` object in `compliance.py` — no additional registration needed in `__init__.py` as long as the compliance router is already mounted.

Confirm this by checking `__init__.py`:
```bash
grep -n "compliance" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/__init__.py
```

## Implementation Steps

1. Read `shared/api_gateway/bff/compliance.py` in full — understand `view_compliance` response structure and `accountMatrix`
2. Read `frontend/src/app/compliance/page.jsx` for styling patterns
3. Check router registration in `bff/__init__.py`
4. Add the `view_compliance_remediation` function to `compliance.py`
5. Create directory `frontend/src/app/compliance/remediation/` if it does not exist
6. Create `frontend/src/app/compliance/remediation/page.jsx`
7. Test BFF route with curl
8. Test frontend page navigates without 404

## Acceptance Criteria

**Given** a user clicks "Remediation Queue" in the compliance navigation
**When** the browser navigates to `/compliance/remediation`
**Then** the page renders without a 404 error

**Given** `GET /api/v1/views/compliance/remediation?tenant_id=T` is called
**When** the BFF processes the request
**Then** HTTP 200 is returned with a `failingControls` array (empty array if no failures, not an error)

**Given** there are failing controls in the DB
**When** the page renders
**Then** the table shows rows with: framework, control ID, severity, affected account count

**Given** there are no failing controls
**When** the page renders
**Then** an empty state message is shown ("No failing controls — great job!")

**Given** controls of different severities exist
**When** the table renders
**Then** CRITICAL rows appear before HIGH, HIGH before MEDIUM, MEDIUM before LOW

## Test / Validation
```bash
# BFF endpoint test:
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines &
curl -s "http://localhost:8000/api/v1/views/compliance/remediation?tenant_id=<t>" | python3 -m json.tool
# Expected: JSON with failingControls array and totalFailing integer

# Page existence check:
ls /Users/apple/Desktop/threat-engine/frontend/src/app/compliance/remediation/page.jsx
# Expected: file exists

# Build check:
cd /Users/apple/Desktop/threat-engine/frontend && npm run build 2>&1 | grep -i error
# Expected: no errors

# Nav link test: click "Remediation Queue" in compliance sidebar
# Expected: page loads, no 404
```

## Definition of Done
- [ ] `frontend/src/app/compliance/remediation/page.jsx` exists
- [ ] Page uses `useViewFetch('compliance/remediation')`
- [ ] Page renders a table with framework, control ID, severity, affected accounts columns
- [ ] Empty state when no failing controls
- [ ] `GET /api/v1/views/compliance/remediation` added to `bff/compliance.py`
- [ ] BFF returns `failingControls` array sorted by severity
- [ ] `curl` test returns HTTP 200 with correct shape
- [ ] No 404 when clicking the Remediation Queue nav link

## Points
2

## Dependencies
UI-01 must be merged first (`useViewFetch` must exist). This is a Wave 2 story.
