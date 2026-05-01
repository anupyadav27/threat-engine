# UI-05: Fix AI-security CSP param

## Status
Ready for dev

## Context
`shared/api_gateway/bff/ai_security.py` has the `csp` query parameter hardcoded to default `"aws"` (line ~127: `csp: str = Query("aws")`). This means that even when a user sets the global cloud provider filter to Azure or GCP, the AI-security page always queries the AI-security engine for AWS resources only. The fix is two-part: make the BFF param optional (falling back to the global `provider` filter), and make the frontend page pass the global filter's `provider` value through.

## Scope
**In scope:**
- `shared/api_gateway/bff/ai_security.py`: change `csp` param type and add fallback logic
- `frontend/src/app/ai-security/page.jsx`: pass `provider` from global filter to `useViewFetch`

**Out of scope:**
- Changing any other BFF handlers
- Changing the AI-security engine itself
- Changing the global filter UI component

## Technical Notes

### BFF change — `shared/api_gateway/bff/ai_security.py`

Read the file first to find the exact handler function. Look for the `csp: str = Query("aws")` signature. The fix:

```python
from typing import Optional
from fastapi import Query

# BEFORE:
async def view_ai_security(
    tenant_id: str,
    csp: str = Query("aws"),
    ...
):

# AFTER:
async def view_ai_security(
    tenant_id: str,
    csp: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    ...
):
    effective_csp = csp or provider or "aws"
    # Use effective_csp wherever csp was used below
```

The `provider` param comes from the global filter — the frontend sends it as a query param (e.g. `?provider=gcp`). `csp` is kept for backward compatibility (existing callers that explicitly set `?csp=azure` still work). The priority order is: explicit `csp` → `provider` → default `"aws"`.

After computing `effective_csp`, replace every use of `csp` in the function body with `effective_csp`. Do a full read of the function to find all occurrences.

### Frontend change — `frontend/src/app/ai-security/page.jsx`

After UI-02 wires this page to `useViewFetch`, it will call:
```js
const { data } = useViewFetch('ai-security');
```

Change it to pass the provider from the global filter:
```js
const { provider } = useGlobalFilter();  // or whatever the context hook is named
const { data } = useViewFetch('ai-security', { provider });
```

Find the correct hook name by grepping:
```bash
grep -rn "useGlobalFilter\|GlobalFilterContext" /Users/apple/Desktop/threat-engine/frontend/src --include="*.js" --include="*.jsx" | head -10
```

### Import to add in BFF
```python
from typing import Optional
```
Check if `Optional` is already imported in `ai_security.py` before adding.

### Verify the AI-security engine accepts `csp` param
Read `engines/ai_security/` (or the service's main router) to confirm the engine's own endpoint accepts `csp` as a query param. The BFF passes it through to the engine — confirm the param name matches what the engine expects. If the engine uses a different param name (e.g. `cloud_provider`), add the appropriate mapping in the BFF.

## Implementation Steps

1. Read `shared/api_gateway/bff/ai_security.py` in full — note the function signature and every use of `csp`
2. Identify the engine URL and endpoint the BFF calls (likely something like `GET /api/v1/scan` or similar on the AI-security engine)
3. Check the AI-security engine's endpoint to confirm `csp` param name
4. Modify `ai_security.py`: change param type, add `provider` param, compute `effective_csp`
5. Replace all uses of `csp` in the function body with `effective_csp`
6. Read `frontend/src/app/ai-security/page.jsx` to understand current structure
7. Find the global filter hook name
8. Add `provider` from global filter to the `useViewFetch` call (second arg object)
9. Test: set global filter to GCP, open AI-security page, check Network tab

## Acceptance Criteria

**Given** the global filter is set to `provider=azure`
**When** the AI-security page loads
**Then** the BFF receives `?provider=azure` and the AI-security engine is called with `csp=azure`

**Given** the global filter is set to `provider=gcp`
**When** the AI-security page loads
**Then** the BFF log shows `effective_csp=gcp`

**Given** neither `csp` nor `provider` is passed to the BFF
**When** the view handler runs
**Then** it falls back to `effective_csp="aws"` (no change in behaviour for existing callers)

**Given** an explicit `?csp=azure` is passed alongside `?provider=gcp`
**When** the view handler runs
**Then** `effective_csp="azure"` (explicit `csp` wins)

## Test / Validation
```bash
# BFF param change — verify function signature:
grep -n "csp\|provider\|effective_csp" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/ai_security.py

# End-to-end (with port-forward to gateway):
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines &
curl "http://localhost:8000/api/v1/views/ai-security?tenant_id=<t>&provider=gcp"
# Check BFF container logs for effective_csp=gcp

# Frontend: DevTools Network tab
# With global filter = GCP, open /ai-security
# Expected: /api/v1/views/ai-security?tenant_id=...&provider=gcp
```

## Definition of Done
- [ ] `ai_security.py` `csp` param is `Optional[str] = Query(None)`
- [ ] `ai_security.py` has `provider: Optional[str] = Query(None)` param
- [ ] `effective_csp = csp or provider or "aws"` logic present
- [ ] All uses of `csp` in the function body replaced with `effective_csp`
- [ ] `ai-security/page.jsx` passes `{ provider }` from global filter to `useViewFetch`
- [ ] Network tab on AI-security page shows `provider=` param matching global filter selection
- [ ] BFF unit test or manual verification confirms `?provider=gcp` results in engine called with `csp=gcp`

## Points
1

## Dependencies
None — this is a Wave 1 story, start immediately. (UI-02 is recommended first so the page already uses `useViewFetch`, but this story can apply the frontend change directly to the existing `fetchView` call if UI-02 is not yet merged.)