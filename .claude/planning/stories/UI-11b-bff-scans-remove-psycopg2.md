# UI-11b: Remove psycopg2 from BFF scans handler

## Status
Ready for dev

## Context
`shared/api_gateway/bff/scans.py` lines 25–48 contain a `_get_scan_history()` function that directly connects to PostgreSQL via `psycopg2`. BFF handlers must never query databases directly — they call engine APIs. BE-04 (UI-11a) adds `GET /api/v1/scan-runs` to the onboarding engine, which serves this data through a proper API. This story replaces the psycopg2 block with a call to that engine endpoint.

## Scope
**In scope:**
- Remove `_get_scan_history()` psycopg2 function from `bff/scans.py`
- Remove the `psycopg2` import from `bff/scans.py` (if it only exists for this function)
- Replace with `await _fetch_engine(client, "onboarding", "/api/v1/scan-runs", params)`
- Add `"onboarding"` to `ENGINE_URLS` in `_shared.py` if not already present

**Out of scope:**
- Changing the onboarding engine (that is UI-11a/BE-04)
- Changing the scans BFF response envelope shape (keep backward compatibility)
- Adding new fields to the scan history response

## Technical Notes

### Read these files first
```bash
# The full scans BFF handler:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/scans.py

# The shared module for _fetch_engine and ENGINE_URLS:
cat /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_shared.py

# Confirm the onboarding engine service name in K8s:
grep -r "engine-onboarding\|onboarding" \
  /Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/ --include="*.yaml" | grep "name:" | head -5
```

### Current psycopg2 block (lines 25–48 approximately)
The block will look something like:
```python
import psycopg2

def _get_scan_history(tenant_id: str, limit: int = 10):
    conn = psycopg2.connect(
        host=os.getenv("SCAN_DB_HOST"),
        ...
    )
    cur = conn.cursor()
    cur.execute("SELECT ... FROM scan_runs WHERE tenant_id = %s LIMIT %s", (tenant_id, limit))
    rows = cur.fetchall()
    ...
    conn.close()
    return rows
```

### Replacement
```python
# In the async view function that currently calls _get_scan_history():
# BEFORE:
scan_history = _get_scan_history(tenant_id, limit=10)

# AFTER:
scan_params = {"tenant_id": tenant_id, "limit": 10}
scan_history_resp = await _fetch_engine(
    client, "onboarding", "/api/v1/scan-runs", scan_params
)
scan_history = scan_history_resp.get("scan_runs", [])
```

The `_fetch_engine` function signature — confirm by reading `_shared.py`:
```python
async def _fetch_engine(client: httpx.AsyncClient, engine_name: str, path: str, params: dict) -> dict:
    ...
```

### ENGINE_URLS in `_shared.py`
Add if not present:
```python
"onboarding": os.getenv("ONBOARDING_ENGINE_URL", "http://engine-onboarding"),
```
Check the existing K8s service name for the onboarding engine. Look at:
```bash
kubectl get svc -n threat-engine-engines | grep onboarding
```

### Remove psycopg2 import
After removing `_get_scan_history`, check if `psycopg2` is used anywhere else in `scans.py`. If not, remove the import. If psycopg2 is used in other BFF files too, add a CI check:
```bash
# CI check to add:
! grep -rn "psycopg2" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/
```
This check should pass after this story is done (zero psycopg2 occurrences in the bff/ directory).

### Graceful fallback
If the onboarding engine is unreachable, `_fetch_engine` should return an empty dict (confirm by reading `_shared.py`). In that case `scan_history_resp.get("scan_runs", [])` returns `[]`, which is the correct graceful fallback.

### Response envelope compatibility
The scans BFF view currently puts `scan_history` into the response envelope. After the change, the field name and structure remain the same — only how the data is fetched changes. Verify the envelope shape is unchanged by comparing the before and after response structures.

## Implementation Steps

1. Read `bff/scans.py` in full — locate `_get_scan_history` and every call to it
2. Read `bff/_shared.py` — note `_fetch_engine` exact signature and `ENGINE_URLS` dict
3. Check if `"onboarding"` is already in `ENGINE_URLS`
4. If not present, add it with the correct K8s service name
5. Remove `_get_scan_history` function from `scans.py`
6. Replace each call to `_get_scan_history(...)` with `await _fetch_engine(...)` as shown
7. Remove `psycopg2` import from `scans.py` (if no longer needed)
8. Run the CI grep check locally to confirm zero psycopg2 occurrences in bff/
9. Test the scans BFF view end-to-end

## Acceptance Criteria

**Given** `grep -n psycopg2 shared/api_gateway/bff/scans.py`
**When** the command runs
**Then** 0 matches (psycopg2 removed from this file)

**Given** `grep -rn psycopg2 shared/api_gateway/bff/`
**When** the command runs
**Then** 0 matches (psycopg2 removed from the entire bff/ directory)

**Given** the onboarding engine is running and has scan runs for `tenant_id=T`
**When** `GET /api/v1/views/scans?tenant_id=T` is called on the BFF
**Then** HTTP 200 is returned with scan history data matching what the onboarding engine serves

**Given** the onboarding engine is temporarily unreachable
**When** the BFF scans view is called
**Then** HTTP 200 is returned with an empty `scanHistory` array (graceful degradation, not 500)

## Test / Validation
```bash
# CI check — no psycopg2 in BFF:
! grep -rn "psycopg2" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/
# Expected: exits 0 (no matches)

# End-to-end test:
kubectl port-forward svc/api-gateway 8000:80 -n threat-engine-engines &
curl -s "http://localhost:8000/api/v1/views/scans?tenant_id=<t>" | python3 -m json.tool
# Expected: JSON with scanHistory array populated from onboarding engine

# Verify ENGINE_URLS has onboarding entry:
grep -n "onboarding" /Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_shared.py
# Expected: "onboarding": ... line
```

## Definition of Done
- [ ] `_get_scan_history()` function removed from `bff/scans.py`
- [ ] `psycopg2` import removed from `bff/scans.py`
- [ ] `_fetch_engine(client, "onboarding", "/api/v1/scan-runs", params)` call replaces old function
- [ ] `"onboarding"` entry in `ENGINE_URLS` in `_shared.py`
- [ ] `grep -rn psycopg2 shared/api_gateway/bff/` → 0 matches
- [ ] BFF scans view returns HTTP 200 with scan history from onboarding engine
- [ ] Onboarding engine unreachable → graceful empty response (not 500)

## Points
1

## Dependencies
UI-11a (BE-04) must be merged AND deployed (engine running in K8s with the new endpoint) before this story can be verified end-to-end. The code change itself can be written in parallel with BE-04, but the final test requires BE-04 deployed.