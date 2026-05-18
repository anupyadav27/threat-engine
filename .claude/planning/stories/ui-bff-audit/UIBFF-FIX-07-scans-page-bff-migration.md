# Story UIBFF-FIX-07: Scans Page — Migrate from Direct Engine Calls to BFF

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-FIX — Direct Engine Call Elimination
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (3 direct engine calls on every page load — no BFF normalization or tenant enforcement)
- **Depends on**: None
- **Blocks**: None

## User Story

As a security engineer, I want the Scans page to fetch scan history, schedules, and cloud accounts through the BFF, so all data is consistently normalized and tenant-scoped.

## Context

Audit finding: `scans/page.jsx` makes 3 direct `getFromEngine()` calls ignoring the existing BFF view:
- Line 255: `getFromEngine('onboarding', '/api/v1/scan-runs?...')`
- Line 256: `fetchView('onboarding/cloud_accounts', {...})` — BFF but different view
- Line 257: `getFromEngine('onboarding', '/api/v1/schedules?...')`

The BFF handler `scans.py` already constructs normalized fields (duration, status mapping, severity distribution at lines 295–240) but is never called. Page receives raw engine data and does its own ad-hoc normalization.

## What to Build

### 1. Ensure `scans.py` BFF returns all fields the page reads

From audit: page reads `scan.overall_status`, `scan.engines_requested`, `scan.engines_completed`, `scan.engine_statuses`, `scan.provider`, `scan.account_id`, `scan.account_name`, `scan.started_at`, `scan.completed_at`, `scan.trigger_type`.

Verify `_normalise_scan_run()` in `scans.py` (lines ~295–366) maps all of these. Add any missing:
```python
def _normalise_scan_run(raw: dict, accounts: dict) -> dict:
    account_id = raw.get("account_id", "")
    return {
        "scan_run_id":        raw.get("scan_run_id"),
        "overall_status":     raw.get("overall_status") or raw.get("status"),
        "engines_requested":  raw.get("engines_requested", []),
        "engines_completed":  raw.get("engines_completed", []),
        "engine_statuses":    raw.get("engine_statuses") or {},
        "provider":           raw.get("provider", ""),
        "account_id":         account_id,
        "account_name":       accounts.get(account_id, {}).get("account_name", account_id),
        "started_at":         raw.get("started_at"),
        "completed_at":       raw.get("completed_at"),
        "trigger_type":       raw.get("trigger_type", "manual"),
        "duration_s":         _calc_duration(raw),
    }
```

Also ensure `view_scans()` returns schedules:
```python
return {
    "scans":     [_normalise_scan_run(r, accounts_map) for r in scan_runs],
    "schedules": [_normalise_schedule(s, accounts_map) for s in schedules],
    "accounts":  list(accounts_map.values()),
}
```

### 2. Update `scans/page.jsx` to use `useViewFetch('scans')`

```javascript
// BEFORE (lines 255-257):
const [scanRuns, accountsData, schedulesData] = await Promise.all([
  getFromEngine('onboarding', '/api/v1/scan-runs?...',  ...),
  fetchView('onboarding/cloud_accounts', {...}),
  getFromEngine('onboarding', '/api/v1/schedules?...',  ...),
]);

// AFTER:
const { data, loading, error, refetch } = useViewFetch('scans',
    { account_id: selectedAccount, provider: selectedProvider }
);
const scanRuns  = data.scans     || [];
const schedules = data.schedules || [];
const accounts  = data.accounts  || [];
```

Adjust downstream state updates that currently spread `scanRuns` / `schedulesData` results.

### 3. Keep `RunNowModal` as direct engine call (mutation)

`postToEngine('onboarding', '/api/v1/schedules/{id}/run-now', {})` is a mutation — this can stay as direct engine call per constitution (mutations bypass BFF).

## Acceptance Criteria

### AC-01 — Scans page loads via BFF
`GET /api/v1/views/scans` returns `scans[]`, `schedules[]`, `accounts[]`. Page renders scan history table.

### AC-02 — `account_name` populated
Each scan row shows the account name (not raw account_id). BFF enriches via accounts map.

### AC-03 — No direct scan-runs or schedules calls
`grep -n "getFromEngine.*scan-runs\|getFromEngine.*schedules" frontend/src/app/scans/page.jsx` returns 0 hits.

### AC-04 — Tenant isolation
BFF scopes scan-runs and schedules queries by `auth.tenant_id`.

### AC-05 — Pagination preserved
Scans table still supports pagination — BFF passes `limit`/`offset` through to engine.

## Cleanup Steps (After Testing)

1. `grep -n "getFromEngine.*scan-runs\|getFromEngine.*schedules" frontend/src/app/scans/page.jsx` — confirm 0 hits
2. Verify `RunNowModal` still calls engine directly (acceptable mutation pattern)
3. Remove any unused imports (`getFromEngine` if no longer used in this file)
4. Rebuild gateway image, verify rollout
5. Post-deploy: load /scans page — scan table populates with real data and correct account names

## Definition of Done

- [ ] `scans.py` BFF `view_scans()` returns `scans`, `schedules`, `accounts` with normalized fields
- [ ] `scans/page.jsx` uses `useViewFetch('scans')` — 0 direct scan-run/schedule engine calls
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-scans1`
