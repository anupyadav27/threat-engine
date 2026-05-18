# Story UIBFF-S01-02: Remove Dashboard Embedded Mock Fallbacks

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-S01 — Fix Empty Sparklines
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 5
- **Priority**: P1 (CSPM Constitution violation — every chart has hardcoded mock data)
- **Depends on**: UIBFF-S01-01 (scan trend helper must exist before wiring dashboard)
- **Blocks**: UIBFF-ARCH-07 (dashboard BFF migration)

## User Story

As a security engineer, I want the dashboard to show real security data — not sine-wave mocks — so that charts and KPIs accurately reflect my cloud posture rather than hardcoded placeholders.

## Context

`frontend/src/app/dashboard/page.jsx` has **10+ hardcoded mock fallbacks** that activate whenever engines return <3 real items. This violates the CSPM Constitution rule: *"Never add fallback/mock data in BFF or UI"*.

Audit-confirmed mock locations (all in `dashboard/page.jsx`):

| Line | Variable | Activates When |
|------|----------|----------------|
| 194–202 | `mockSvcEntries` | `real services < 3` |
| 205–214 | `mockRules` | `no real rules` |
| 317–328 | `mockMitre` | `no MITRE data from engine` |
| 331–344 | `mockTrend` | `no threat trend (30-day sine wave)` |
| 777–786 | `mockFrameworks` | `real frameworks < 2` |
| 1097–1109 | `mockControls` | `failing controls empty` |
| 1644–1657 | `mockAssets` | `real assets < 3` |
| 1877–1890 | `mockStores` | `data stores empty` |
| 2082–2095 | `mockFindings` | `network findings empty` |
| 2252–2263 | `mockScenarios` | `risk scenarios empty` |
| 2470–2483 | `mockDetections` | `CDR detections empty` |
| 3239–3473 | `|| MOCK_DASHBOARD.xxx` | `KPI fallbacks throughout` |

The BFF at `shared/api_gateway/bff/dashboard.py` already calls 7 engines in parallel. When engines return no data, the correct behavior is to show empty states, not fake data.

## What to Build

### 1. Remove all mock fallback variables from `dashboard/page.jsx`

Delete or neutralize each mock variable and its usage. Replace with empty-state patterns:

**Pattern for tables/lists:**
```javascript
// BEFORE:
const services = realServices.length >= 3 ? realServices : mockSvcEntries;

// AFTER:
const services = realServices;
// Table renders with EmptyState component when services.length === 0
```

**Pattern for charts:**
```javascript
// BEFORE:
const trendData = realTrend.length > 0 ? realTrend : mockTrend; // sine wave

// AFTER:
const trendData = data.trendData || [];
// Chart renders "No scan history yet" when trendData.length === 0
```

**Pattern for KPIs:**
```javascript
// BEFORE:
const criticalCount = data.kpi?.critical ?? MOCK_DASHBOARD.kpi.critical;

// AFTER:
const criticalCount = data.kpi?.critical ?? 0;
```

### 2. Wire `trendData` from BFF scan history (depends on UIBFF-S01-01)

The dashboard's threat trend chart currently falls back to a 30-day sine-wave. Once `UIBFF-S01-01` ships, `dashboard.py` will call `fetch_scan_trend()`. Wire the result:

In `dashboard.py` (already has TODO for this):
```python
from ._scan_history import fetch_scan_trend   # added by S01-01

# In view_dashboard():
scan_trend = await fetch_scan_trend(tenant_id, auth_headers, days=30)

return {
    ...existing fields...,
    "trendData": scan_trend,   # replaces {} / None
}
```

### 3. Remove `MOCK_DASHBOARD` import if no longer referenced

`dashboard/page.jsx` imports `{ MOCK_DASHBOARD, MOCK_THREATS, MOCK_FRAMEWORKS, MOCK_POSTURE }` from `@/lib/mock-data`. After removing all fallbacks, remove the import if nothing references these.

### 4. Add empty-state UI for every chart/table

For each section that previously fell back to mocks, add an inline empty state:
- Charts: render `<p className="text-muted-foreground text-sm">No data yet — run a scan to populate</p>` when array is empty
- KPI cards: show `0` or `—` instead of mock numbers
- Tables: existing `EmptyState` component if already used elsewhere on the page, otherwise inline empty row

## Acceptance Criteria

### AC-01 — No mock imports on first scan
After a fresh tenant's **first** scan completes, the dashboard renders real KPIs. No mock data appears — zero-value KPIs show `0`, empty charts show the empty-state message.

### AC-02 — `mockTrend` sine wave eliminated
`trendData` in the dashboard response is never a generated sine wave. If scan history is empty, the chart renders "No trend data yet" instead of fake peaks.

### AC-03 — Table empty states work
When services/assets/network-findings/risk-scenarios are empty arrays, the corresponding tables render an empty state message, not mock rows.

### AC-04 — KPI fallbacks show 0
All `|| MOCK_DASHBOARD.xxx` KPI fallbacks replaced with `?? 0`. No MOCK_DASHBOARD import in the bundle.

### AC-05 — No runtime errors on empty data
Loading a fresh tenant with zero scans does not throw JavaScript errors. All optional-chaining already in place.

### AC-06 — Multi-tenant isolation preserved
`trendData` from dashboard BFF is always scoped by `tenant_id` from `AuthContext`. No cross-tenant leak.

## Technical Notes

- Do NOT remove the existing `MOCK_*` exports from `lib/mock-data.js` — other pages may import them
- Only remove the *usage* in `dashboard/page.jsx`
- The `|| MOCK_DASHBOARD.xxx` fallbacks at lines 3239–3473 are inside the KPI destructuring block — remove carefully to avoid breaking surrounding logic
- `mockTrend` at line 331 is a 30-entry sine-wave array — confirm the replacement is `data.trendData || []` (not `data.trendData?.trend || []`)
- After this story, run `grep -r "MOCK_DASHBOARD\|mockTrend\|mockSvcEntries\|mockFrameworks" frontend/src/app/dashboard/` to confirm zero matches

## Definition of Done

- [ ] All 10+ mock fallback variables removed from `dashboard/page.jsx`
- [ ] `MOCK_DASHBOARD` import removed (or confirmed still needed by another page section)
- [ ] `trendData` wired to `fetch_scan_trend()` result from BFF
- [ ] Empty states added for every chart/table that previously used mocks
- [ ] AC-01 through AC-06 verified
- [ ] `grep` for MOCK patterns returns 0 hits in dashboard page
