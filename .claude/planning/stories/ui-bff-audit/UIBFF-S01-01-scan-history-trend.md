# Story UIBFF-S01-01: Scan History / scanTrend BFF Endpoint

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-S01 — Fix Empty Sparklines
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P1 (affects sparklines on every page)
- **Depends on**: None
- **Blocks**: UIBFF-S01-02 (dashboard mock removal), all per-page scanTrend wiring

## User Story

As a security engineer, I want scan-over-scan trend sparklines on the inventory, misconfig, and dashboard pages to show real historical data, so I can see whether my posture is improving or degrading over time.

## Context

Currently **every sparkline on every page is empty** because no engine stores historical scan data.

- `scanTrend[]` in `misconfig` BFF: `safe_get(data, "scan_trend", [])` — threat engine never returns this
- `INV_SCAN_TREND` in `inventory/page.jsx`: **removed** (was 8-point hardcoded mock — now wired to `data.scanTrend || []` which is also empty)
- Dashboard `trendData`: falls back to 30-day generated sine-wave mock when engine returns empty
- `PostureTrendChart` in misconfig: always shows "No trend data yet"

`scan_orchestration` already records every scan with `started_at`, `completed_at`, `status`, and per-engine finding counts. This is the authoritative source for scan history.

## What to Build

### 1. DB View / Query (no new table needed)

The BFF needs to query `scan_orchestration` (in the onboarding/discoveries DB) to build the trend. The query groups completed scans by date and computes:

```sql
SELECT
  DATE(started_at AT TIME ZONE 'UTC') AS scan_date,
  COUNT(*) AS scan_count,
  MAX(total_findings) AS total,
  MAX(critical_count) AS critical,
  MAX(high_count) AS high,
  MAX(medium_count) AS medium
FROM scan_orchestration
WHERE tenant_id = %s
  AND status = 'completed'
  AND started_at > NOW() - INTERVAL '60 days'
GROUP BY scan_date
ORDER BY scan_date
```

> Note: column names may differ — verify against actual `scan_orchestration` schema before running.

### 2. BFF shared helper `_shared.py`

Add `async def fetch_scan_trend(tenant_id: str, auth_headers: dict, days: int = 30) -> list` that:
- Connects to onboarding/discoveries DB (whichever has `scan_orchestration`)
- Runs the query above
- Returns `[{date, total, critical, high, medium, passRate}]` sorted by date

### 3. Wire into inventory BFF (`bff/inventory.py`)

In `view_inventory()`, call `fetch_scan_trend()` and add to return:
```python
"scanTrend": scan_trend,
```

Shape each item:
```json
{ "date": "2026-05-01", "assets": 0, "critical": 12, "high": 34, "total": 120, "drift": 0 }
```
> `assets` and `drift` require separate queries (or can stay 0 until a dedicated scan_history table exists).

### 4. Wire into misconfig BFF (`bff/misconfig.py`)

Replace current:
```python
"scanTrend": safe_get(data, "scan_trend", []),
```
With result of `fetch_scan_trend()`. Field names must include `passRate` (computed as `passed / (passed + failed) * 100`).

### 5. Dashboard BFF (`bff/dashboard.py`)

Replace client-side 30-day sine-wave mock (`trendData` fallback at UI line 345) with server-side `fetch_scan_trend()` result in `trendData` field.

## Acceptance Criteria

### AC-01 — Inventory sparklines show real data
After running 2+ scans, `data.scanTrend` in inventory BFF response contains at least 2 data points. Inventory page sparklines (assetsTrend, criticalTrend) render non-empty.

### AC-02 — Misconfig PostureTrendChart renders
After running 2+ scans, `scanTrend[]` in misconfig BFF response is non-empty. `PostureTrendChart` renders bars and line instead of "No trend data yet".

### AC-03 — Dashboard threat trend uses real data
`trendData` in dashboard BFF contains real scan dates when ≥2 scans completed. UI no longer falls back to sine-wave mock.

### AC-04 — Multi-tenant isolation
`scan_trend` query always scoped by `tenant_id` from `AuthContext`. No cross-tenant data leakage.

### AC-05 — Empty state handled gracefully
When `scanTrend = []` (first scan not yet run), all sparklines render empty without crash. No division-by-zero in delta calculations.

## Technical Notes

- `scan_orchestration` location: verify with `kubectl exec` — check which engine pod has `SCAN_ORCHESTRATION_DB_HOST` env var
- The `pass_rate` field must be computed: `(total - critical - high - medium) / total * 100` as a proxy until per-scan pass/fail counts are stored
- `assets` count per scan requires joining `scan_orchestration` with `inventory_assets` count — defer to v2; set `assets: 0` for now
- `drift` per scan requires comparing consecutive scans — defer to v2; set `drift: 0` for now

## Definition of Done

- [ ] `fetch_scan_trend()` helper in `_shared.py` (or `bff/_scan_history.py`)
- [ ] `inventory` BFF returns `scanTrend[]` with real data
- [ ] `misconfig` BFF returns `scanTrend[]` with `{date, total, critical, high, medium, passRate}` shape
- [ ] Dashboard BFF `trendData` uses real scan history
- [ ] All three: empty state = `[]`, not crash
- [ ] Multi-tenant guard verified
- [ ] No mock fallback data in BFF or UI for scan trend
