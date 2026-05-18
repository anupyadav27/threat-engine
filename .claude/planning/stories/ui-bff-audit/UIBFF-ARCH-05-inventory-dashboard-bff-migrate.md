# Story UIBFF-ARCH-05: Inventory + Dashboard BFF — Add scanTrend and Posture Summary from Tables

## Status: ready-for-dev

## Metadata
- **Phase**: Sprint UIBFF-ARCH — Two-Table BFF Architecture Migration
- **Epic**: UI→BFF→Engine Verified Data Chain
- **Points**: 3
- **Priority**: P2
- **Depends on**: UIBFF-S01-01 (fetch_scan_trend), UIBFF-BFF-02 (read_posture), UIBFF-S01-02 (dashboard mock removal must ship first)
- **Blocks**: None

## User Story

As a developer, I want the Inventory and Dashboard BFF handlers to use `read_posture()` for KPI aggregations and `fetch_scan_trend()` for trend data so all charts are consistently sourced from the two central tables.

## Context

**Inventory BFF** (`inventory.py`): Already fetches assets from inventory engine. Needs to add:
1. `scanTrend` from `fetch_scan_trend()` (UIBFF-S01-01 does this)
2. Per-asset posture dimensions (risk_score, critical_count) enriched from `resource_security_posture`

**Dashboard BFF** (`dashboard.py`): Makes 7 engine HTTP calls in parallel. After UIBFF-S01-02 removes mock fallbacks, `trendData` needs a real source. This story wires it via `fetch_scan_trend()`.

## What to Build

### 1. Wire `scanTrend` into Inventory BFF (if not done by S01-01)

In `inventory.py` `view_inventory()`:
```python
from ._shared import fetch_scan_trend, read_posture

async def view_inventory(tenant_id, account_id=None, provider=None, region=None, auth_headers={}) -> dict:
    # ... existing asset fetch from inventory engine

    # Add scanTrend
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers, days=30)

    # Enrich top assets with posture dimensions from resource_security_posture
    if assets:
        top_uids = [a["resource_uid"] for a in assets[:200]]
        posture_result = await read_posture(
            tenant_id=tenant_id,
            resource_uids=top_uids,
        )
        posture_map = {p["resource_uid"]: p for p in posture_result["posture"]}

        for asset in assets:
            p = posture_map.get(asset.get("resource_uid"), {})
            asset["risk_score"]           = p.get("overall_posture_score") or asset.get("risk_score", 0)
            asset["blast_radius_score"]   = p.get("overall_posture_score")  # best proxy until blast-radius col added
            asset["is_encrypted"]         = p.get("is_encrypted_at_rest", False)
            asset["is_in_private_subnet"] = p.get("is_in_private_subnet", False)

    return {
        ...existing...,
        "scanTrend": scan_trend,
    }
```

### 2. Wire `trendData` into Dashboard BFF

In `dashboard.py` `view_dashboard()`:
```python
from ._shared import fetch_scan_trend, read_posture

async def view_dashboard(tenant_id, ..., auth_headers={}) -> dict:
    # ... existing 7 engine calls

    # Add scan trend
    scan_trend = await fetch_scan_trend(tenant_id, auth_headers, days=30)

    # Add posture summary from resource_security_posture
    posture_summary = await read_posture(
        tenant_id=tenant_id,
        limit=1,  # just for summary
    )

    return {
        ...existing...,
        "trendData":    scan_trend,   # replaces None/{}
        "postureSummary": posture_summary["summary"],
    }
```

Remove the sinew-wave `mockTrend` reference in BFF if any remains (should be done by S01-02).

### 3. Verify Inventory `scanTrend` shape matches page expectations

`inventory/page.jsx` reads:
```javascript
const scanTrend = data.scanTrend || [];
const assetsTrend   = scanTrend.map(d => d.assets   ?? 0);
const criticalTrend = scanTrend.map(d => d.critical  ?? 0);
const driftTrend    = scanTrend.map(d => d.drift     ?? 0);
```

`fetch_scan_trend()` returns `[{date, total, critical, high, medium, passRate}]`.
Add `assets: 0` and `drift: 0` fields to each item (deferred until inventory joins scan history — see S01-01 technical notes):

```python
scan_trend = [
    {**item, "assets": 0, "drift": 0}
    for item in await fetch_scan_trend(tenant_id, auth_headers)
]
```

## Acceptance Criteria

### AC-01 — Inventory `scanTrend` populated
`/api/v1/views/inventory` response contains `scanTrend[]` with ≥1 item after 1+ completed scans.

### AC-02 — Dashboard `trendData` populated
`/api/v1/views/dashboard` response contains `trendData[]` with real scan dates, not a sine wave.

### AC-03 — Inventory sparklines render
Inventory page sparklines (assetsTrend, criticalTrend) show non-flat lines after 2+ scans.

### AC-04 — Dashboard trend chart renders real data
Dashboard threat trend chart renders real bars/points — not sine-wave peaks.

### AC-05 — Empty state on zero scans
When no scans have run, `scanTrend: []` — sparklines render flat with no crash.

## Cleanup Steps (After Testing)

1. `grep "mockTrend\|RISK_SCAN_TREND\|sine\|Math.sin" shared/api_gateway/bff/` → 0 hits
2. Load inventory page after 2 scans — sparklines show real data
3. Load dashboard — trend chart shows real scan dates
4. Rebuild gateway, verify rollout

## Definition of Done

- [ ] `inventory.py` returns `scanTrend` from `fetch_scan_trend()`
- [ ] Inventory assets enriched with `risk_score`, `is_encrypted`, `is_in_private_subnet` from `read_posture()`
- [ ] `dashboard.py` returns `trendData` from `fetch_scan_trend()`
- [ ] AC-01 through AC-05 verified
- [ ] Cleanup completed
- [ ] Gateway image: `yadavanup84/threat-engine-api-gateway:v-bff-arch-inv-dash1`