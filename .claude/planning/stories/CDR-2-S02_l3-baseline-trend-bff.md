# CDR-2-S02: L3 Baseline Trend BFF Endpoint + UI Sparkline

## Sprint
CDR-2 — UI Enrichment Sprint

## Priority
P1 — `cdr_actor_daily_stats` and `cdr_baselines` tables contain 14 days of per-actor behavioral metrics and computed mean/stddev thresholds. This data exists but has no BFF endpoint and no UI visualization. Analysts cannot see whether an anomaly is a one-off spike or a sustained drift.

## Depends On
CDR-1-S02 (L3 resource_uid resolution) — must be deployed so L3 findings have valid resource_uid before trend data is surfaced.

## Story
As a security analyst on the CDR identity profile page, I need to see a 14-day trend sparkline for each behavioral metric alongside the computed baseline threshold, so I can determine whether an anomaly is a sudden spike or a sustained behavioral shift.

## Background

**Tables available (in `threat_engine_cdr` DB):**

`cdr_actor_daily_stats`:
```sql
actor_principal TEXT, metric_name TEXT, metric_date DATE,
metric_value FLOAT, tenant_id VARCHAR
```

`cdr_baselines`:
```sql
actor_principal TEXT, metric_name TEXT, mean FLOAT, stddev FLOAT,
window_days INT, computed_at TIMESTAMPTZ, tenant_id VARCHAR
```

**Metric names** (examples): `api_call_count`, `unique_services`, `unique_resources`, `unique_source_ips`, `after_hours_ratio`, `cross_region_ratio`

**Existing engine endpoint**: None — needs to be added to `api_server.py`.
**Existing BFF endpoint**: `GET /api/v1/views/cdr_identity` exists (`bff/cdr_identity.py`) and already builds hourly activity data. The 14-day baseline trend should be added to this same BFF view.

## Files to Read First

- `engines/cdr/cdr_engine/api_server.py` — existing endpoints; find where to add `/actor/{principal}/baseline-trend`
- `shared/api_gateway/bff/cdr_identity.py` — current `cdr_identity` BFF view shape; add baseline_trend here
- `shared/database/schemas/cdr_schema.sql` — or check CREATE TABLE DDL in `baseline_evaluator.py` for exact column names
- `engines/cdr/cdr_engine/evaluator/baseline_evaluator.py` — understand `metric_name` values written

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/cdr_engine/api_server.py` | Add `GET /api/v1/cdr/actor/baseline-trend` endpoint |
| `shared/api_gateway/bff/cdr_identity.py` | Call new endpoint; add `baselineTrend` to BFF response |
| `frontend/src/app/(portal)/cdr/` | Add baseline trend sparklines to identity profile page |

## Exact Engine Endpoint

### `GET /api/v1/cdr/actor/baseline-trend`

Query params: `principal` (URL-encoded ARN), `tenant_id` from AuthContext.

```python
@router.get("/actor/baseline-trend")
async def get_actor_baseline_trend(
    principal: str = Query(...),
    auth: AuthContext = Depends(require_permission("cdr:read")),
):
    with get_cdr_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        # Daily stats — last 14 days
        cur.execute("""
            SELECT metric_name, metric_date, metric_value
            FROM cdr_actor_daily_stats
            WHERE tenant_id = %s AND actor_principal = %s
              AND metric_date >= CURRENT_DATE - INTERVAL '14 days'
            ORDER BY metric_name, metric_date
        """, (auth.tenant_id, principal))
        stats = cur.fetchall()

        # Baselines
        cur.execute("""
            SELECT metric_name, mean, stddev
            FROM cdr_baselines
            WHERE tenant_id = %s AND actor_principal = %s
        """, (auth.tenant_id, principal))
        baselines = {row["metric_name"]: row for row in cur.fetchall()}

    # Group stats by metric
    from collections import defaultdict
    grouped = defaultdict(list)
    for row in stats:
        grouped[row["metric_name"]].append({
            "date": str(row["metric_date"]),
            "value": float(row["metric_value"]),
        })

    result = []
    for metric, points in grouped.items():
        b = baselines.get(metric, {})
        result.append({
            "metric": metric,
            "points": points,
            "mean": float(b["mean"]) if b.get("mean") else None,
            "stddev": float(b["stddev"]) if b.get("stddev") else None,
            "threshold": (float(b["mean"]) + 2 * float(b["stddev"])) if b.get("mean") and b.get("stddev") else None,
        })

    return {"principal": principal, "metrics": result}
```

### BFF: `cdr_identity.py` addition

In the parallel fetch block, add call to `baseline-trend` alongside the existing hourly-activity call. Add to response:
```python
"baselineTrend": {
    "metrics": [...],   # from engine response
}
```

## UI Component: Baseline Trend Sparklines

On the CDR identity profile page (`/cdr_identity?principal=...`), below the hourly heatmap, add a section "14-Day Behavioral Baseline":

```
┌─────────────────────────────────────────────────────┐
│  14-Day Behavioral Baseline                          │
├─────────────────────────────────────────────────────┤
│  API Call Count     ████████▄▄▄▄▂▂▄▄██████████ 847  │
│  Baseline: 210  Threshold: 390  ↑ 4.0σ ANOMALY      │
│                                                     │
│  Unique Services    ▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂ 6          │
│  Baseline: 5  Threshold: 8  Normal                  │
│                                                     │
│  Cross-Region Ratio ▂▂▂▂▂▂▂▂▂▂▂▂▂▂▂███ 0.42         │
│  Baseline: 0.02  Threshold: 0.08  ↑ HIGH             │
└─────────────────────────────────────────────────────┘
```

- One row per metric
- SVG sparkline (14 data points), colored red if latest value > threshold
- Mean line and threshold line drawn on sparkline
- Sigma deviation badge shown when latest value > mean + 2σ

## Acceptance Criteria

- [ ] `GET /api/v1/cdr/actor/baseline-trend?principal=...` returns 14-day stats and baseline thresholds scoped by `tenant_id` from AuthContext (NOT from query param)
- [ ] BFF `/views/cdr_identity` response includes `baselineTrend.metrics` array
- [ ] Identity profile page renders sparklines for all available metrics
- [ ] Metrics with no data in last 14 days are omitted (not shown as empty rows)
- [ ] If actor has no baseline (new actor < 14 days old): show "Insufficient history for baseline" message
- [ ] Red coloring when latest value > mean + 2σ threshold
- [ ] `require_permission("cdr:read")` on new engine endpoint
- [ ] Viewer role can see baseline trend (cdr:read is viewer permission)
- [ ] `analyst` and above required for `cdr_identity` page (confirm `cdr:sensitive` gate still in place on BFF)
- [ ] All engine queries scoped by `tenant_id` from AuthContext

## Security Checklist

- [ ] `principal` query param is validated (must be non-empty, max 512 chars) — do not pass raw to SQL without parameterization
- [ ] `tenant_id` always from AuthContext, never from `principal` ARN parsing
- [ ] No raw event data in baseline trend response (only aggregate stats)
- [ ] SOC2 audit log emitted on `cdr_identity` BFF call (already present — confirm not removed)

## Definition of Done

- [ ] Engine endpoint added to `api_server.py`
- [ ] BFF `cdr_identity.py` wires baseline trend into response
- [ ] Sparkline UI component rendered on identity profile page
- [ ] Manual verify: port-forward CDR engine, call `/actor/baseline-trend?principal=...`, confirm metrics returned
- [ ] No `latest` image tag in CDR K8s manifest
- [ ] CDR image rebuilt and pushed