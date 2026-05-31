# CDR-3-S02: CDR Dashboard Header Shows Last CDR Scan + Last Attack-Path Re-evaluation Times

## Sprint
CDR-3 — Attack-Path Enrichment Sprint

## Priority
P2 — Analysts need to know data freshness. CDR runs hourly; after each CDR scan the attack-path is re-evaluated (Wave 5 of cdr-cron-pipeline). Currently there is no UI indication of when the last CDR scan completed or when attack paths were last refreshed.

## Story
As a security analyst on the CDR overview page, I need to see when the last CDR scan completed and when the attack path was last re-evaluated, so I know whether the current findings reflect the most recent cloud activity.

## Background

**Last CDR scan time** — available from `cdr_report` table (in `threat_engine_cdr`):
```sql
SELECT MAX(completed_at) FROM cdr_report WHERE tenant_id = %s AND status = 'completed'
```

**Last attack-path re-evaluation time** — available from `scan_runs` table (in `threat_engine_onboarding`) or from `attack_paths` table:
```sql
SELECT MAX(created_at) FROM attack_paths WHERE tenant_id = %s
```
Or via the existing attack-path engine health/status endpoint if one exists.

Both values should be added to the existing CDR BFF dashboard response, not as a new endpoint.

## Files to Read First

- `shared/api_gateway/bff/cdr.py` — dashboard BFF view; find where dashboard KPI data is fetched; confirm response shape
- `engines/cdr/cdr_engine/api_server.py` — `GET /api/v1/cdr/dashboard` endpoint; check if `last_scan_at` is already returned
- `engines/attack-path/attack_path_engine/` — check if there's a status/summary endpoint; check `attack_paths` table name and schema

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/cdr_engine/api_server.py` | Add `last_completed_scan_at` to dashboard endpoint response (read from `cdr_report`) |
| `shared/api_gateway/bff/cdr.py` | Add `lastAttackPathAt` to BFF response (query attack-path engine or DI DB) |
| `frontend/src/app/(portal)/cdr/page.tsx` | Add freshness indicator to CDR page header |

## Exact Engine Change: `api_server.py` dashboard endpoint

Add to the dashboard query or as a secondary query:
```python
cur.execute("""
    SELECT MAX(completed_at) AS last_scan_at
    FROM cdr_report
    WHERE tenant_id = %s AND status = 'completed'
""", (auth.tenant_id,))
scan_row = cur.fetchone()
last_scan_at = scan_row["last_scan_at"].isoformat() if scan_row and scan_row["last_scan_at"] else None
```

Add `"last_completed_scan_at": last_scan_at` to dashboard response.

## BFF Change: `bff/cdr.py`

After fetching dashboard data, add a call to the attack-path engine's summary/status or directly query `attack_paths`:
```python
# Prefer attack-path engine status endpoint if available
# Fallback: compute from dashboard's scan_run_id lookup
```

Add to BFF response:
```python
"scanFreshness": {
    "lastCdrScanAt": dashboard.get("last_completed_scan_at"),
    "lastAttackPathAt": last_ap_at,   # ISO timestamp or None
    "cdrScanAgeMinutes": compute_age_minutes(last_cdr_at),
    "attackPathAgeMinutes": compute_age_minutes(last_ap_at),
    "isStale": cdr_age_minutes > 90,  # stale if > 1.5× hourly cadence
}
```

## UI: Freshness Indicator in CDR Page Header

```
┌──────────────────────────────────────────────────────────────────┐
│  Cloud Detection & Response                                       │
│  Last scan: 14 min ago  ·  Attack paths updated: 8 min ago  ✓   │
│  ⚠ Scan data is 2h old — next scan due soon                      │
└──────────────────────────────────────────────────────────────────┘
```

- Green checkmark when both ages < 90 min
- Amber warning when CDR age > 90 min (scan overdue)
- Tooltip on hover: exact ISO timestamp
- "Attack paths updated" only shown if CDR-3-S01 is deployed (conditional render based on value presence)

## Acceptance Criteria

- [ ] BFF `/views/cdr` response includes `scanFreshness.lastCdrScanAt` (ISO timestamp or null)
- [ ] BFF `/views/cdr` response includes `scanFreshness.lastAttackPathAt` (ISO timestamp or null)
- [ ] `isStale = true` when CDR scan age > 90 minutes
- [ ] CDR overview page header renders freshness indicator
- [ ] Green state when both ages < 90 min; amber state when CDR age > 90 min
- [ ] Null timestamps shown as "Never" not as blank or crash
- [ ] All DB queries for timestamps scoped by `tenant_id`

## Security Checklist

- [ ] Timestamps are metadata — no finding data or resource UIDs in freshness response
- [ ] `tenant_id` from AuthContext in all queries

## Definition of Done

- [ ] Engine dashboard endpoint updated
- [ ] BFF response includes `scanFreshness`
- [ ] Frontend renders freshness indicator in CDR page header
- [ ] Manual verify: CDR scan completes → browser shows "X min ago" updating correctly
- [ ] Gateway image rebuilt if BFF changed; CDR image rebuilt if engine changed