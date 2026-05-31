# CDR-2-S03: Wire Identity Heatmap into CDR Overview Page

## Status: DONE — Already Implemented (verified 2026-05-30)
## Action: Delete this file — no work needed.

`IdentityRiskHeatmap` is imported and rendered in `frontend/src/app/cdr/page.jsx`.
Data fetched via `fetchView('cdr/heatmap')`. BFF endpoint exists in `bff/cdr.py`.
No further work needed. Delete this story file.

---

## Sprint
CDR-2 — UI Enrichment Sprint

## Priority
P1 — The identity heatmap BFF endpoint (`GET /api/v1/views/cdr/heatmap`) already exists and returns an account × principal_type matrix. It is unclear whether the frontend `/cdr` page actually renders it. This story confirms, fixes, and fully wires the heatmap.

## Story
As a security analyst on the CDR overview page, I need to see a heatmap showing which cloud accounts have the most active identities by type (iam_user, iam_role, service_account, root), so I can quickly identify high-risk accounts without drilling into each one individually.

## Background

BFF endpoint exists in `shared/api_gateway/bff/cdr.py`:
```
GET /api/v1/views/cdr/heatmap
```
Returns (from engine `/api/v1/cdr/identities/heatmap`):
```json
{
  "heatmap": [
    {
      "account_id": "123456789",
      "principal_type": "iam_role",
      "identity_count": 42,
      "active_count": 18,
      "avg_risk_score": 67
    },
    ...
  ]
}
```

This story: read the frontend CDR page, confirm whether the heatmap is rendered, and if not, build the component and wire it.

## Files to Read First

- `shared/api_gateway/bff/cdr.py` — full heatmap BFF handler; confirm response shape
- `engines/cdr/cdr_engine/api_server.py` — `GET /api/v1/cdr/identities/heatmap` engine endpoint
- `frontend/src/app/(portal)/cdr/page.tsx` (or `.jsx`) — current CDR overview page; check if heatmap is referenced
- `frontend/src/lib/api.js` — `fetchView()` usage pattern

## Files to Modify

| File | Change |
|---|---|
| `frontend/src/app/(portal)/cdr/page.tsx` | Add `IdentityHeatmap` component if not present; wire `fetchView('cdr/heatmap')` |
| `frontend/src/app/(portal)/cdr/IdentityHeatmap.tsx` | **NEW if missing** — renders account × principal_type grid |

## Component Design: `IdentityHeatmap`

```
┌─────────────────────────────────────────────────────────┐
│  Identity Activity Heatmap  (by account × principal type)│
├──────────────┬───────────┬────────────┬─────────────────┤
│              │ iam_user  │  iam_role  │ service_account │
├──────────────┼───────────┼────────────┼─────────────────┤
│ 123456789012 │  ██ 12    │  ████ 42   │     ▒ 4         │
│ 987654321098 │   ▒ 3     │   ██ 18    │    ██ 22        │
│ 456789012345 │   ░ 1     │    ▒ 6     │     ░ 2         │
└──────────────┴───────────┴────────────┴─────────────────┘
  Heat scale: ░ low  ▒ medium  █ high  (based on avg_risk_score)
```

- Rows = cloud accounts (account_id, show short alias if available)
- Columns = principal_type (iam_user, iam_role, service_account, root)
- Cell = color intensity based on `avg_risk_score` (0-100 → white→red), label = `active_count`
- Click cell → navigate to `/cdr_identity` filtered by account + principal_type
- Empty cells (no data) shown as grey, not blank

## Acceptance Criteria

- [ ] CDR overview page (`/cdr`) renders the `IdentityHeatmap` component
- [ ] Heatmap data loaded via `fetchView('cdr/heatmap')` (BFF call — not direct engine)
- [ ] Cells colored by `avg_risk_score` (0=white, 50=orange, 100=red)
- [ ] Cell label shows `active_count` (identities with findings in last 30 days)
- [ ] Clicking a cell navigates to `/cdr_identity` with `?account=X&principal_type=Y` filter
- [ ] If heatmap returns empty array: show "No identity activity recorded" state
- [ ] Loading skeleton shown while BFF call is in flight
- [ ] Heatmap is below the severity breakdown section on the page (not above KPI cards)
- [ ] `fetchView` uses session auth cookie — no API key in frontend
- [ ] Heatmap visible to `analyst` and `tenant_admin` roles; `viewer` sees it too (cdr:read)

## Security Checklist

- [ ] BFF heatmap handler scopes engine call with `tenant_id` from AuthContext (confirm in `bff/cdr.py`)
- [ ] No account_id leakage across tenants — BFF uses session-scoped tenant_id
- [ ] Cell click navigation uses query params, not route params that could be manipulated

## Definition of Done

- [ ] Frontend CDR page renders heatmap (confirmed by loading `/cdr` in browser with real data)
- [ ] If heatmap was already wired, document confirmation and close story
- [ ] Component handles loading, empty, and error states
- [ ] No frontend build errors
- [ ] No `latest` image tag if any K8s manifest touched