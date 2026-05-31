# CDR-2-S04: Add Sequence Detections Section to CDR BFF View + UI

## Sprint
CDR-2 — UI Enrichment Sprint

## Priority
P1 — Multi-stage sequence detector findings (`rule_source='sequence'`: identity_pivot, secrets_staging, compute_hijack, s3_exfil) are written to `cdr_findings` but are not surfaced in the CDR BFF view or the overview page. These are the highest-fidelity detections CDR produces and should be prominently displayed.

## Depends On
CDR-1-S04 (sequence detector posture signals) — sequence findings must write correct posture signals before surfacing in UI.

## Story
As a security analyst on the CDR overview page, I need a dedicated "Multi-Stage Attack Sequences" section showing detected attack chains with their step count and severity, so I can prioritize investigation of confirmed multi-hop attacks over individual log anomalies.

## Background

`cdr_findings` has `rule_source` column with values:
- `'rule'` — L1 single-event rule match
- `'log_correlation'` — L2 multi-event correlation
- `'baseline'` — L3 behavioral anomaly
- `'sequence'` — sequence detector (multi-stage attack pattern)

The current CDR BFF view (`shared/api_gateway/bff/cdr.py`) fetches dashboard, identities, and top-rules from the engine. None of these filter by `rule_source='sequence'`. Sequence findings show up in the top-rules list only if they happen to have the highest count — they are not surfaced as a distinct category.

The engine endpoint `GET /api/v1/cdr/findings` accepts a `rule_source` filter. Use it.

## Files to Read First

- `shared/api_gateway/bff/cdr.py` — full BFF view handler; find the parallel fetch block
- `engines/cdr/cdr_engine/api_server.py` — `GET /api/v1/cdr/findings` endpoint; confirm `rule_source` filter param works
- `frontend/src/app/cdr/page.jsx` — current overview page (file is `.jsx`, not `.tsx`)

## Current CDR Tab Structure (verified 2026-05-30)

```js
// from page.jsx lines 515–530
tabs: [
  { id: 'overview',    label: 'Overview',        count: topCritical.length },
  { id: 'detections',  label: 'Detection Rules', count: topRules.length    },
  { id: 'events',      label: 'Log Sources',     count: logSources.length  },
]
// tabData: { overview, detections, events }
// Overview tab uses renderTab (custom layout with heatmap + identity table)
// Add: { id: 'sequences', label: 'Sequences', count: sequenceDetections.total }
```

CDR-2-S03 (heatmap) is DONE — already wired. No changes needed there.

## Files to Modify

| File | Change |
|---|---|
| `shared/api_gateway/bff/cdr.py` | Add `sequence_detections` parallel fetch; include in BFF response |
| `frontend/src/app/cdr/page.jsx` | Add `sequences` tab + `sequenceColumns` + `sequenceDetections` state |
| (no new component file needed — use DataTable via PageLayout tabData) |

## Exact BFF Change: `bff/cdr.py`

In the parallel fetch block, add alongside existing calls:

```python
import asyncio

async def _fetch_sequence_detections(engine_base: str, scan_run_id: str, tenant_id: str, headers: dict) -> list:
    url = f"{engine_base}/api/v1/cdr/findings?rule_source=sequence&limit=20&scan_run_id={scan_run_id}"
    # use existing HTTP client pattern in the file
    resp = await http_get(url, headers=headers)
    return resp.get("findings", [])
```

Add to BFF response dict:
```python
"sequenceDetections": {
    "findings": sequence_findings,  # list of up to 20 sequence findings
    "total": len(sequence_findings),
    "has_critical": any(f["severity"] == "critical" for f in sequence_findings),
}
```

Each finding in the list: `finding_id`, `rule_id`, `title`, `severity`, `actor_principal`, `resource_uid`, `first_seen_at`, `mitre_tactics`, `rule_source='sequence'`.

## UI Component: `SequenceDetections`

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚠ Multi-Stage Attack Sequences  (3 detected)                    │
├──────────────────┬──────────────┬───────────────┬───────────────┤
│ Pattern          │ Actor        │ Target        │ Severity      │
├──────────────────┼──────────────┼───────────────┼───────────────┤
│ S3 Data Exfil    │ user/alice   │ s3://prod     │ 🔴 CRITICAL   │
│ Identity Pivot   │ role/svc     │ role/admin    │ 🔴 HIGH       │
│ Secrets Staging  │ lambda/fn    │ secretsmgr    │ 🟡 HIGH       │
└──────────────────┴──────────────┴───────────────┴───────────────┘
  [View all sequences →]
```

- Shown above the top-rules section (sequence findings are higher fidelity)
- Red alert banner if `has_critical=true`
- Each row: pattern name (from `rule_id` → human label map), actor short name, resource short name, severity badge
- Click row → opens finding detail side panel (same as other CDR findings)
- "View all sequences" → navigates to `/cdr/findings?rule_source=sequence`
- If no sequences: section hidden (not rendered as empty state)

Rule ID → human label map (define in component):
```
RULE_S3_EXFIL      → "S3 Data Exfiltration"
RULE_IDENTITY_PIVOT → "Identity Pivot Chain"
RULE_SECRETS_STAGING → "Secrets Staging"
RULE_COMPUTE_HIJACK → "Compute Hijack"
```

## Acceptance Criteria

- [ ] BFF `/views/cdr` response includes `sequenceDetections.findings` array
- [ ] Engine call to fetch sequences uses `rule_source=sequence` filter — NOT a full scan then client-side filter
- [ ] BFF call is in parallel with other CDR fetch calls (not sequential)
- [ ] UI section renders when `sequenceDetections.total > 0`
- [ ] UI section is hidden entirely when `total === 0` (no empty-state render)
- [ ] Red banner shown when `has_critical=true`
- [ ] Severity badge colors match platform severity palette (critical=red, high=orange, medium=yellow)
- [ ] Click row opens finding detail side panel (reuse existing CDR finding detail component)
- [ ] "View all sequences" link present when total > 5
- [ ] All BFF engine calls scoped by `tenant_id` from AuthContext
- [ ] `require_permission('cdr:read')` — viewer role can see sequence detections

## Security Checklist

- [ ] Engine call passes `tenant_id` from AuthContext via X-Auth-Context header, not as URL param
- [ ] `rule_source` param passed to engine is hardcoded as `'sequence'` — not user-controllable
- [ ] No raw event data in BFF response — only structured finding fields

## Definition of Done

- [ ] `bff/cdr.py` updated with `sequenceDetections` fetch
- [ ] `SequenceDetections.tsx` component created
- [ ] CDR overview page renders the section when sequences exist
- [ ] Manual verify: test-tenant-002 CDR scan → sequence findings present → section visible in browser
- [ ] No `latest` image tag if K8s manifest touched
- [ ] Gateway image rebuilt if `bff/cdr.py` changed