# CDR-2-S01: Wire L2 Correlation Timeline into Finding Detail Panel

## Sprint
CDR-2 — UI Enrichment Sprint

## Priority
P0 — L2 correlation findings have a `contributing_steps` chain stored in `cdr_findings.finding_data` JSONB and a dedicated engine endpoint (`GET /api/v1/cdr/findings/{finding_id}/timeline`) that returns it. Nothing in the UI renders this chain. Security analysts see a single finding card with no context about the multi-event sequence that triggered it.

## Depends On
CDR-1-S03 (multi-technique indexing) — CDR-1 must be deployed first so `detail.all_mitre_techniques` is available for step-level technique display.

## Story
As a security analyst viewing a CDR finding detail panel, I need to see the ordered sequence of events that triggered an L2 correlation finding, so I can understand the full attack chain and trace back to the originating event.

## Background

The engine endpoint already exists and works:
```
GET /api/v1/cdr/findings/{finding_id}/timeline
```
Returns:
```json
{
  "finding_id": "...",
  "rule_source": "log_correlation",
  "contributing_steps": [
    {
      "step": 1,
      "event_time": "2026-05-30T10:01:00Z",
      "operation": "ConsoleLogin",
      "actor_principal": "arn:aws:iam::123:user/alice",
      "source_ip": "1.2.3.4",
      "resource_uid": "...",
      "mitre_technique": "T1078",
      "anomaly_score": 0.82
    },
    ...
  ],
  "total_steps": 3
}
```

This endpoint is reachable via the API gateway at `/api/engine/cdr/findings/{id}/timeline` (direct engine proxy, not BFF — paginated/detail data goes direct per the constitution).

L1 findings have no timeline (single event). The UI should only show the timeline component for `rule_source = 'log_correlation'` findings.

## Files to Read First

- `shared/api_gateway/bff/cdr.py` — CDR BFF view; understand what `findingDetail` shape currently looks like
- `engines/cdr/cdr_engine/api_server.py` — `GET /api/v1/cdr/findings/{finding_id}/timeline` endpoint implementation
- `frontend/src/lib/constants.js` — `ENGINE_ENDPOINTS` map for CDR
- `frontend/src/lib/api.js` — `getFromEngine()` pattern for direct engine calls
- Any existing finding detail panel in frontend (check `/cdr` page components) — to understand the side-panel drilldown pattern

## Files to Modify

| File | Change |
|---|---|
| `frontend/src/app/(portal)/cdr/` | Add `CorrelationTimeline` component; wire into finding detail side panel when `rule_source='log_correlation'` |
| `frontend/src/lib/constants.js` | Confirm CDR timeline endpoint is in `ENGINE_ENDPOINTS` (add if missing) |

## Component Design: `CorrelationTimeline`

```
┌─────────────────────────────────────────────────────┐
│  Attack Sequence  (3 steps)              L2 Correl. │
├─────────────────────────────────────────────────────┤
│  ① 10:01  ConsoleLogin     alice   1.2.3.4  T1078  │
│      └─ Anomaly score: 0.82                         │
│                    ↓                                │
│  ② 10:04  AssumeRole       alice → role/admin T1078 │
│      └─ Cross-account assume                        │
│                    ↓                                │
│  ③ 10:09  GetObject        s3://prod-data   T1530  │
│      └─ 42 objects accessed                         │
└─────────────────────────────────────────────────────┘
```

- Vertical step chain, each step shows: step number, timestamp, operation, actor, resource short name, MITRE technique badge
- Anomaly score shown as a small pill if > 0
- Steps connected by a vertical arrow line
- Only shown when `rule_source === 'log_correlation'`
- Loaded via `getFromEngine('cdr', `/findings/${findingId}/timeline`)` on panel open

## Acceptance Criteria

- [ ] L2 correlation finding detail panel shows `CorrelationTimeline` component
- [ ] L1 findings (rule_source = 'rule') do NOT show the timeline component
- [ ] L3 baseline findings (rule_source = 'baseline') do NOT show the timeline component
- [ ] Timeline steps render in chronological order (step 1 → N)
- [ ] Each step shows: timestamp, operation, actor_principal (truncated to last segment), MITRE technique badge
- [ ] Loading state shown while timeline fetches
- [ ] If timeline endpoint returns empty steps: show "No step detail available" message (do not crash)
- [ ] Timeline is fetched from direct engine endpoint, NOT BFF (constitution: paginated/detail data goes direct)
- [ ] `require_permission('cdr:read')` enforced on the engine endpoint (already there — confirm not removed)
- [ ] Viewer role sees the timeline (cdr:read is a viewer permission — confirm)

## Security Checklist

- [ ] `finding_id` in URL is validated as UUID before engine call
- [ ] No raw event payloads displayed in UI — only structured step fields
- [ ] `actor_principal` displayed without exposing raw CloudTrail JSON

## Definition of Done

- [ ] `CorrelationTimeline` component created and wired into CDR finding detail panel
- [ ] Tested with a real L2 finding on test-tenant-002 (port-forward CDR engine, fetch timeline)
- [ ] Tested with L1 and L3 findings — no timeline shown
- [ ] No frontend build errors (`npm run build` clean)
- [ ] No `latest` image tag if any K8s manifest touched