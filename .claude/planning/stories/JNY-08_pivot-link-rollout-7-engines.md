# JNY-08: Wire PivotLink in 7 posture engine row tables

## Track
Investigation Journey Unification — Phase C

## Priority
P0 — Closes G-12..G-18 (orphaned rows across IAM, Network, DataSec, Encryption, Container Sec, DB Sec, AI Security) and G-19 (no rule_id click).

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | 7 sub-tasks (each engine consulted — see Sub-tasks) | C |
| UI / BFF / Gateway dev | `cspm-ui-dev` (coordinates rollout) | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1 L2 and Sprint §6, this is a mechanical rollout — wrap every `resource_uid`, `rule_id`, `actor_principal` cell with `<PivotLink>` across 7 list pages. Per Open Question 2 in ADR §6.2, ship one PR per engine, batched in a single rollout day. Each engine's page already has the row table; this story only swaps the cell renderer.

## What to build
For each of the 7 engine pages below, replace bare text cells with `<PivotLink>` and remove any `onClick={() => router.push(...)}` row handlers (PivotLink handles it):

- `/Users/apple/Desktop/threat-engine/frontend/src/app/iam/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/network-security/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/datasec/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/encryption/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/container-security/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/database-security/page.jsx`
- `/Users/apple/Desktop/threat-engine/frontend/src/app/ai-security/page.jsx`

Per row, wire three pivot points:
- `finding_id` → `<PivotLink to="finding" engine="<engine>" id={row.finding_id}>` (whole-row clickable)
- `resource_uid` cell → `<PivotLink to="asset" id={row.resource_uid} provider={row.provider}>`
- `rule_id` cell → `<PivotLink to="finding" engine="check" id={row.rule_id}>` (or rule detail route once available)

## Sub-tasks

Per [ADR §4.3.2](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#432-multi-engine-sub-task-breakdown), one sub-task per engine page; `cspm-ui-dev` (R) coordinates the rollout.

| Sub | Engine | Page file | Lead |
|-----|--------|-----------|------|
| JNY-08.1 | IAM | `frontend/src/app/iam/page.jsx` | `iam` (C) + `cspm-ui-dev` (R) |
| JNY-08.2 | Network Security | `frontend/src/app/network-security/page.jsx` | `network-security` (C) + `cspm-ui-dev` (R) |
| JNY-08.3 | DataSec | `frontend/src/app/datasec/page.jsx` | `datasec` (C) + `cspm-ui-dev` (R) |
| JNY-08.4 | Encryption | `frontend/src/app/encryption/page.jsx` | `encryption` (C) + `cspm-ui-dev` (R) |
| JNY-08.5 | Container Security | `frontend/src/app/container-security/page.jsx` | `container-security` (C) + `cspm-ui-dev` (R) |
| JNY-08.6 | Database Security | `frontend/src/app/database-security/page.jsx` | `dbsec` (C) + `cspm-ui-dev` (R) |
| JNY-08.7 | AI Security | `frontend/src/app/ai-security/page.jsx` | `ai-security` (C) + `cspm-ui-dev` (R) |

## Acceptance criteria
- [ ] All 7 pages updated; no remaining `router.push` in row click handlers for these pages
- [ ] Middle-click any row → opens `/finding/<engine>/<id>` in new tab
- [ ] Click resource_uid → `/inventory/[uid]`
- [ ] Click rule_id → finding/check detail
- [ ] No regression in row selection / bulk action behavior
- [ ] No new BFF fields requested — uses what list endpoints already return
- [ ] One PR per engine page, all stacked behind a feature flag if needed
- [ ] Visual regression: row height ±2px tolerance vs pre-change
- [ ] All 7 engines pass `cspm-code-reviewer` (find/replace pattern uniformity)

## Dependencies
- Blocks: sprint exit walk-through (Sprint §9)
- Blocked by: JNY-07 (component), JNY-05 + JNY-06 (destination route + BFF), JNY-04 (deploy)

## Constitution check
- UI competitive standards: every entity navigable, deep-linkable.
- No BFF fallback (PivotLink target page handles its own data state).
- Multi-cloud `provider` propagated.

## Out of scope
- CIEM, Compliance, Risk, CNAPP, CWPP, SecOps, Vulnerability pages (CIEM has its own bug fix in JNY-10; Risk/Vuln in JNY-12; others tracked separately).
- New columns or schema changes.
- BulkAction redesign.

## Files touched (estimate)
- `frontend/src/app/iam/page.jsx`
- `frontend/src/app/network-security/page.jsx`
- `frontend/src/app/datasec/page.jsx`
- `frontend/src/app/encryption/page.jsx`
- `frontend/src/app/container-security/page.jsx`
- `frontend/src/app/database-security/page.jsx`
- `frontend/src/app/ai-security/page.jsx`

## Test plan
- Unit: each page renders rows with PivotLink for the three pivot points
- UI smoke: per engine, click first row, land on `/finding/<engine>/<id>`
- E2E: click resource_uid in a Network row → land on Inventory asset page → see Network finding listed in Resource Context
- Cross-engine: same resource_uid clicked from IAM row and DataSec row both land on the same `/inventory/[uid]` page
