# JNY-09: Threat UI bug fixes — stopPropagation, SLA undefined, deprecated /threat_detail

## Track
Investigation Journey Unification — Phase D

## Priority
P1/P3 cluster — addresses G-4 (P1), G-5 (P3), G-8 (P3) in a single small PR.

## Status
done — all three bugs (G-4/G-5/G-8) resolved by deletion of /threats/[threatId]/ route; code no longer exists

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `threat` | C |
| UI / BFF / Gateway dev | `cspm-ui-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Three Threat Center bugs from ADR §2.2:
- **G-4 (P1)**: TechniqueDetailModal click is swallowed by parent `NodeInvestigationPanel` — needs `e.stopPropagation()` at `frontend/src/app/threats/[threatId]/page.jsx:1131`.
- **G-5 (P3)**: Remediation tab renders literal `"undefined d left"` when SLA is absent.
- **G-8 (P3)**: Frontend still calls deprecated `/api/v1/views/threat_detail` (404) in parallel with the working `/views/threats/{id}`.

## What to build
1. Add `e.stopPropagation()` (and `e.preventDefault()` if PivotLink-wrapped) on the technique badge click handler at `/Users/apple/Desktop/threat-engine/frontend/src/app/threats/[threatId]/page.jsx` (around line 1131).
2. Guard SLA formatter — render `—` (em dash) or `No SLA` when `sla_due_at` is null/undefined; never `${days} d left` with undefined `days`.
3. Remove the deprecated `/api/v1/views/threat_detail` fetch — grep frontend for `threat_detail` and delete or migrate the only call site.

## Acceptance criteria
- [ ] Technique badge click opens TechniqueDetailModal without also triggering the parent NodeInvestigationPanel close/expand
- [ ] Remediation tab shows `—` (or `No SLA`) for findings with no SLA; never `undefined d left`
- [ ] Browser network tab on `/threats/[id]` shows zero 404s
- [ ] Code search confirms `threat_detail` removed from frontend
- [ ] Existing Threat Center smoke tests still pass
- [ ] All three fixes ship in one PR

## Dependencies
- Blocks: sprint exit walk-through
- Blocked by: JNY-01 (technique modal needs working DB) and JNY-04 (deploy)

## Constitution check
- UI competitive standards — no broken/dead network calls.
- No new BFF endpoints, no schema changes.

## Out of scope
- TechniqueDetailModal redesign.
- SLA computation logic.
- Migration of any other deprecated endpoints (separate cleanup story if found).

## Files touched (estimate)
- `frontend/src/app/threats/[threatId]/page.jsx` — three small fixes
- `frontend/src/components/threats/TechniqueBadge.jsx` (if exists) — stopPropagation
- `frontend/src/lib/sla.js` (or inline formatter) — null guard
- `frontend/src/__tests__/threat-detail.test.jsx` — regression tests

## Test plan
- Unit: SLA formatter null/undefined → `—`
- UI smoke: open a threat detail; click technique badge; modal opens; parent panel state unchanged
- Network: open `/threats/[id]`, assert no 404 entries in browser network log
- Regression: existing threat journey E2E continues to pass
