# JNY-12: `/risk/scenario/[id]` + `/vulnerability/agents/[id]` detail routes

## Track
Investigation Journey Unification — Phase F

## Priority
P1 — Closes G-11 (Vulnerability "Could not load agent list" + no agent detail) and G-28 (Risk scenarios don't link to driving findings); covers ADR §6.3 recommended scope expansion.

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `risk` + `vulnerability` | R |
| UI / BFF / Gateway dev | `cspm-ui-dev` + `cspm-bff-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
— (no checkpoint participation) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1, `Risk Scenario` and `Vulnerability Agent` are L1 entities with canonical detail routes. Per ADR §6.3 (recommended yes), `/risk/scenario/[id]` must link back to driving threat detections + failing compliance controls — that closes G-28. Vulnerability agent detail closes G-11 ("Could not load agent list" + no agents endpoint).

## What to build

### Risk Scenario detail
1. Route: `/Users/apple/Desktop/threat-engine/frontend/src/app/risk/scenario/[id]/page.jsx`
2. BFF: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/views/risk_scenario_detail.py`
3. Tabs: Overview (FAIR breakdown — LEF, LM, ALE) · Driving Findings (PivotLink to threat/check findings) · Affected Assets (PivotLink to inventory) · Failing Controls (PivotLink to compliance framework) · Mitigations.
4. Reuse PivotLink everywhere outbound.

### Vulnerability Agent detail
1. Route: `/Users/apple/Desktop/threat-engine/frontend/src/app/vulnerability/agents/[id]/page.jsx`
2. BFF: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/views/vulnerability_agent_detail.py`
3. List endpoint fix: ensure `/api/v1/views/vulnerability/agents` returns 200 with at least an empty array when no agents (closes "Could not load agent list").
4. Tabs: Overview · Scans · Findings (PivotLink to CVEs) · Host Context.

## Acceptance criteria
- [ ] `/risk/scenario/[id]` renders 5 tabs; FAIR fields populated from `risk_scenarios` + `risk_summary` tables
- [ ] Driving Findings tab uses PivotLink to threat + check findings — middle-click works
- [ ] Failing Controls tab uses PivotLink to `/compliance/[framework]` (closes G-28)
- [ ] `/vulnerability/agents/[id]` renders 4 tabs
- [ ] Vulnerability agents list endpoint returns 200 (empty array allowed) — no console error on `/vulnerability` page
- [ ] All BFF reads use standard columns + JSONB only; no new SQL columns
- [ ] Tenant isolation enforced
- [ ] OpenAPI specs added at `/docs`

## Dependencies
- Blocks: sprint exit walk-through
- Blocked by: JNY-05/JNY-06 (universal finding contract reused), JNY-07 (PivotLink), JNY-04 (deploy)

## Constitution check
- BFF read-only; writes to engine endpoints.
- No fallback merge across engines for FAIR data.
- Standard columns + finding_data JSONB.
- Tenant_id MANDATORY.

## Out of scope
- Modifying FAIR scoring math.
- Vulnerability agent enrollment flow.
- New vulnerability schema (only read existing tables).

## Files touched (estimate)
- `frontend/src/app/risk/scenario/[id]/page.jsx` — new
- `frontend/src/app/vulnerability/agents/[id]/page.jsx` — new
- `shared/api_gateway/bff/views/risk_scenario_detail.py` — new
- `shared/api_gateway/bff/views/vulnerability_agent_detail.py` — new
- `shared/api_gateway/bff/router.py` — register both routes
- `shared/api_gateway/bff/views/vulnerability_agents_list.py` — bug fix (empty list)
- `frontend/src/app/vulnerability/page.jsx` — wire PivotLink to agent detail
- `.claude/documentation/API-REFERENCE.md` — entries

## Test plan
- Unit: BFF returns expected envelope for known scenario_id and agent_id
- BFF contract: schema validation
- UI smoke: navigate from Risk page row → scenario detail → click a driving finding → land on `/finding/threat/<id>`
- Cross-engine: scenario → driving threat → click resource → land on inventory asset
- Security: cross-tenant request → 404
