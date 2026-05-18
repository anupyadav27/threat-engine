# JNY-05: Universal finding route `/finding/[engine]/[id]` + 5-tab template

## Track
Investigation Journey Unification — Phase B

## Priority
P0 — Closes G-20 (no per-finding detail route across 11 posture engines) and unlocks G-12..G-18 row-click pivots.

## Status
done — route /finding/[engine]/[id] exists with layout validation, FindingPageClient, FindingTabsShell (5 universal tabs + engine plugin registry), all 5 tab components, engine-meta.js; BFF contract published at .claude/documentation/contracts/finding-detail-bff-contract.md

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `inventory` + `threat` + `ciem` | C |
| UI / BFF / Gateway dev | `cspm-ui-dev` | R |
| Security architect (design) | `bmad-security-architect` | A |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-architect` (A) + `bmad-dev` + `bmad-agent-ux-designer` | R/A |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-2 (schema gate, end of D7) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1, every finding across 11 posture engines must reach a canonical detail URL `/finding/[engine]/[finding_id]`. ADR §3.3 explicitly rejects bespoke per-engine detail pages and modal-only detail. This story owns the Next.js route + the 5-tab template — the BFF that feeds it lives in JNY-06 (which depends on the page contract published here).

## What to build
1. New route file: `/Users/apple/Desktop/threat-engine/frontend/src/app/finding/[engine]/[id]/page.jsx`
2. 5-tab template per ADR §3.1:
   - `Overview` — finding header, severity, status, rule_id, resource_uid, first/last seen
   - `Resource Context` — slot for shared `AssetContextCard.jsx` keyed on `resource_uid`
   - `Related Findings` — table of other findings on same resource (cross-engine)
   - `Compliance` — frameworks/controls violated by this finding
   - `Remediation` — rule remediation text + status PATCH controls
3. Tab plugin pattern (per ADR §6.1): each engine may register additional tabs via a tabs map. Floor = 5 tabs.
4. Page contract document (consumed by JNY-06): `/Users/apple/Desktop/threat-engine/.claude/documentation/contracts/finding-detail-bff-contract.md` — exact request shape, field-level response schema.
5. Loading + error + empty states using the EngineShell primitives (placeholder components OK; JNY-11 hardens them).
6. Status PATCH wired to existing engine endpoints (no new write paths in BFF).

## Acceptance criteria
- [ ] `/finding/iam/abcd1234` renders 5 tabs even with empty data (no 4xx, no console error)
- [ ] Engine name validated against allowlist `{iam, network, datasec, encryption, container, dbsec, ai, ciem, check, threat, secops}`
- [ ] Page contract markdown published before JNY-06 dev starts
- [ ] AssetContextCard slot reused unchanged from prior sprint
- [ ] Middle-click and direct URL paste both work (server-rendered, no client-only routing dependency)
- [ ] Tab navigation does not refetch parent finding (one fetch on mount)
- [ ] Status PATCH writes go directly to `/api/v1/<engine>/findings/{id}/status` not BFF
- [ ] Tab plugin contract documented and exercised by at least one engine in this story (e.g. CIEM `Activity Heatmap` slotted)

## Dependencies
- Blocks: JNY-06, JNY-08, JNY-12
- Blocked by: JNY-01 (technique badge inside Overview), JNY-04 (deploy)

## Constitution check
- BFF for reads, engine endpoint for writes (status PATCH).
- No-fallback: when BFF returns `available: false`, the tab shows the unavailable state, not merged stale data.
- Standard columns only — page reads `finding_id`, `resource_uid`, `severity`, `status`, etc.
- Multi-tenant: page never accepts a `tenant_id` query param — derived from auth context.

## Out of scope
- BFF implementation (JNY-06).
- PivotLink component (JNY-07).
- Audit log on status PATCH (G-31, deferred per Sprint §7).
- Compliance per-control click-through (G-27, deferred).

## Files touched (estimate)
- `frontend/src/app/finding/[engine]/[id]/page.jsx` — new
- `frontend/src/app/finding/[engine]/[id]/tabs/Overview.jsx` — new
- `frontend/src/app/finding/[engine]/[id]/tabs/ResourceContext.jsx` — new
- `frontend/src/app/finding/[engine]/[id]/tabs/RelatedFindings.jsx` — new
- `frontend/src/app/finding/[engine]/[id]/tabs/Compliance.jsx` — new
- `frontend/src/app/finding/[engine]/[id]/tabs/Remediation.jsx` — new
- `frontend/src/lib/engineTabRegistry.js` — plugin pattern
- `.claude/documentation/contracts/finding-detail-bff-contract.md` — new

## Test plan
- Unit: tab registry returns 5 floor tabs + plugin tabs, dedup by id
- BFF contract: page consumes JNY-06 schema; mock fixture in `/__tests__/`
- UI smoke: navigate to `/finding/iam/<id>` from a row click (after JNY-08), verify all 5 tabs paint
- Security: invalid engine name → 404, not 500; cross-tenant id → 404
- E2E: a known IAM finding loads Resource Context with the asset's threats and CIEM data
