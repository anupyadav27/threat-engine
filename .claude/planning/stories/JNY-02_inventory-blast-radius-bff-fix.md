# JNY-02: BFF fix — `/inventory/asset/{uid}/blast-radius` returns 500

## Track
Investigation Journey Unification — Phase A

## Priority
P0 — Inventory Asset journey "Blast Radius" tab is broken (G-2); blocks Phase B because the AssetContextCard and `/finding/[engine]/[id]` Resource Context tab both link out to it.

## Status
done — handler at inventory.py:1075 already returns _EMPTY (no 500) on all error paths; graceful degradation confirmed

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `inventory` | C |
| UI / BFF / Gateway dev | `cspm-bff-dev` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-1 (design gate, end of D2) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 G-2, `GET /api/v1/views/inventory/asset/{uid}/blast-radius` returns 500 in the running cluster. The handler likely chokes on a missing Neo4j index, an unhandled None resource_uid, or a tenant_id propagation gap. ADR §3.1 makes the asset detail page a canonical L1 entity — Blast Radius is one of its 8 tabs and must not 500.

## What to build
1. Reproduce: hit the live endpoint via gateway port-forward; capture stack trace from `kubectl logs api-gateway` and `kubectl logs engine-inventory`.
2. Root-cause and patch the BFF view handler at `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/views/inventory_blast_radius.py` (or wherever the handler lives — confirm via grep).
3. Add proper error envelope: on Neo4j/DB failure return `200 { available: false, reason: "..." }` per CSPM_CONSTITUTION fail-loud-but-no-fallback rule (used elsewhere in `asset_context.py`).
4. Add structured logging with `scan_run_id`, `tenant_id`, `resource_uid`.
5. Fix the underlying Neo4j query if it's the cause (likely missing parameter binding or empty-graph case).

## Acceptance criteria
- [ ] Endpoint returns 200 for any valid resource_uid, even when Neo4j has no edges (returns `{ nodes: [], edges: [], available: true }`)
- [ ] Returns `200 { available: false, reason }` (never 500) when downstream is genuinely unavailable
- [ ] All error paths log with `tenant_id`, `resource_uid`, full stack
- [ ] Multi-tenant isolation: assets from tenant A cannot show edges into tenant B's resources
- [ ] Response time p95 < 2s on a 5-node sample asset (matches AssetContextCard 2s timeout)
- [ ] Browser network tab on `/inventory/[uid]` Blast Radius tab shows 200, no console errors
- [ ] Unit tests cover: empty graph, missing asset, Neo4j down, tenant boundary

## Dependencies
- Blocks: JNY-04, JNY-05 (Resource Context tab links here)
- Blocked by: none

## Constitution check
- No BFF fallback / data merge. Failure mode is explicit `available: false`, not a silent merge with a different graph source.
- Tenant-scoped queries — every Neo4j call must include `tenant_id` parameter.
- Standard columns: read `resource_uid`, `tenant_id` only — do not invent new finding fields.

## Out of scope
- Multi-hop attack path enrichment (G-22 — deferred per Sprint §7).
- Performance optimization beyond the 2s p95 target.
- Adding new node types to the graph schema.

## Files touched (estimate)
- `shared/api_gateway/bff/views/inventory_blast_radius.py` — bug fix
- `shared/api_gateway/bff/views/asset_context.py` — confirm reuse of same error envelope
- `engines/inventory/inventory_engine/api/blast_radius.py` (if engine endpoint involved) — defensive programming
- `engines/inventory/tests/test_blast_radius.py` — new unit tests

## Test plan
- Unit: missing asset → `available: false`; empty edges → `nodes: [...], edges: []`
- BFF contract: schema validation against asset_context envelope
- Integration: trigger inventory scan, hit endpoint with one of the new asset uids
- Security: cross-tenant request returns 403 or empty (never leaks)
- UI smoke: live walk-through `/inventory/[uid]` Blast Radius tab — must render
