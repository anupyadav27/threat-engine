# JNY-06: Universal BFF — `GET /api/v1/views/finding/{engine}/{id}`

## Track
Investigation Journey Unification — Phase B

## Priority
P0 — Backs JNY-05's universal route; without it the 5-tab template paints empty for every engine (G-20).

## Status
draft

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | all 11 engine agents | C |
| UI / BFF / Gateway dev | `cspm-bff-dev` | R |
| Security architect (design) | `bmad-security-architect` | A |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-2 (schema gate, end of D7) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1 + Sprint §6 risk mitigation, the BFF must read 11 different finding tables (`iam_findings`, `network_findings`, `datasec_findings`, `encryption_findings`, `container_sec_findings`, `dbsec_findings`, `ai_security_findings`, `ciem_findings`, `check_findings`, `threat_findings`, secops findings) using ONLY standard columns guaranteed by CSPM_CONSTITUTION §Database. Per-engine specifics surface via `finding_data` JSONB.

## What to build
1. New BFF view handler: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/views/finding_detail.py`
2. Engine→table map: `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/views/_finding_engine_map.py`
3. Response envelope (per JNY-05 contract):
   ```json
   {
     "engine": "iam",
     "finding": { "finding_id": "...", "rule_id": "...", "resource_uid": "...", "severity": "...", "status": "...", "first_seen_at": "...", "last_seen_at": "...", "title": "...", "description": "...", "finding_data": {...} },
     "resource_context": { ... asset_context envelope ... },
     "related_findings": [ { engine, finding_id, severity, rule_id, title } ],
     "compliance": [ { framework, control_id, control_name, status } ],
     "remediation": { rule_remediation_text, references }
   }
   ```
4. Reuse existing `asset_context` aggregator for `resource_context`.
5. `related_findings` query: cross-engine SELECT WHERE `resource_uid = $1 AND tenant_id = $2 AND finding_id != $3` LIMIT 100, fanned out per engine DB.
6. `compliance` lookup via `rule_control_mapping` join in check DB.
7. Per-engine timeout (2s) + graceful `available: false` shape (no fallback, no merge).

## Acceptance criteria
- [ ] Endpoint returns 200 with envelope for any (engine, finding_id) where the finding exists
- [ ] 404 (not 500) when finding_id doesn't exist for that engine
- [ ] Tenant isolation enforced — request for another tenant's finding returns 404
- [ ] Reads only standard columns + `finding_data` JSONB; new fields land via JSONB never new SQL columns
- [ ] `related_findings` sorted by severity DESC, capped at 100
- [ ] Each fan-out call has 2s timeout; failures surface as `available: false` per engine, never silent merge
- [ ] p95 < 2.5s on a finding with 10 related findings
- [ ] Engine allowlist mirrors JNY-05 page allowlist exactly
- [ ] OpenAPI spec generated and visible at `/docs`

## Dependencies
- Blocks: JNY-08 (row click destinations need data), JNY-12 (risk/vuln pages reuse this contract shape)
- Blocked by: JNY-05 (page contract), JNY-04 (deploy)

## Constitution check
- No BFF fallback / data merge — `available: false` per engine on failure.
- Standard columns only; finding_data JSONB for engine-specific extras.
- Tenant_id MANDATORY in every WHERE clause.
- Reads in BFF; writes (status PATCH) go to engine endpoints.
- credential_ref / credential_type never echoed in response.

## Out of scope
- Audit logging of status changes (G-31 deferred).
- Batched attack chain enrichment (G-26 deferred per Sprint §7).
- Caching layer.

## Files touched (estimate)
- `shared/api_gateway/bff/views/finding_detail.py` — new
- `shared/api_gateway/bff/views/_finding_engine_map.py` — new
- `shared/api_gateway/bff/router.py` — register route `/api/v1/views/finding/{engine}/{id}`
- `shared/api_gateway/tests/test_finding_detail.py` — new
- `.claude/documentation/API-REFERENCE.md` — new endpoint entry

## Test plan
- Unit: each engine map entry resolves to correct DB + table
- BFF contract: assert response matches JNY-05 contract markdown schema
- Security: cross-tenant request returns 404; `bmad-security-reviewer` runs SQLi + tenant-isolation pass
- Integration: hit endpoint for an iam, network, datasec finding from a fresh scan; assert non-empty related_findings on shared resource
- Performance: 100 concurrent calls, p95 < 2.5s
