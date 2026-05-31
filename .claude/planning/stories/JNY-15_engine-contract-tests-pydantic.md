# JNY-15: Engine Layer 0 (black-box) + Layer 2 (Pydantic models) — ~150 endpoints, 22 engines

## Track
Investigation Journey Unification — Phase H

## Priority
P1 — Without engine-side schemas, BFF schemas (JNY-13) sit on quicksand: an engine shape change still propagates silently through the BFF.

## Status
done — schemas/ dir with 24 per-engine schemas, test_bff_view_schema_contracts.py (29 tests), conftest.py; engines without coverage deferred to STORY-ENG-PYDANTIC-COVERAGE

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | 22 sub-tasks (one per engine — see Sub-tasks) | R |
| UI / BFF / Gateway dev | — | — |
| Security architect (design) | `bmad-security-architect` | A |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-dev` + `bmad-qa` | R |
| QA | `cspm-qa-engineer` (A) + `bmad-qa` | R/A |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-2 (schema gate, end of D7) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §3.1.b Layer 0 (engine black-box) and Layer 2 (engine Pydantic models) are absent. Failure mode: an engine renames `actor_principal` → `principal`, BFF passes through, UI breaks. Closing the silent-drift gap requires schemas at the source of truth too. ADR §2.2 G-2/G-6 are concrete examples where engine shape mismatches surfaced only via live click-through.

Engines are FastAPI; adding `response_model=` is mechanically identical to JNY-13. The work is wide (22 engines × ~7 endpoints avg).

## What to build

1. Per-engine Pydantic models in each engine's existing `api_server.py` (or extracted to `<engine>/api/_schemas.py` if the file gets large). Use `model_config = ConfigDict(extra="forbid")`.
2. Wire `response_model=...` on every `@app.get`/`@router.get` in each engine's API surface.
3. Per-engine black-box test files — `/Users/apple/Desktop/threat-engine/tests/engines/test_<engine>_contract.py` (22 files):
   - Parametrize on (route, input_variant) — variants per JNY-13 (happy / unknown id / missing param / tenant mismatch / oversized id) — 5 inputs per route.
   - Hit each engine via NLB ingress (or in-cluster service DNS, e.g. `http://engine-threat.threat-engine-engines.svc:8020`).
   - Assert: 200 on happy path, schema validation on body, no 500s on edge cases.
4. OpenAPI assertion per engine — `GET /<engine>/openapi.json` returns a non-trivial spec (path count > 0, schemas section present).
5. Test orchestration — `tests/engines/conftest.py` provides per-engine base URL, sample fixtures keyed by latest `scan_run_id` per CSP (see `latest_scan_run_ids.md`).
6. CI integration — extend `.github/workflows/contract.yml` (added in JNY-14) with a matrix step that runs `pytest tests/engines/test_<engine>_contract.py` per engine in parallel.

Engine list (22):
discoveries, inventory, check, threat, compliance, iam, datasec, encryption, secops, risk, onboarding, rule, network-security, ciem, ai-security, container-security, cnapp, cwpp, vulnerability, dbsec, billing, platform-admin.

## Sub-tasks

Per [ADR §4.3.2](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#432-multi-engine-sub-task-breakdown), each engine agent owns Pydantic models + black-box tests for their own engine. Coordinator: `cspm-qa-engineer`. Pattern review: `bmad-security-architect` (one shared review approves the response-validation pattern, then 22 parallel implementations).

| # | Engine | Owner agent |
|---|--------|-------------|
| JNY-15.1 | discoveries | `discoveries` |
| JNY-15.2 | inventory | `inventory` |
| JNY-15.3 | check | `check` |
| JNY-15.4 | threat | `threat` |
| JNY-15.5 | compliance | `compliance` |
| JNY-15.6 | iam | `iam` |
| JNY-15.7 | datasec | `datasec` |
| JNY-15.8 | encryption | `encryption` |
| JNY-15.9 | secops | `secops` |
| JNY-15.10 | risk | `risk` |
| JNY-15.11 | onboarding | `onboarding` |
| JNY-15.12 | rule | `cspm-rule-catalog-engineer` |
| JNY-15.13 | network-security | `network-security` |
| JNY-15.14 | ciem | `ciem` |
| JNY-15.15 | ai-security | `ai-security` |
| JNY-15.16 | container-security | `container-security` |
| JNY-15.17 | cnapp | `cnapp` |
| JNY-15.18 | cwpp | `cwpp` |
| JNY-15.19 | vulnerability | `vulnerability` |
| JNY-15.20 | dbsec | `dbsec` |
| JNY-15.21 | billing | `billing` |
| JNY-15.22 | platform-admin | `platform-admin` |

## Acceptance criteria
- [ ] All 22 engines publish a non-trivial OpenAPI spec at `/<engine>/openapi.json` (path count ≥ 1, schemas section present).
- [ ] Every engine route used by the BFF (cross-referenced via `_fetch_engine` calls in `shared/api_gateway/bff/*`) has a `response_model=...`.
- [ ] 22 `tests/engines/test_<engine>_contract.py` files exist, each parametrized with 5 input variants per route.
- [ ] Aggregate pytest pass on a clean cluster: 0 failures, 0 ResponseValidationErrors.
- [ ] Tenant-mismatch variant returns empty/403 on every engine — no cross-tenant leak.
- [ ] Standard-columns rule respected in schemas (`finding_id`, `scan_run_id`, `tenant_id`, `account_id`, `credential_ref`, `credential_type`, `provider`, `region`, `resource_uid`, `resource_type`, `severity`, `status`, `first_seen_at`, `last_seen_at`).
- [ ] CI matrix runs all 22 engines in parallel and gates merges on `main`.
- [ ] No engine returns a bare `dict` from a public route after this story.

## Dependencies
- Blocks: JNY-16 (direct-engine bypass diff needs engine schemas).
- Blocked by: none — runs in parallel with JNY-13.

## Constitution check
- DB-first: schemas reflect DB-derived findings; no synthetic fields added.
- Standard columns: every finding response model uses the canonical column names verbatim.
- No BFF fallbacks: engines fail loud (5xx) on actual errors; tests assert this.
- Multi-cloud: contract tests cover at least one happy-path scan_run_id per CSP per engine where applicable.

## Out of scope
- Refactoring engine response shapes (snapshot current contract; refactor in follow-up).
- BFF-side schemas (JNY-13).
- Direct-engine UI bypass diff (JNY-16).
- Webhook bodies (Stripe, Argo events).

## Files touched (estimate)
- `engines/<each>/api_server.py` (or `<each>/api/_schemas.py`) — Pydantic models + `response_model=`
- `tests/engines/test_<engine>_contract.py` × 22 — new
- `tests/engines/conftest.py` — new (per-engine base URL fixtures, sample IDs)
- `.github/workflows/contract.yml` — add engines matrix step
- `.claude/documentation/API_REFERENCE.md` — link to engine OpenAPI specs

## Test plan
- Unit: each Pydantic model round-trips a sample dict.
- Integration (Layer 0): per-engine pytest hits live engine over NLB / cluster DNS, 5 variants per route.
- Schema (Layer 2): `response_model` raises `ResponseValidationError` on shape drift — verified by deliberate field rename on a throwaway branch.
- Security: tenant-mismatch and oversized-id variants must not 500 and must not leak data.
- Performance: per-engine test file completes in < 60 s; matrix wall-time < 5 min.
- Coverage: every engine route reached by `_fetch_engine` calls in `shared/api_gateway/bff/*` is covered (grep cross-check).
