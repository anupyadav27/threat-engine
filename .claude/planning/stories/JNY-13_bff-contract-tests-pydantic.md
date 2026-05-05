# JNY-13: BFF Layer 1 (black-box) + Layer 2 (Pydantic models) — all 53 BFF views

## Track
Investigation Journey Unification — Phase H

## Priority
P1 — Closes the silent contract-drift hole between BFF and UI; required before JNY-14 can diff anything meaningful.

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
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | `bmad-qa` | A |
| QA | `bmad-qa` + `cspm-qa-engineer` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-2 (schema gate, end of D7) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 (G-2, G-32, G-33) and ADR §3.1.b, BFF views currently return raw `dict` payloads with no FastAPI `response_model`. This means:
- Shape regressions (renamed keys, dropped fields, type flips) reach the UI silently.
- `/gateway/openapi.json` is near-empty — no schema for downstream codegen or contract diff.
- Layer 1 (black-box hit-every-endpoint) and Layer 2 (Pydantic validation at runtime) of the ADR's five-layer test stack do not exist.

This story builds Layers 1 + 2. JNY-14 then consumes the resulting Pydantic schema set for the UI contract diff (Layer 3+4).

## What to build

1. Pydantic response models — `/Users/apple/Desktop/threat-engine/shared/api_gateway/bff/_schemas.py`
   - One `BaseModel` per BFF view (53 total). Group by engine: `InventoryAssetView`, `InventoryAssetBlastRadiusView`, `InventoryAssetCiemView`, `ThreatsListView`, `ThreatDetailView`, `ThreatsTechniqueView`, `CiemIdentitiesView`, `IamFindingsView`, `ComplianceFrameworkView`, etc.
   - Use `model_config = ConfigDict(extra="forbid")` so unknown keys fail validation in tests.
2. Decorator wiring — every `bff/*.py` `@router.get(...)` gets `response_model=...`:
   ```python
   from shared.api_gateway.bff._schemas import InventoryAssetBlastRadiusView

   @router.get("/views/inventory/asset/{uid}/blast-radius",
               response_model=InventoryAssetBlastRadiusView)
   async def asset_blast_radius(uid: str, ...): ...
   ```
3. Black-box test — `/Users/apple/Desktop/threat-engine/tests/bff/test_all_endpoints.py`
   - Parametrize on (endpoint, input_variant) — 53 endpoints × 5 input variants ≈ 265 cases.
   - Variants: happy path (real `scan_run_id` + tenant), unknown id (404 expected), missing required query param (422 expected), tenant mismatch (403/empty), oversized id (422).
   - Asserts: status code, Content-Type=application/json, body validates against the registered Pydantic model.
4. OpenAPI snapshot test — `tests/bff/test_openapi_snapshot.py` asserts `len(spec["paths"]) >= 53` and `/gateway/openapi.json` body size > 50 KB.
5. CI hook — add `pytest tests/bff/` to `.github/workflows/ci.yml` (or existing pipeline) before `cspm-deploy`.

## Acceptance criteria
- [ ] `shared/api_gateway/bff/_schemas.py` exists and exports a `BaseModel` for every one of the 53 BFF views (enumerated list in module docstring).
- [ ] Every `@router.get` in `shared/api_gateway/bff/*.py` declares `response_model=...`; grep `response_model=` count == 53.
- [ ] No BFF endpoint returns a bare `dict` — `mypy` or AST grep confirms.
- [ ] `pytest tests/bff/test_all_endpoints.py -v` passes with ≥ 265 parametrized cases.
- [ ] `GET /gateway/openapi.json` returns a body > 50 KB (verifies non-trivial schemas).
- [ ] `extra="forbid"` flushes out any field the BFF returns but the schema doesn't declare — fail-loud, not silent.
- [ ] CI runs `tests/bff/` on every PR; failing schema validation blocks merge.
- [ ] No tenant cross-leak: tenant-mismatch variant returns empty/403, never a populated body for the wrong tenant.

## Dependencies
- Blocks: JNY-14 (needs the Pydantic schema set), JNY-17 (new BFF views must conform), JNY-18 (constitution gate references this).
- Blocked by: none — runs in parallel with JNY-15.

## Constitution check
- DB-first: schemas describe DB-derived shapes; no fallbacks added.
- BFF-only contract (ADR §3.1.c): this story is the prerequisite enforcement layer for the rule.
- No BFF fallbacks: schemas formalize current shapes including `available: false` graceful-degradation pattern; do not add fallback fields.

## Out of scope
- Renaming or restructuring existing BFF response shapes (snapshot the current contract first; refactor in a follow-up).
- Engine-side schemas (covered by JNY-15).
- UI-side consumption diff (covered by JNY-14).
- Backwards-compat versioning of BFF responses.

## Files touched (estimate)
- `shared/api_gateway/bff/_schemas.py` — new (~600 lines)
- `shared/api_gateway/bff/inventory.py`, `threat.py`, `ciem.py`, `iam.py`, `datasec.py`, `compliance.py`, `risk.py`, `cnapp.py`, `cwpp.py`, `network.py`, `encryption.py`, `container_security.py`, `dbsec.py`, `ai_security.py`, `secops.py`, `vulnerability.py`, `onboarding.py`, `asset_context.py`, `technique_detail.py`, `ciem_identity.py` — add `response_model=` per route
- `tests/bff/test_all_endpoints.py` — new
- `tests/bff/test_openapi_snapshot.py` — new
- `tests/bff/conftest.py` — fixtures: gateway base URL, tenant id, sample `scan_run_id` per CSP
- `.github/workflows/ci.yml` — add pytest step

## Test plan
- Unit: each Pydantic model round-trips a hand-crafted sample dict (`Model.model_validate(sample)`).
- Integration (Layer 1): pytest matrix hits live gateway service in cluster (or port-forwarded `8000:80`), 265 cases, all green.
- Schema (Layer 2): FastAPI `response_model` raises `ResponseValidationError` on shape drift — verified by deliberately mutating one BFF return in a throwaway branch.
- Security: tenant-mismatch test variant must not leak data; oversized-id variant must 422 not 500.
- Performance: full matrix completes in < 90 s.
- Regression: snapshot test fails if `paths` count or schema size shrinks.
