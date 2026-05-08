# STORY-ENG-SECOPS-FINDING-TABLE

## Track
Engine — SecOps Finding Table Confirmation (spin-off from JNY-06 / CP-2 B4)

## Priority
P2 — blocks SecOps engine support in the universal `/finding/[engine]/[id]` route. Phase B ships without SecOps support; Phase C closes the gap.

## Status
draft

## Context (from CP-2 schema gate)

JNY-06 design discovered that 9 of 11 posture engines have **no `get_<engine>_conn()` DB connection helper documented** in `shared/common/db_connections.py`, and SecOps in particular has **no canonical singular-finding endpoint**. The engine returns findings only via `GET /api/v1/secops/scan/{scan_id}/findings` (list scoped to scan), not by `finding_id`. To support SecOps in the universal finding route, we need:

1. Confirmation of the canonical SecOps findings table name (likely `secops_findings`).
2. Verification that the table has all 14 standard columns (per CSPM_CONSTITUTION §2.2).
3. A new `get_secops_conn()` helper in `shared/common/db_connections.py` matching the existing per-engine pattern.
4. (Optional, recommended) A new `GET /api/v1/secops/findings/{finding_id}` endpoint on the SecOps engine for symmetry with `threat`/`ciem`. BFF can DB-direct without it, but the endpoint makes engine-direct integration tests possible.

## What to build

1. Inspect `engines/secops/` source (`secops_fix/`, `sast_engine/`, etc.) to identify which DB tables hold finding rows.
2. Document the canonical schema (column-by-column) in `shared/database/schemas/secops_schema.sql` if not already present.
3. Add `get_secops_conn()` to `shared/common/db_connections.py` following the pattern of `get_check_conn()` etc.
4. Update `shared/api_gateway/bff/views/_finding_engine_map.py` (added by JNY-06) to register `secops` with its conn helper, table name, and `secops:read` permission.
5. Remove the 501 short-circuit in JNY-06 BFF for `secops`.
6. Add an integration test that fetches a real SecOps finding by id via the universal endpoint.

## Acceptance criteria

- [ ] `get_secops_conn()` exists, returns a psycopg2 connection to the SecOps DB.
- [ ] `_finding_engine_map.py` includes `secops` with valid table name + permission.
- [ ] `GET /api/v1/views/finding/secops/{id}` returns 200 with the standard `FindingDetailResponse` shape.
- [ ] All 14 standard columns are populated in the response.
- [ ] JNY-07 PivotLink is updated to remove the secops-hide guard.
- [ ] CSPM_CONSTITUTION §2.2 standard-columns check passes for the SecOps finding table.

## Dependencies

- Blocks: full Phase C SecOps support in universal finding route.
- Blocked by: none. Can run anytime after JNY-06 lands.

## Owner
- CSPM lead: `cspm-secops-engineer` (R)
- BMad lead: `bmad-dev`
- Quality gate: standard chain.

## Out of scope
- Refactoring the SecOps scan/finding ingestion pipeline.
- Migrating SecOps to a unified findings schema if it currently uses a non-standard shape (separate larger story).
