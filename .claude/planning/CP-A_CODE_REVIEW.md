# CP-A — Code Review (Phase A pre-deploy)

**Reviewer:** `cspm-code-reviewer`
**Verdict:** **PASS-WITH-MINOR — 0 blocking issues**
**Date:** 2026-05-05

## Per-rule findings (CSPM Constitution C-1..C-12)

| # | Rule | Status | Notes |
|---|---|---|---|
| C-1 | Standard columns on finding-table refs | PASS | `threat_findings` SELECTs in `technique_detail.py` use `tenant_id`, `status`, `mitre_technique`, `mitre_parent_technique`. Reference table exempt. |
| C-2 | No BFF fallback / fail-loud | PASS | `ciem_identity.py:142-149` returns canonical `_EMPTY` envelope on engine failure. `view_asset_ciem` 403s rather than fabricates. |
| C-3 | JSONB read as dict | PASS | `technique_detail.py:198` returns `dict(row)` from RealDictCursor. Loader's `json.loads()` is CSV-input validation only. |
| C-4 | tenant_id from auth_context only | PASS | `bff/inventory.py:769,781`, `bff/ciem_identity.py:98` — all via `resolve_tenant_id(request)`. |
| C-5 | Parameterized SQL | PASS | `_LOOKUP_SQL` uses `%(name)s`; `_UPSERT_SQL` uses `execute_values` template. |
| C-6 | ON CONFLICT explicit + deterministic | PASS | `load_mitre_reference.py:210` — legacy cols use `COALESCE(target, EXCLUDED)`; new cols use `EXCLUDED`. |
| C-7 | tenants upsert | N/A | Reference table — no tenant FK. |
| C-8 | Migrations idempotent | PASS | All `IF NOT EXISTS` / `DO $$ ... pg_constraint`; BEGIN/COMMIT wrapped; UPDATE backfills have re-run guards. |
| C-9 | No tenant_id on global reference | PASS | `threat_mitre_technique_ref_001.sql:20` documents the exemption. |
| C-10 | Audit logs JSON via named logger | PASS | `api-gateway.audit` logger; `_json.dumps(payload)`. No `print()`. |
| C-11 | strip_sensitive_fields | PASS-WITH-MINOR | `view_asset_ciem` is gated; raw findings flow through aggregation without explicit pop of `event_raw`/`credential_ref`. Defense-in-depth opportunity. |
| C-12 | Type hints + Google docstrings | PASS | All public functions typed; Google-style docstrings present. |

## Per-file findings (only flagged)

### `shared/api_gateway/bff/inventory.py` — PASS-WITH-MINOR
- **L753-905 `view_asset_ciem`**: aggregation loop at L832-852 reads raw CIEM finding dicts without first stripping `event_raw`/`credential_ref`. Safe today (gated + only aggregated fields returned), but mirror `ciem_identity.py:163-166` for defense-in-depth.
- L565-573 (JNY-02 stray-kwarg fix): clean.
- L706-750 (`_jny03_emit_ciem_audit`): correctly uses named logger and JSON payload.

### `engines/threat/scripts/load_mitre_reference.py` — PASS-WITH-MINOR
- L147, L156: `json.loads(raw)` is validate-only — add a one-line comment for future readers.
- L186 (`_to_bool` for `is_subtechnique`): no warning if CSV inconsistent (`parent_id` present but `is_subtechnique=false`).

### All other files — PASS

## Non-blocking suggestions (next sprint)

1. Defense-in-depth strip on `view_asset_ciem` raw findings (`bff/inventory.py:832`) — add `f.pop("event_raw", None); f.pop("credential_ref", None)`.
2. Loader sanity warning when `parent_id` set but `is_subtechnique=false`.
3. Validate-only `json.loads` comment in `_to_jsonb_or_*` helpers.
4. Audit emitter dedup — promote to `bff/_audit.py`.

## Cross-cutting checks
- No `scan_run_id` shape changes
- No `print()` calls
- No bare `except:` (specific `psycopg2.OperationalError`/`DatabaseError`; `Exception` only at startup hook with logging)
- No hardcoded credentials
- CSV SHA-256-verified before parse; fails loud on mismatch
- No constitution violations re: BFF data fabrication or cross-tenant leak

## Verdict (final)

**PASS-WITH-MINOR — 0 blocking. May proceed to deploy after security + QA gates.**

Top concern: defense-in-depth strip on `view_asset_ciem` raw findings (track in next sprint).
