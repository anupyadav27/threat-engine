# TODO — BFF/UI read layer: findings not surfacing after real-account scan

**Status as of 2026-05-31:** Pipeline engines validated end-to-end against a real AWS
account (588989875114, tenant `d39a5675-daab-4025-b685-334ba79148f3`). Engines write
findings correctly. The gap is the **BFF/UI read layer** pointing at the wrong tables.

## What works (verified)

Full CSPM pipeline completed (9/9 engines) and wrote real findings:

| Table | Database | Count for scan `d803c480-f41b-453c-bbc4-4d67ecc62f1e` |
|-------|----------|------|
| `check_findings` | check db | 3,961 (9 critical, 687 high, 3,253 medium, 10 low) |
| `security_findings` | DI db (`threat_engine_di`) | 8,220 |
| `iam_findings` | iam db | 102 |

The `account_id` mismatch fixes (DI stores AWS account number, callers pass internal
UUID) are deployed for check/iam/datasec/network di_readers and their scanner job images.

## What's broken (BFF/UI read layer — fix next)

### 1. Misconfig page shows 0 despite 3,961 findings
- `shared/api_gateway/bff/misconfig.py:75` reads from the **threat engine**
  `/api/v1/threat/ui-data`, which queries the **`attack_paths`** table
  (`threat_engine_attack_path` db).
- `attack_paths` has **0 rows** for a fresh account (no computed attack chains), so
  both the Overview and All Findings tabs show 0.
- The real misconfigurations live in `check_findings` / DI `security_findings`.
- **Fix:** rewire `misconfig.py` to read check findings (check engine
  `/api/v1/check/findings` or DI `security_findings`) for the misconfig list, and keep
  `attack_paths` only for the attack-path views.

### 2. Dashboard 500 → "Internal server error — showing demo data"
- `shared/api_gateway/bff/dashboard.py:128` aggregates 7 engine `ui-data` endpoints.
- One endpoint errors → the whole dashboard 500s → falls back to mock data.
- **Fix:** identify the failing endpoint (wrap each in try/except so one failure
  doesn't blank the whole dashboard); confirm each engine's `/ui-data` returns for the
  new tenant.

### 3. Tenant dropdown missing "Ajay's Org"
- The scope selector lists `anup's Organization` and `Test Tenant 002` but not
  `Ajay's Org` (`d39a5675`, customer `521fd295`) even though it shares the same
  customer as `my-tenant` which IS shown.
- **Fix:** check the tenant-list BFF / customer-scoping query that powers the dropdown.

## Notes / gotchas confirmed this session
- BFF resolves tenant via `x-active-tenant-id` header; platform_admin defaults to
  "All Tenants" (tenant_id=None). See `shared/api_gateway/bff/_auth.py:resolve_tenant_id`.
- `/api/v1/threat/ui-data` requires `attack_path:read` permission (not `threat:read`).
- This is a read-layer fix only — gateway redeploy, no engine pod restarts needed.

## Separately pending (not BFF)
- **SecOps OOMKilled** at 1Gi during large-repo scan — bump memory limit or move scan
  to a K8s Job like the other engines (`kubectl set resources deployment/engine-secops
  --limits=memory=3Gi`).
- **Vulnerability agent** — set shared `X_INTERNAL_SECRET` on engine-onboarding +
  engine-vulnerability so `/api/v1/agents/register` → onboarding `validate-token`
  succeeds (currently 401, empty secret). Agent scripts now auto-register
  (`register_with_vulnerability_engine`) and are uploaded to
  `s3://cspm-vulnerability-agent/agents/latest/<platform>/onam-agent.py` (public).
