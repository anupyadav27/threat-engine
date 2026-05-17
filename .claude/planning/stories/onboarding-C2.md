---
id: onboarding-C2
title: "Fix scan_runs→scan_orchestration (3 files) + CDR reference + delete credentials.py"
sprint: C
points: 0.5
depends_on: [onboarding-C1]
blocks: [onboarding-C6, onboarding-C7, onboarding-C9]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-09
---

## Context

This is a targeted bug-fix story covering BUG-01, BUG-02, BUG-03, BUG-06, and the security-critical deletion of `credentials.py` (BUG-04 precursor). Three onboarding engine files contain SQL references to `scan_runs` — a table that does not exist. The correct table is `scan_orchestration`. These bugs cause every scan pipeline trigger to fail silently. Additionally, `engines/onboarding/orchestrator/engine_orchestrator.py` has a hardcoded `engine-ciem` reference that was supposed to be updated to `engine-cdr` during the CDR rename sprint but was missed (BUG-06). Finally, `engines/onboarding/api/credentials.py` is a legacy router with zero authentication on store/validate/delete credential endpoints (BUG-04 — SECURITY CRITICAL) — this file must be deleted entirely, with all credential routes verified as either unused or migrated into `cloud_accounts.py` (which will get auth in onboarding-C3). This story is purely code changes — no schema changes, no new endpoints.

## Acceptance Criteria

- [ ] AC1 (BUG-01): `engines/onboarding/database/scan_run_operations.py` contains zero references to `scan_runs` table name in any SQL string.
- [ ] AC2 (BUG-02): `engines/onboarding/api/scans.py` contains zero references to `scan_runs` table name in any SQL string.
- [ ] AC3 (BUG-03): `engines/onboarding/api/ui_data_router.py` contains zero references to `scan_runs` table name in any SQL string.
- [ ] AC4: All three files use `scan_orchestration` in all SQL INSERT/SELECT/UPDATE statements.
- [ ] AC5 (BUG-06): `engines/onboarding/orchestrator/engine_orchestrator.py` has no reference to `engine-ciem` — all occurrences replaced with `engine-cdr`.
- [ ] AC6 (BUG-04): `engines/onboarding/api/credentials.py` is DELETED from the filesystem. No import of it remains in `main.py` or any router registration file.
- [ ] AC7: After deleting `credentials.py`, the FastAPI app starts without import errors (`GET /api/v1/health/live` returns 200).
- [ ] AC8: Verification grep returns no hits: `grep -r "scan_runs" engines/onboarding/ --include="*.py"` → empty.
- [ ] AC9: Verification grep returns no hits: `grep -r "engine-ciem" engines/onboarding/ --include="*.py"` → empty.
- [ ] AC10: Verification grep returns no hits: `grep -r "credentials" engines/onboarding/main.py` — the router import/include is gone.

## Key Files

- `engines/onboarding/database/scan_run_operations.py` — Replace `scan_runs` with `scan_orchestration` (BUG-01)
- `engines/onboarding/api/scans.py` — Replace `scan_runs` with `scan_orchestration` (BUG-02)
- `engines/onboarding/api/ui_data_router.py` — Replace `scan_runs` with `scan_orchestration` (BUG-03)
- `engines/onboarding/orchestrator/engine_orchestrator.py` — Replace `engine-ciem` with `engine-cdr` (BUG-06)
- `engines/onboarding/api/credentials.py` — DELETE this file (BUG-04)
- `engines/onboarding/main.py` — Remove `credentials` router include

## Technical Notes

**Step 1 — Find all occurrences to fix:**
```bash
grep -rn "scan_runs" /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py"
grep -rn "engine-ciem" /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py"
grep -rn "credentials" /Users/apple/Desktop/threat-engine/engines/onboarding/main.py
```

**Step 2 — Replace scan_runs with scan_orchestration:**
The replacement must be exact and context-aware. Example patterns to replace:
```python
# BEFORE:
"INSERT INTO scan_runs ..."
"SELECT * FROM scan_runs ..."
"UPDATE scan_runs SET ..."
# FROM scan_runs WHERE

# AFTER: use scan_orchestration in all cases
"INSERT INTO scan_orchestration ..."
```

**Step 3 — Fix CDR reference in orchestrator:**
```bash
grep -n "engine-ciem\|engine-cdr" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/orchestrator/engine_orchestrator.py
```
Replace every `engine-ciem` with `engine-cdr` — this is the Kubernetes service name used to construct health-check URLs.

**Step 4 — Delete credentials.py safely:**
Before deleting, verify what routes it registers:
```bash
grep -n "router\|@router\|APIRouter" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/api/credentials.py
```
If any route in `credentials.py` is NOT already present in `cloud_accounts.py`, note it — the architecture decision is to delete credentials.py and ensure its routes (with auth) are in cloud_accounts.py. Do NOT carry forward unauthenticated routes.

```bash
# Delete the file
rm /Users/apple/Desktop/threat-engine/engines/onboarding/api/credentials.py

# Remove its include from main.py
grep -n "credentials" /Users/apple/Desktop/threat-engine/engines/onboarding/main.py
# Remove the corresponding app.include_router() line
```

**Step 5 — Verify engine starts:**
```bash
# After deploying new image, check health endpoint
kubectl logs -l app=engine-onboarding -n threat-engine-engines --tail=50 | grep -E "ERROR|startup|Application"
```

**scan_orchestration column reference:** The table has columns `scan_run_id`, `tenant_id`, `account_id`, `status`, `engines_requested`, `engines_completed`, `created_at`, `updated_at`. The `engines_requested` and `engines_completed` columns are JSONB — already dict when read from psycopg2, do NOT call `json.loads()`.

**Final verification grep (must all return empty):**
```bash
grep -r "scan_runs" /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py"
grep -r "engine-ciem" /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py"
```

## Security Checklist

- [ ] `credentials.py` deleted — zero unauthenticated credential endpoints remain
- [ ] No new endpoints introduced in this story
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge (critical — deletion of zero-auth router)

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "scan_runs" engines/onboarding/ --include="*.py"` → empty output
- [ ] `grep -r "engine-ciem" engines/onboarding/ --include="*.py"` → empty output
- [ ] `engines/onboarding/api/credentials.py` does not exist on filesystem
- [ ] Engine health endpoint returns 200 after deploy
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s