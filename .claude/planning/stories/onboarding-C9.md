---
id: onboarding-C9
title: "Bulk run-all schedules endpoint"
sprint: C
points: 1
depends_on: [onboarding-C6]
blocks: [onboarding-D11]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-14
---

## Context

Gap S-05: There is no bulk scan trigger endpoint. Org admins need to be able to trigger all active accounts in a tenant with a single call — useful for after credential rotation, emergency rescan, or end-of-quarter compliance sweeps. The architecture defines `POST /api/v1/scans/run-all` which iterates all active, valid accounts for the caller's `tenant_id`, triggers a scan for each (identical to C7's run-now logic per account), and returns a structured response with triggered and skipped accounts. This endpoint requires `scans:create` permission AND the caller must be `org_admin` or `platform_admin` (not available to `tenant_admin` or `analyst`). The endpoint must be in a separate router file `engines/onboarding/routers/bulk_scans.py`.

## Acceptance Criteria

- [ ] AC1 (S-05): `POST /api/v1/scans/run-all` endpoint exists in `engines/onboarding/routers/bulk_scans.py`.
- [ ] AC2: Endpoint requires `Depends(require_permission("scans:create"))` AND caller must be `org_admin` or `platform_admin` role — `tenant_admin` receives HTTP 403.
- [ ] AC3: Request body: `{"tenant_id": "<tid>"}` — BUT the engine validates that the body `tenant_id` matches `auth.tenant_id` for `org_admin` role (platform_admin may pass any tenant_id).
- [ ] AC4: Queries all `cloud_accounts` WHERE `tenant_id = auth.tenant_id` AND `validation_status = 'pass'` AND `account_status != 'INACTIVE'`.
- [ ] AC5: For each qualifying account, calls the same scan submission logic as C7's run-now (creates `scan_orchestration` row + submits Argo pipeline).
- [ ] AC6: Accounts with `validation_status != 'pass'` OR `account_status = 'INACTIVE'` are added to the `skipped` list with `reason`.
- [ ] AC7: Response HTTP 202:
  ```json
  {
    "triggered": [{"account_id": "...", "scan_run_id": "..."}],
    "skipped": [{"account_id": "...", "reason": "INACTIVE credential"}]
  }
  ```
- [ ] AC8: If zero accounts are active, returns 202 with `triggered: []` and `skipped: [...]` — not an error.
- [ ] AC9: Each account's scan is triggered independently — failure of one scan submission does not abort the rest. Failed submissions are added to `skipped` with `reason: "submission_error"`.
- [ ] AC10: Unit tests: org_admin triggers all valid accounts; tenant_admin gets 403; INACTIVE account is skipped; mixed scenario returns correct triggered/skipped split.

## Key Files

- `engines/onboarding/routers/bulk_scans.py` — Create this file with the run-all endpoint
- `engines/onboarding/main.py` — Register the bulk_scans router
- `engines/onboarding/database/cloud_accounts_operations.py` — Add `get_active_accounts_for_tenant()` query

## Technical Notes

**New router file:**
```python
# routers/bulk_scans.py
from fastapi import APIRouter, Depends, HTTPException
from engine_common.auth import require_permission, AuthContext

router = APIRouter(prefix="/api/v1/scans", tags=["bulk-scans"])
```

**Role check beyond permission — verify org_admin or platform_admin:**
```python
async def run_all(
    body: RunAllRequest,
    auth: AuthContext = Depends(require_permission("scans:create")),
):
    if auth.role not in ("org_admin", "platform_admin"):
        raise HTTPException(403, "Only org_admin or platform_admin can trigger bulk scans")

    # For org_admin: enforce tenant boundary
    if auth.role == "org_admin" and body.tenant_id != auth.tenant_id:
        raise HTTPException(403, "org_admin can only trigger scans for their own tenant")

    tenant_id = auth.tenant_id  # use auth context, not body
```

**RunAllRequest schema:**
```python
class RunAllRequest(BaseModel):
    tenant_id: str  # validated against auth.tenant_id for non-platform_admin

    class Config:
        extra = 'ignore'
```

**get_active_accounts_for_tenant:**
```python
async def get_active_accounts_for_tenant(tenant_id: str, conn) -> list:
    return await conn.fetch(
        """SELECT account_id, account_type, validation_status, account_status
           FROM cloud_accounts
           WHERE tenant_id = $1
           ORDER BY created_at""",
        tenant_id
    )
```

**Per-account scan submission (reuse C7 logic):**
```python
triggered = []
skipped = []

for account in accounts:
    if account["validation_status"] != "pass" or account["account_status"] == "INACTIVE":
        skipped.append({"account_id": str(account["account_id"]), "reason": "INACTIVE credential"})
        continue
    try:
        scan_run_id = await submit_single_scan(account, auth.tenant_id, conn)
        triggered.append({"account_id": str(account["account_id"]), "scan_run_id": scan_run_id})
    except Exception as e:
        skipped.append({"account_id": str(account["account_id"]), "reason": "submission_error"})
```

**scan_orchestration write — use the same `create_scan_run()` from C7:**
```python
from database.scan_run_operations import create_scan_run
# insert into scan_orchestration (not scan_runs)
```

**Register in main.py:**
```python
from routers.bulk_scans import router as bulk_scans_router
app.include_router(bulk_scans_router)
```

## Security Checklist

- [ ] `tenant_id` from `auth.tenant_id` — body `tenant_id` is validated against auth, not trusted directly
- [ ] Role check: `org_admin` and `platform_admin` only
- [ ] `require_permission("scans:create")` enforced
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `scan_orchestration` used (not `scan_runs`) in all SQL
- [ ] `tenant_admin` calling the endpoint gets 403
- [ ] Unit tests: 4 test cases (AC10)
- [ ] bmad-security-reviewer: no BLOCKERs (S-05 resolved)
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s