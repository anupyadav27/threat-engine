---
id: onboarding-C7
title: "Ad-hoc scan endpoint (run-now)"
sprint: C
points: 1
depends_on: [onboarding-C6]
blocks: [onboarding-C9, onboarding-D6, onboarding-D11]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-14
---

## Context

Gap S-02: There is no way to trigger an ad-hoc scan for a cloud account without a pre-existing schedule. Users must set up a schedule first, then trigger it. The architecture calls for a `POST /api/v1/scans/run-now` endpoint that accepts an `account_id` and immediately submits a scan pipeline to Argo, writing a row to `scan_orchestration` and returning the `scan_run_id`. This endpoint must require `scans:create` permission, validate the account exists and belongs to the caller's tenant, verify the account's `validation_status` is `'pass'` (not INACTIVE), pass `exclude_regions` from the account's schedule (if any) to the Argo pipeline, and return 202 Accepted. Note: `scan_orchestration` (not `scan_runs`) is the correct table — confirmed by C2.

## Acceptance Criteria

- [ ] AC1 (S-02): `POST /api/v1/scans/run-now` endpoint exists in the onboarding engine.
- [ ] AC2: Endpoint requires `Depends(require_permission("scans:create"))`.
- [ ] AC3: Request body: `{"account_id": "<uuid>"}` — `tenant_id` is NOT in the request body; it comes from `auth.tenant_id`.
- [ ] AC4: Account existence and tenant ownership validated: if `account_id` does not exist for the caller's `tenant_id`, return HTTP 404.
- [ ] AC5: If the account's `validation_status != 'pass'` OR `account_status = 'INACTIVE'`, return HTTP 409 with `{"detail": "Account credentials are not valid or account is inactive"}`.
- [ ] AC6: On success, creates a row in `scan_orchestration` with a new UUID `scan_run_id`, `tenant_id` from auth, `account_id`, `status='queued'`.
- [ ] AC7: Submits the scan pipeline to Argo using the existing `ArgoClient.submit_pipeline()` method, passing `scan_run_id`, `account_id`, and `exclude_regions` from the account's active schedule.
- [ ] AC8: Returns HTTP 202 with `{"scan_run_id": "<uuid>", "status": "queued"}`.
- [ ] AC9: For `vulnerability`-type accounts, instead of submitting Argo pipeline, set `run_now = true` on the account's `agent_registrations` row (agent polls this on next heartbeat — see C4).
- [ ] AC10: Unit tests: valid account → 202 + scan_run_id; wrong tenant → 404; inactive account → 409; agent account → sets run_now flag.

## Key Files

- `engines/onboarding/api/scans.py` — Add `run-now` endpoint (after C2 has fixed the scan_runs references)
- `engines/onboarding/database/scan_run_operations.py` — Add `create_scan_run(account_id, tenant_id)` function
- `engines/onboarding/orchestrator/engine_orchestrator.py` — Add or verify `submit_scan_now()` method

## Technical Notes

**Endpoint implementation:**
```python
@router.post("/scans/run-now", status_code=202)
# RBAC: requires scans:create
async def run_scan_now(
    body: RunNowRequest,
    auth: AuthContext = Depends(require_permission("scans:create")),
    db=Depends(get_db),
):
    tenant_id = auth.tenant_id  # never from body

    # Validate account ownership
    account = await get_cloud_account(body.account_id, tenant_id, db)
    if not account:
        raise HTTPException(404, "Account not found")

    # Check account is ready to scan
    if account["validation_status"] != "pass" or account.get("account_status") == "INACTIVE":
        raise HTTPException(409, "Account credentials are not valid or account is inactive")

    # Create scan_orchestration row
    scan_run_id = str(uuid4())
    await create_scan_run(scan_run_id, str(body.account_id), tenant_id, db)

    # Submit pipeline or set agent flag
    if account["account_type"] == "vulnerability":
        await set_agent_run_now(str(body.account_id), db)
    else:
        exclude_regions = await get_account_exclude_regions(str(body.account_id), db)
        await orchestrator.submit_pipeline(
            scan_run_id=scan_run_id,
            account_id=str(body.account_id),
            exclude_regions=exclude_regions,
        )

    return {"scan_run_id": scan_run_id, "status": "queued"}
```

**RunNowRequest schema:**
```python
from pydantic import BaseModel
from uuid import UUID

class RunNowRequest(BaseModel):
    account_id: UUID
```

**scan_orchestration INSERT (use after C2 fix):**
```python
async def create_scan_run(scan_run_id: str, account_id: str, tenant_id: str, conn) -> None:
    await conn.execute(
        """INSERT INTO scan_orchestration
           (scan_run_id, account_id, tenant_id, status, engines_requested, engines_completed, created_at, updated_at)
           VALUES ($1, $2, $3, 'queued', '{}', '{}', NOW(), NOW())""",
        scan_run_id, account_id, tenant_id
    )
```

**get_account_exclude_regions (reads TEXT[] from schedules):**
```python
async def get_account_exclude_regions(account_id: str, conn) -> list:
    row = await conn.fetchrow(
        "SELECT exclude_regions FROM schedules WHERE account_id = $1 AND active = TRUE LIMIT 1",
        account_id
    )
    if row and row["exclude_regions"]:
        return row["exclude_regions"]  # psycopg2 returns TEXT[] as Python list — no json.loads()
    return []
```

**Argo pipeline submit:** Use existing `ArgoClient` or orchestrator helper. Pass `exclude_regions` as a parameter to the pipeline template.

**JSONB note:** `scan_orchestration.engines_requested` and `engines_completed` are JSONB. Use `'{}'::jsonb` not `''` when inserting empty JSONB.

## Security Checklist

- [ ] `tenant_id` from `auth.tenant_id` — never from request body
- [ ] Account ownership validated before scan submission
- [ ] `require_permission("scans:create")` enforced
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `scan_orchestration` (not `scan_runs`) used in all SQL
- [ ] Existing scheduled scans not broken (regression check)
- [ ] Unit tests: 4 test cases (AC10)
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s
