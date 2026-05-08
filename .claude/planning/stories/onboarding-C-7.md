---
story_id: onboarding-C-7
title: Ad-hoc scan endpoint — trigger scan without a schedule
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-6]
blocks: [onboarding-D-4, onboarding-D-11]
sme: Python/FastAPI/Argo engineer
estimate: 1 day
---

# Story: Ad-hoc scan endpoint (no schedule required)

## User Story
As a tenant_admin, I want to trigger a scan on a cloud account immediately without
creating a schedule first, so that I can run a one-off scan after making infrastructure
changes without waiting for the next scheduled window.

## Context
Gap S-02 from USER-FLOWS-SCHEDULING.md. Currently, triggering a scan requires a schedule
to exist and calling `POST /schedules/{id}/run-now`. There is no way to scan an account
without first creating a schedule.

The ad-hoc scan:
1. Creates a transient `scan_run` row (no schedule FK — `schedule_id` is NULL).
2. Submits the Argo pipeline with `scan-run-id`, `tenant-id`, `account-id`, `provider`,
   `credential-type`, `credential-ref`.
3. Returns `{scan_run_id: "uuid", status: "submitted"}` immediately (async).
4. Uses default `engines_requested` from account's `account_type` (from YAML catalog mapping).

Unlike `run-now` (which uses a schedule's saved scope), the ad-hoc scan uses the account's
full scope by default. Optional body params allow overriding `include_regions`,
`include_services`, `engines_requested`.

## Files to Create/Modify
- `engines/onboarding/api/cloud_accounts.py` — add `POST /api/v1/cloud-accounts/{id}/scan`
- `engines/onboarding/database/scan_operations.py` — add `create_scan_run_adhoc()`

## Implementation Notes

### New endpoint

```python
@router.post("/cloud-accounts/{account_id}/scan")
async def trigger_adhoc_scan(
    account_id: str,
    body: AdHocScanRequest = Body(default=AdHocScanRequest()),
    auth: AuthContext = Depends(require_permission("scans:create")),
    db = Depends(get_db),
):
    account = await get_cloud_account(db, account_id, tenant_id=auth.engine_tenant_id)
    if not account:
        raise HTTPException(404, "Account not found")
    if account["credential_validation_status"] != "valid":
        raise HTTPException(422, "Cannot scan account with invalid credentials")

    scan_run_id = str(uuid.uuid4())
    await create_scan_run_adhoc(db, scan_run_id, account, triggered_by=str(auth.user_id))

    await argo_client.submit_pipeline(
        workflow_template="cspm-scan-pipeline",
        parameters={
            "scan-run-id":       scan_run_id,
            "tenant-id":         str(auth.engine_tenant_id),
            "account-id":        account_id,
            "provider":          account["provider"],
            "credential-type":   account["credential_type"],
            "credential-ref":    account["credential_ref"],
            "include-services":  json.dumps(body.include_services or []),
            "include-regions":   json.dumps(body.include_regions or []),
            "engines-requested": json.dumps(
                body.engines_requested or get_default_engines(account["account_type"])
            ),
        },
    )
    return JSONResponse({"scan_run_id": scan_run_id, "status": "submitted"}, status_code=202)
```

### Pydantic request model

```python
class AdHocScanRequest(BaseModel):
    include_regions: Optional[List[str]] = None
    include_services: Optional[List[str]] = None
    engines_requested: Optional[List[str]] = None
```

### `get_default_engines()` helper

Maps `account_type` → default engines list (use `catalog/account_types/auth_requirements.yaml` scope_capabilities as reference):
```python
DEFAULT_ENGINES_BY_ACCOUNT_TYPE = {
    "aws_account": ["discovery", "inventory", "check", "threat", "compliance", "iam", "datasec", "network", "risk"],
    "azure_subscription": ["discovery", "inventory", "check", "threat", "compliance", "iam", "datasec", "network", "risk"],
    "gcp_project": ["discovery", "inventory", "check", "threat", "compliance", "iam", "datasec", "network", "risk"],
    "github_repo": ["secops"],
    "vulnerability_agent": ["vulnerability"],
    "database_agent": ["dbsec"],
    "kubernetes_cluster": ["discovery", "inventory", "check", "threat", "compliance", "container_security", "risk"],
}
```

### scan_operations.py addition

```python
async def create_scan_run_adhoc(db, scan_run_id, account, triggered_by):
    await db.execute("""
        INSERT INTO scan_orchestration
          (scan_run_id, tenant_id, account_id, provider, status,
           schedule_id, triggered_by, created_at, updated_at)
        VALUES (%s, %s, %s, %s, 'submitted', NULL, %s, NOW(), NOW())
    """, (scan_run_id, account["tenant_id"], account["id"], account["provider"], triggered_by))
```

`schedule_id = NULL` distinguishes ad-hoc from scheduled runs.

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/cloud-accounts/{id}/scan` with valid account → 202, `scan_run_id` in response
- [ ] AC2: No schedule required — no schedule FK on the created `scan_orchestration` row
- [ ] AC3: `scan_orchestration.triggered_by = str(auth.user_id)`
- [ ] AC4: Account with `credential_validation_status != 'valid'` → 422
- [ ] AC5: Missing account or wrong tenant → 404
- [ ] AC6: viewer permission → 403
- [ ] AC7: Optional `include_regions` body param passed through to Argo parameters

## Definition of Done
- [ ] `POST /cloud-accounts/{id}/scan` endpoint added with RBAC
- [ ] `create_scan_run_adhoc()` writes to `scan_orchestration` with `schedule_id=NULL`
- [ ] `get_default_engines()` returns correct list for each account_type
- [ ] Argo pipeline submission tested (mock argo_client in tests)
- [ ] Tests cover: valid scan, invalid creds 422, viewer 403, missing account 404
- [ ] bmad-security-reviewer: no BLOCKERs
