---
id: onboarding-C8
title: "exclude_regions / include_regions on Schedule ORM"
sprint: C
points: 1
depends_on: [onboarding-C1]
blocks: [onboarding-D5, onboarding-D10]
security_blocks: []
nist_csf: PR.DS
owasp_samm: Implementation
csa_ccm: IAM-14
---

## Context

Gap S-04: The `schedules` table now has `include_regions`, `exclude_regions`, `include_services`, `exclude_services` TEXT[] columns (added in C1). However, the existing `Schedule` ORM model in `engines/onboarding/models/schedule.py` does not have these fields, the `schedule_operations.py` DB layer does not read/write them, and the Argo pipeline submission code in the orchestrator does not forward `exclude_regions` to the Argo workflow parameters — so the regions are silently dropped even if set. This story wires all three layers: (1) ORM model, (2) DB operations, (3) Argo submission. Additionally, the `PATCH /schedules/{id}` endpoint must accept these new fields via its schema (using an allow-list Pydantic model to prevent mass assignment).

## Acceptance Criteria

- [ ] AC1 (S-04): `engines/onboarding/models/schedule.py` `Schedule` class has `include_regions`, `exclude_regions`, `include_services`, `exclude_services` fields (typed as `Optional[List[str]]`).
- [ ] AC2: `schedule_operations.py` `create_schedule()` reads and writes all 4 new fields to the DB.
- [ ] AC3: `schedule_operations.py` `get_schedule()` returns all 4 new fields in the result dict.
- [ ] AC4: `PATCH /schedules/{id}` accepts a body containing any subset of `{include_regions, exclude_regions, include_services, exclude_services}` and persists them.
- [ ] AC5: `PATCH /schedules/{id}` schema uses `extra='ignore'` — fields not in the allow-list are silently dropped.
- [ ] AC6: When `engine_orchestrator.py` submits a pipeline, it reads `exclude_regions` from the schedule and passes it to `ArgoClient.submit_pipeline()` as a workflow parameter.
- [ ] AC7: The Argo workflow template receives `exclude_regions` as a parameter (verify the template definition or add a placeholder if not yet wired).
- [ ] AC8: Existing schedules without the new columns return `include_regions: null`, `exclude_regions: null` (nullable — not errors).
- [ ] AC9: Unit tests: create schedule with regions → regions persisted; PATCH regions on existing schedule → DB updated; Argo submit call includes exclude_regions parameter.

## Key Files

- `engines/onboarding/models/schedule.py` — Add 4 new fields to `Schedule` model
- `engines/onboarding/database/schedule_operations.py` — Update create/read/update SQL to include new fields
- `engines/onboarding/api/schedules.py` — Update PATCH schema to accept new fields
- `engines/onboarding/orchestrator/engine_orchestrator.py` — Pass `exclude_regions` to Argo submit
- `deployment/aws/eks/argo/cspm-pipeline.yaml` — Verify/add `exclude_regions` parameter to pipeline template

## Technical Notes

**Schedule model update:**
```python
# models/schedule.py
from typing import Optional, List

class Schedule:
    include_regions:  Optional[List[str]] = None
    exclude_regions:  Optional[List[str]] = None
    include_services: Optional[List[str]] = None
    exclude_services: Optional[List[str]] = None
```

**schedule_operations.py CREATE (TEXT[] columns):**
```python
await conn.execute(
    """INSERT INTO schedules
       (schedule_id, tenant_id, account_id, cron_expression,
        include_regions, exclude_regions, include_services, exclude_services, ...)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, ...)""",
    schedule_id, tenant_id, account_id, cron_expr,
    include_regions or [],   # TEXT[] — pass Python list directly
    exclude_regions or [],
    include_services or [],
    exclude_services or [],
    ...
)
```

**Reading TEXT[] from psycopg2:**
```python
row = await conn.fetchrow("SELECT * FROM schedules WHERE schedule_id = $1", sid)
exclude_regions = row["exclude_regions"]  # already a Python list — no json.loads()
```

**PATCH schema (allow-list):**
```python
class SchedulePatch(BaseModel):
    include_regions:  Optional[List[str]] = None
    exclude_regions:  Optional[List[str]] = None
    include_services: Optional[List[str]] = None
    exclude_services: Optional[List[str]] = None
    cron_expression:  Optional[str] = None

    class Config:
        extra = 'ignore'
```

**Argo submit with exclude_regions:**
```python
# engine_orchestrator.py
async def submit_pipeline(self, scan_run_id: str, account_id: str, exclude_regions: list):
    params = {
        "scan_run_id": scan_run_id,
        "account_id": account_id,
        "exclude_regions": ",".join(exclude_regions) if exclude_regions else "",
    }
    # Pass params to ArgoClient.submit()
```

**Argo template parameter (in cspm-pipeline.yaml):**
```yaml
arguments:
  parameters:
  - name: exclude_regions
    value: ""
```

**Find ArgoClient.submit call:**
```bash
grep -n "submit\|ArgoClient\|argo" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/orchestrator/engine_orchestrator.py
```

## Security Checklist

- [ ] PATCH schema has `extra='ignore'` — no mass assignment of tenant_id or credential_ref
- [ ] `tenant_id` from `auth.tenant_id` in all schedule queries
- [ ] `require_permission("scans:create")` on PATCH (from C6)
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `exclude_regions` forwarded to Argo submit call (verify in orchestrator code)
- [ ] TEXT[] columns read as Python lists without `json.loads()`
- [ ] Unit tests: create + read + patch + argo-submit verified
- [ ] bmad-security-reviewer: no BLOCKERs (S-04 resolved)
- [ ] `kubectl rollout status deployment/engine-onboarding -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding -n threat-engine-engines` shows no ERROR in first 60s