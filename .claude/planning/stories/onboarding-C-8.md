---
story_id: onboarding-C-8
title: exclude_regions / include_regions / include_services on Schedule ORM
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-1]
blocks: [onboarding-D-10]
sme: Python/SQLAlchemy/FastAPI engineer
estimate: 1 day
---

# Story: exclude_regions / include_regions / include_services on Schedule ORM

## User Story
As a tenant_admin creating a schedule, I want to specify which regions and services to
include or exclude, so that I can limit scans to production regions only and avoid
scanning development accounts.

## Context
Gap S-04 from USER-FLOWS-SCHEDULING.md. The `schedules` table has an `include_services`
column (JSONB) already. It does NOT have `include_regions` or `exclude_regions` columns.
The Argo pipeline accepts `include-regions` and `exclude-services` parameters but
`schedules` has no way to store them.

The `Schedule` ORM model in `engines/onboarding/database/models.py` has `include_services`
but the `create_schedule()` INSERT in `postgres_operations.py` may not include it, and
there are no `include_regions`/`exclude_regions` columns on the ORM or table.

This story:
1. Adds `include_regions JSONB`, `exclude_regions JSONB` columns to `schedules` table via migration.
2. Updates the ORM model.
3. Updates `create_schedule()` and `update_schedule()` to persist these values.
4. Passes them through to `trigger_scan()` → Argo submission.

## Files to Create/Modify
- `shared/database/migrations/20260503_schedule_region_scope.sql` — new migration
- `engines/onboarding/database/models.py` — add columns to `Schedule` model
- `engines/onboarding/database/postgres_operations.py` — update create/update/trigger
- `engines/onboarding/api/schedules.py` — update request models

## Implementation Notes

### Migration (new file)

```sql
-- File: shared/database/migrations/20260503_schedule_region_scope.sql
BEGIN;

ALTER TABLE schedules
    ADD COLUMN IF NOT EXISTS include_regions  JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS exclude_regions  JSONB DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS exclude_services JSONB DEFAULT '[]'::jsonb;

COMMIT;
```

### ORM model additions

File: `engines/onboarding/database/models.py` — in `Schedule` class:
```python
include_regions  = Column(JSONB, default=list)
exclude_regions  = Column(JSONB, default=list)
exclude_services = Column(JSONB, default=list)
```

Update `Schedule.to_dict()`:
```python
'include_regions':  self.include_regions or [],
'exclude_regions':  self.exclude_regions or [],
'exclude_services': self.exclude_services or [],
```

### `create_schedule()` — add to INSERT

```python
# In the INSERT column list, add:
# include_regions, exclude_regions, exclude_services
# In VALUES, add:
json.dumps(data.get("include_regions") or []),
json.dumps(data.get("exclude_regions") or []),
json.dumps(data.get("exclude_services") or []),
```

### Argo submission — pass through to pipeline

In `trigger_scan()` (wherever Argo params are assembled):
```python
parameters={
    ...
    "include-regions":   json.dumps(schedule.include_regions or []),
    "exclude-regions":   json.dumps(schedule.exclude_regions or []),
    "include-services":  json.dumps(schedule.include_services or []),
    "exclude-services":  json.dumps(schedule.exclude_services or []),
}
```

### Pydantic models for schedule create/update

```python
class ScheduleCreate(BaseModel):
    tenant_id: str
    account_id: str
    cron_expression: str
    engines_requested: List[str] = []
    include_services: List[str] = []
    include_regions: List[str] = []
    exclude_regions: List[str] = []
    exclude_services: List[str] = []
```

## Acceptance Criteria
- [ ] AC1: `schedules` table has `include_regions`, `exclude_regions`, `exclude_services` JSONB columns after migration
- [ ] AC2: `POST /api/v1/schedules/` with `include_regions=["us-east-1","eu-west-1"]` persists and returns correctly
- [ ] AC3: `GET /api/v1/schedules/{id}` response includes `include_regions`, `exclude_regions`, `exclude_services` keys
- [ ] AC4: `PATCH /api/v1/schedules/{id}` can update `include_regions` — new value persisted
- [ ] AC5: When a scheduled scan fires, `include-regions` and `exclude-regions` Argo params match schedule values
- [ ] AC6: Existing schedules default to `[]` for all three new columns (no data loss)

## Definition of Done
- [ ] Migration file written and applied to RDS
- [ ] ORM model updated with type hints
- [ ] CREATE and UPDATE operations include new columns
- [ ] Argo submission passes `exclude-regions` and `include-regions` through
- [ ] Tests: create schedule with regions, verify Argo params
- [ ] No regression on existing schedules (existing rows default to `[]`)
- [ ] bmad-security-reviewer: no BLOCKERs
