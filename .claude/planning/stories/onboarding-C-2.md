---
story_id: onboarding-C-2
title: Verify and fix scan_runs vs scan_orchestration table name mismatch
status: ready
sprint: onboarding-revamp-C
depends_on: []
blocks: []
sme: Python/psycopg2/Argo-Workflows engineer
estimate: 0.5 days
---

# Story: Verify and fix scan_runs vs scan_orchestration naming

## User Story
As a platform engineer, I want the onboarding engine and Argo pipeline to use the
same table name for scan runs, so that scan triggers from onboarding are visible in
the pipeline and vice versa without silent write failures.

## Context
The onboarding engine ORM model declares `__tablename__ = 'scan_runs'` (line 268 of
`engines/onboarding/database/models.py`).  The docstring says "Was: scan_orchestration
table".

The rest of the platform (Argo templates, pipeline worker, all scanning engines)
references `scan_orchestration` as the canonical table name.  If the onboarding engine
is writing to `scan_runs` but Argo reads from `scan_orchestration`, scan triggers
from the UI will silently disappear and no pipeline will start.

This story investigates which table actually exists in RDS, confirms or closes the
mismatch, and either renames the ORM table reference or documents why the split is
intentional.

## Files to Create/Modify
- `engines/onboarding/database/models.py` — possibly change `__tablename__` on `ScanRun`
- `engines/onboarding/database/postgres_operations.py` — check for any raw SQL referencing `scan_runs` or `scan_orchestration`
- `engines/onboarding/database/cloud_accounts_operations.py` — same check
- Code comment in models.py documenting the finding

## Implementation Notes

### Step 1 — Confirm live table name in RDS

Run the following inside the onboarding pod to see which scan tables exist:

```bash
kubectl exec -n threat-engine-engines deployment/engine-onboarding -- \
  python3 -c "
import os, psycopg2
conn = psycopg2.connect(
    host=os.environ['DB_HOST'],
    port=os.environ.get('DB_PORT', 5432),
    dbname=os.environ['DB_NAME'],
    user=os.environ['DB_USER'],
    password=os.environ['DB_PASSWORD']
)
cur = conn.cursor()
cur.execute(\"SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename LIKE '%scan%'\")
print(cur.fetchall())
conn.close()
"
```

Expected outcomes:
- If only `scan_runs` exists: the split is real; Argo templates that reference
  `scan_orchestration` are broken. Fix: create an alias view `scan_orchestration` on
  top of `scan_runs`, or rename the table and update the ORM.
- If only `scan_orchestration` exists: the ORM `__tablename__` is wrong. Fix: change
  to `scan_orchestration`.
- If both exist: they diverged. Document which is the source of truth and migrate.

### Step 2 — Fix based on finding

**Most likely outcome** (based on project-wide naming): `scan_orchestration` is the
live table.  If so, change line 268 of `models.py`:
```python
__tablename__ = 'scan_orchestration'
```
Add a comment:
```python
# NOTE (2026-05-03): Was incorrectly declared as 'scan_runs'.
# Confirmed via kubectl exec psql that RDS table is 'scan_orchestration'.
# All Argo templates and scanning engines read/write scan_orchestration.
```

Also grep `postgres_operations.py` for any raw SQL:
```bash
grep -n "scan_runs\|scan_orchestration" \
  /Users/apple/Desktop/threat-engine/engines/onboarding/database/postgres_operations.py
```
Update any raw SQL to use the confirmed live table name.

### Step 3 — Validate with a scan trigger

After the fix, trigger a manual scan via the onboarding API and confirm the row
appears in `scan_orchestration`:
```bash
kubectl exec -n threat-engine-engines deployment/engine-onboarding -- \
  python3 -c "
import os, psycopg2
conn = psycopg2.connect(...)
cur = conn.cursor()
cur.execute('SELECT scan_run_id, overall_status FROM scan_orchestration ORDER BY created_at DESC LIMIT 5')
print(cur.fetchall())
"
```

## Reference Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/models.py`
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/postgres_operations.py`
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/argo/cspm-pipeline.yaml`

## Acceptance Criteria
- [ ] AC1: A kubectl exec command in the story PR description shows which table(s) exist in RDS
- [ ] AC2: `ScanRun.__tablename__` matches the confirmed live table name
- [ ] AC3: No raw SQL in `postgres_operations.py` references the wrong table name
- [ ] AC4: A manual scan triggered via `POST /api/v1/scan-runs` (or equivalent) produces a row that Argo can query with its standard `scan_orchestration` table reference
- [ ] AC5: Code comment in `models.py` documents the finding date and resolution

## Definition of Done
- [ ] kubectl exec investigation run and result documented in PR
- [ ] ORM `__tablename__` and raw SQL aligned to live table name
- [ ] No Argo pipeline template requires change (confirm by grepping argo YAML)
- [ ] Unit tests updated if any test fixture hardcodes `scan_runs`
- [ ] Story accepted by SM before merge
