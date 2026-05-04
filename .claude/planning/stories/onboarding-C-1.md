---
story_id: onboarding-C-1
title: Apply account_type migration + fix ORM model + fix INSERT
status: ready
sprint: onboarding-revamp-C
depends_on: []
blocks: [onboarding-C-5]
sme: Python/SQLAlchemy/psycopg2 engineer
estimate: 1 day
---

# Story: Apply account_type migration + fix ORM model + fix INSERT

## User Story
As a platform engineer, I want the onboarding engine to correctly write and read
`account_type` and `auth_config` on `cloud_accounts`, so that downstream engines
and the wizard UI can branch behaviour by account type without querying a legacy
`account_category` field.

## Context
The migration `20260503_account_type_and_agent_registrations.sql` was written and
committed but has NOT been applied to RDS yet. It adds `account_type` VARCHAR(50)
(non-nullable, default `cloud_csp`) and `auth_config` JSONB to `cloud_accounts`,
and creates the `agent_registrations` table.

The ORM model at `engines/onboarding/database/models.py` does not have columns for
`account_type` or `auth_config` on the `CloudAccount` class.  The psycopg2 INSERT
in `cloud_accounts_operations.py::create_cloud_account()` does not include either
column.  The `update_cloud_account()` allowed-set also omits both.  The
`list_cloud_accounts()` filter translates `account_category` but there is no
`account_type` filter path.

The `Tenant` ORM model is also missing `org_id` and `tenant_type` columns which are
needed by story C-5 and the full hierarchy design.

Current broken state:
- `POST /api/v1/cloud-accounts` succeeds in DB but silently drops `account_type`
  and `auth_config` values — they are never written.
- `PATCH /{account_id}` cannot update `account_type`.
- ORM `CloudAccount.to_dict()` returns no `account_type` or `auth_config` key.

## Files to Create/Modify
- `engines/onboarding/database/models.py` — add columns to `CloudAccount` and `Tenant`
- `engines/onboarding/database/cloud_accounts_operations.py` — fix INSERT and UPDATE
- `shared/database/migrations/20260503_account_type_and_agent_registrations.sql` — apply to RDS (document command)

## Implementation Notes

### Step 1 — Apply migration to RDS
```bash
# Get the onboarding pod name
kubectl get pods -n threat-engine-engines -l app=engine-onboarding -o jsonpath='{.items[0].metadata.name}'

# Copy migration file to the pod
kubectl cp /Users/apple/Desktop/threat-engine/shared/database/migrations/20260503_account_type_and_agent_registrations.sql \
  threat-engine-engines/<POD_NAME>:/tmp/migrate.sql

# Run migration
kubectl exec -n threat-engine-engines <POD_NAME> -- \
  psql -h $DB_HOST -U $DB_USER -d $DB_NAME -f /tmp/migrate.sql
```

### Step 2 — ORM model changes in `models.py`

Add to `CloudAccount` class (after the `log_sources` column, before `last_scan_at`):
```python
account_type = Column(String(50), nullable=False, default='cloud_csp', index=True)
auth_config   = Column(JSONB, default=dict)
```

Update `CloudAccount.to_dict()` — add both fields:
```python
'account_type': self.account_type,
'auth_config':  self.auth_config or {},
```

Keep `account_category` in `to_dict()` as an alias pointing at `account_type` for
backward compatibility:
```python
'account_category': self.account_type,   # backward compat alias
```

Add to `Tenant` class (after `updated_at`, before `__table_args__`):
```python
org_id       = Column(String(255), nullable=True, index=True)
tenant_type  = Column(String(50), nullable=True, default='cloud')
```

Update `Tenant.to_dict()` to include both:
```python
'org_id':      self.org_id,
'tenant_type': self.tenant_type,
```

### Step 3 — Fix INSERT in `cloud_accounts_operations.py`

The `create_cloud_account()` function currently has this INSERT (lines 29–62).
The column list and VALUES tuple must include `account_type` and `auth_config`:

Add `account_type, auth_config` to the INSERT column list.
Add `data.get("account_type", "cloud_csp")` and
`json.dumps(data.get("auth_config") or {})` to the VALUES tuple.
The `json.dumps` is required because psycopg2 does not auto-serialize plain dicts
for non-declared-JSONB columns in raw SQL — use `psycopg2.extras.Json` or
`json.dumps` wrapper.

### Step 4 — Fix UPDATE allow-list in `cloud_accounts_operations.py`

`update_cloud_account()` has an `allowed` set (line 184–194). Add:
```python
"account_type", "auth_config",
```

### Step 5 — Fix `list_cloud_accounts()` filter path

After the existing `account_status` filter block (around line 163) add:
```python
if "account_type" in filters:
    query += " AND ca.account_type = %s"
    params.append(filters["account_type"])
```

The `account_category` filter in the API handler (`cloud_accounts.py` line 163)
maps `account_category` → `filters["account_category"]`.  After this story, the
filter key in operations should be `account_type`.  Update the API handler's
`list_accounts()` to translate: when `account_category` query param is passed, set
`filters["account_type"] = account_category`.

## Reference Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/models.py`
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/cloud_accounts_operations.py`
- `/Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py`
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/20260503_account_type_and_agent_registrations.sql`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/ONBOARDING-HIERARCHY-DESIGN.md` — Section 6

## Acceptance Criteria
- [ ] AC1: `kubectl exec` psql confirms `cloud_accounts` has columns `account_type VARCHAR(50) NOT NULL DEFAULT 'cloud_csp'` and `auth_config JSONB`
- [ ] AC2: `kubectl exec` psql confirms `agent_registrations` table exists with all columns from the migration
- [ ] AC3: `POST /api/v1/cloud-accounts` with `account_type="vulnerability"` returns a response dict including `account_type: "vulnerability"`
- [ ] AC4: `GET /api/v1/cloud-accounts/{id}` response includes `account_type` and `auth_config` keys (not null)
- [ ] AC5: `PATCH /api/v1/cloud-accounts/{id}` with body `{"account_type":"secops"}` updates the DB column and returns the new value
- [ ] AC6: `GET /api/v1/cloud-accounts?account_category=vulnerability` returns only accounts whose `account_type = 'vulnerability'` (backward-compat filter translation works)
- [ ] AC7: `Tenant.to_dict()` response includes `org_id` and `tenant_type` keys
- [ ] AC8: Unit test for `create_cloud_account` mocking psycopg2 — asserts `account_type` and `auth_config` appear in the INSERT parameters

## Definition of Done
- [ ] Migration applied to RDS and verified with psql
- [ ] ORM model updated with type hints and docstring update on `to_dict()`
- [ ] `create_cloud_account` INSERT includes `account_type` and `auth_config`
- [ ] `update_cloud_account` allowed-set includes both fields
- [ ] `list_cloud_accounts` handles `account_type` filter
- [ ] Unit tests pass (mock psycopg2)
- [ ] No existing AWS cloud-csp account creation broken (regression: existing accounts default to `cloud_csp`)
- [ ] Story accepted by SM before merge
