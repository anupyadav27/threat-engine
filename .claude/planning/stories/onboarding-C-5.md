---
story_id: onboarding-C-5
title: Account type validation against tenant_type
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-1]
blocks: [onboarding-D-5]
sme: Python/FastAPI engineer
estimate: 0.5 days
---

# Story: Account type validation against tenant_type

## User Story
As a platform engineer, I want the API to reject an `account_type` that does not
belong in the parent tenant's `tenant_type`, so that a user cannot accidentally add
a GitHub repo account under a Cloud Infrastructure tenant.

## Context
The hierarchy design (`ONBOARDING-HIERARCHY-DESIGN.md` Section 7) defines a strict
mapping: each `tenant_type` allows only a fixed set of `account_type` values.  For
example, a tenant with `tenant_type = "cloud"` may only contain accounts of type
`aws_account`, `azure_subscription`, `gcp_project`, etc.  An `account_type =
"github_repo"` in a `cloud` tenant should return HTTP 422.

The onboarding engine's `create_account()` in `cloud_accounts.py` currently infers
`account_type` from provider name but does NOT validate it against the parent
tenant's `tenant_type`.

The `Tenant` ORM model will have `tenant_type` after story C-1 is done.  This story
depends on C-1 (for `tenant_type` column on `cloud_accounts` / `tenants` tables and
ORM model).

The `VALID_ACCOUNT_TYPES` dict from the design doc must be implemented in a constants
file so it can be imported by both the onboarding engine and any future Django-side
validation.

## Files to Create/Modify
- `engines/onboarding/constants.py` — new file: `VALID_ACCOUNT_TYPES` dict
- `engines/onboarding/api/cloud_accounts.py` — add validation in `create_account()`
- `engines/onboarding/database/tenant_operations.py` — confirm `get_tenant()` returns `tenant_type`

## Implementation Notes

### `engines/onboarding/constants.py` (new file)

```python
"""
Onboarding engine constants.
"""
from typing import Dict, FrozenSet

# Maps tenant_type → set of valid account_type values.
# Source of truth: ONBOARDING-HIERARCHY-DESIGN.md Section 7.
VALID_ACCOUNT_TYPES: Dict[str, FrozenSet[str]] = {
    "cloud": frozenset({
        "aws_account", "azure_subscription", "gcp_project",
        "oci_tenancy", "alicloud_account", "ibm_account", "kubernetes_cluster",
    }),
    "secops": frozenset({
        "github_repo", "gitlab_project", "bitbucket_repo",
        "azure_devops_repo", "generic_git_repo",
    }),
    "vulnerability": frozenset({"vuln_agent", "container_registry"}),
    "database": frozenset({
        "postgres_db", "mysql_db", "mssql_db", "mongodb_db", "oracle_db", "redis_db",
    }),
    "middleware": frozenset({"middleware_agent"}),
    "technology": frozenset({"tech_agent"}),
    "saas": frozenset({
        "github_org", "okta_org", "salesforce_org", "slack_workspace", "jira_project",
    }),
}

# Backward-compat: map old provider values to new account_type values
PROVIDER_TO_ACCOUNT_TYPE: Dict[str, str] = {
    "aws":       "aws_account",
    "azure":     "azure_subscription",
    "gcp":       "gcp_project",
    "oci":       "oci_tenancy",
    "alicloud":  "alicloud_account",
    "ibm":       "ibm_account",
    "k8s":       "kubernetes_cluster",
    "postgres":  "postgres_db",
    "mysql":     "mysql_db",
    "mssql":     "mssql_db",
    "mongodb":   "mongodb_db",
    "oracle":    "oracle_db",
    "redis":     "redis_db",
}
```

### Validation in `create_account()` in `cloud_accounts.py`

After line 116 (the tenant existence check), add:

```python
from engine_onboarding.constants import VALID_ACCOUNT_TYPES, PROVIDER_TO_ACCOUNT_TYPE

# Resolve the final account_type (existing logic already does this — just ensure
# the resolved value uses the canonical names from VALID_ACCOUNT_TYPES)
# Map old-style provider → canonical account_type if not explicitly provided
if not body.account_type:
    account_type = PROVIDER_TO_ACCOUNT_TYPE.get(body.provider, "aws_account")
else:
    account_type = body.account_type

# Validate against tenant_type
tenant_type = tenant.get("tenant_type", "cloud")   # default cloud for legacy tenants
valid_types = VALID_ACCOUNT_TYPES.get(tenant_type, set())

if account_type not in valid_types:
    raise HTTPException(
        status_code=422,
        detail=(
            f"account_type '{account_type}' is not valid for tenant_type '{tenant_type}'. "
            f"Valid types: {sorted(valid_types)}"
        ),
    )
```

Note: `tenant.get("tenant_type", "cloud")` — if the tenant was created before
`tenant_type` was added (legacy), default to `"cloud"` to avoid breaking existing
cloud accounts.  This is safe because all existing tenants are cloud tenants.

### Confirm `get_tenant()` returns `tenant_type`

Check `engines/onboarding/database/tenant_operations.py`.  The `get_tenant()` query
must `SELECT *` or explicitly select `tenant_type`.  After story C-1 adds the column
to the ORM model, the raw psycopg2 query should also return it.  Confirm and update
the SELECT if it uses an explicit column list.

### New tenant creation endpoint must pass `tenant_type`

The endpoint `POST /api/v1/tenants/` (in the tenants router) must accept
`tenant_type` in the request body and write it to the `tenants` table.  Confirm the
tenants router accepts this field; add it if missing.  Default: `"cloud"`.

## Reference Files
- `/Users/apple/Desktop/threat-engine/engines/onboarding/api/cloud_accounts.py`
- `/Users/apple/Desktop/threat-engine/engines/onboarding/database/tenant_operations.py`
- `/Users/apple/Desktop/threat-engine/.claude/documentation/ONBOARDING-HIERARCHY-DESIGN.md` — Section 7

## Acceptance Criteria
- [ ] AC1: `POST /api/v1/cloud-accounts` with `provider="github"` (or `account_type="github_repo"`) under a `tenant_type="cloud"` tenant returns 422 with descriptive error
- [ ] AC2: `POST /api/v1/cloud-accounts` with `account_type="aws_account"` under `tenant_type="cloud"` succeeds (201)
- [ ] AC3: `POST /api/v1/cloud-accounts` with `account_type="vuln_agent"` under `tenant_type="vulnerability"` succeeds (201)
- [ ] AC4: Legacy tenant with no `tenant_type` (NULL) defaults to `"cloud"` — existing cloud account creation not broken
- [ ] AC5: `constants.py` contains `VALID_ACCOUNT_TYPES` dict with all 7 tenant types and their frozen sets
- [ ] AC6: Unit test: mock `get_tenant()` returning `tenant_type="secops"`, call `create_account` with `account_type="aws_account"`, assert 422
- [ ] AC7: Unit test: mock `get_tenant()` returning `tenant_type=None`, call with `provider="aws"`, assert 201 (backward compat)

## Definition of Done
- [ ] `constants.py` created with `VALID_ACCOUNT_TYPES` and `PROVIDER_TO_ACCOUNT_TYPE`
- [ ] Validation added to `create_account()` after tenant lookup
- [ ] `get_tenant()` confirmed to return `tenant_type` column
- [ ] Unit tests pass
- [ ] Story accepted by SM before merge