---
story_id: onboarding-C-10
title: Credential expiry health-check Celery task
status: ready
sprint: onboarding-revamp-C
depends_on: [onboarding-C-1]
blocks: []
sme: Python/Celery/boto3 engineer
estimate: 1 day
---

# Story: Credential expiry health-check Celery task

## User Story
As a platform operator, I want a weekly automated check to validate all stored
credentials are still active, so that accounts with expired credentials are paused
before the next scheduled scan fails silently.

## Context
Gap S-06 from USER-FLOWS-SCHEDULING.md. Currently, credentials are validated only at
onboarding time. If an AWS access key is deleted, an Azure service principal expires, or
a Git PAT is revoked, the next scheduled scan fails with an authentication error and the
failure may not surface to the user clearly.

The health-check task:
1. Runs weekly via Celery Beat.
2. For each `cloud_account` with `credential_validation_status = 'valid'` or `unknown`:
   - Loads credentials from Secrets Manager.
   - Makes a lightweight, read-only API call per CSP to verify the credential still works.
   - On failure: sets `credential_validation_status = 'expired'`, `account_status = 'credential_error'`.
   - On success: sets `credential_validation_status = 'valid'`, `last_credential_check_at = NOW()`.
3. For accounts whose status changes to `expired`, emits a notification (log + future email hook).

**Credential check per CSP:**
- AWS access_key: `sts.get_caller_identity()`
- AWS iam_role: `sts.assume_role(RoleArn=..., ExternalId=...)`
- Azure: `subscription_client.subscriptions.get(subscription_id)`
- GCP: `storage.list_buckets(max_results=1)`
- OCI: `identity_client.get_user(user_id)`
- AliCloud: `sts.get_caller_identity()`
- GitHub/GitLab/Bitbucket (git tokens): `GET /user` or `GET /version` with token auth
- Agent accounts: check `agent_registrations.last_heartbeat_at` — if > 7 days ago, flag

## Files to Create/Modify
- `engines/onboarding/tasks/credential_health_check.py` — new Celery task
- `engines/onboarding/celery_app.py` — register beat schedule
- `engines/onboarding/credential_validators/` — already has per-CSP validators; extend or reuse

## Implementation Notes

### Celery task skeleton

```python
from celery import shared_task
import logging

logger = logging.getLogger(__name__)

@shared_task(name="credential_health_check", queue="cred-health")
def credential_health_check():
    """Weekly task: validate all stored credentials are still alive."""
    from database.db import get_db_sync
    from database.cloud_accounts_operations import get_accounts_for_health_check, update_credential_status

    db = get_db_sync()
    accounts = get_accounts_for_health_check(db)
    results = {"checked": 0, "valid": 0, "expired": 0, "errors": 0}

    for account in accounts:
        try:
            ok = _validate_credential(account)
            status = "valid" if ok else "expired"
            if not ok:
                account_status = "credential_error"
                logger.warning("credential.expired account_id=%s provider=%s",
                               account["id"], account["provider"])
                results["expired"] += 1
            else:
                account_status = "active"
                results["valid"] += 1
            update_credential_status(db, account["id"], status, account_status)
            results["checked"] += 1
        except Exception as e:
            logger.error("credential_health_check failed account_id=%s error=%s",
                         account["id"], str(e))
            results["errors"] += 1

    logger.info("credential_health_check complete %s", results)
    return results
```

### `_validate_credential()` dispatch

```python
def _validate_credential(account):
    provider = account["provider"]
    creds = load_from_secrets_manager(account["credential_ref"])

    if provider == "aws" and account["credential_type"] == "access_key":
        return _check_aws_access_key(creds)
    elif provider == "aws" and account["credential_type"] == "iam_role":
        return _check_aws_iam_role(creds)
    elif provider == "azure":
        return _check_azure(creds)
    elif provider == "gcp":
        return _check_gcp(creds)
    # ... other providers
    elif account["account_type"] in ("vulnerability_agent", "database_agent", "middleware_agent"):
        return _check_agent_heartbeat(account)
    return True  # unknown type — assume valid
```

### Celery Beat registration

```python
# In celery_app.py:
app.conf.beat_schedule = {
    "credential-health-check-weekly": {
        "task": "credential_health_check",
        "schedule": crontab(day_of_week="sunday", hour=2, minute=0),
    }
}
```

### `last_credential_check_at` column

Add to `cloud_accounts` if not present:
```sql
ALTER TABLE cloud_accounts
    ADD COLUMN IF NOT EXISTS last_credential_check_at TIMESTAMPTZ NULL;
```
(Fold into `20260503_schedule_region_scope.sql` migration or a new migration file.)

## Acceptance Criteria
- [ ] AC1: Task `credential_health_check` runs against all accounts with status `valid` or `unknown`
- [ ] AC2: AWS access_key check: `sts.get_caller_identity()` — failure sets `credential_validation_status='expired'`, `account_status='credential_error'`
- [ ] AC3: On success: `last_credential_check_at` updated to NOW()
- [ ] AC4: Celery Beat schedule: runs every Sunday at 02:00 UTC
- [ ] AC5: Agent accounts with `last_heartbeat_at > 7 days ago` → flagged as `credential_error`
- [ ] AC6: Task failure for one account does not abort the task — others still checked
- [ ] AC7: Results dict returned and logged at INFO level

## Definition of Done
- [ ] `credential_health_check` Celery task implemented with per-CSP dispatch
- [ ] Celery Beat schedule registered
- [ ] `last_credential_check_at` column added to `cloud_accounts`
- [ ] Tests: mock Secrets Manager + mock CSP SDK calls; valid credential → no status change; expired → status update
- [ ] Logs `credential.expired` at WARNING (not ERROR) — expected maintenance event
- [ ] No credentials logged in plaintext
- [ ] bmad-security-reviewer: no BLOCKERs
