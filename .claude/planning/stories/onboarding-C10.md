---
id: onboarding-C10
title: "Credential expiry Celery health-check task + K8s beat manifest"
sprint: C
points: 1
depends_on: [onboarding-C1]
blocks: []
security_blocks: []
nist_csf: DE.AE
owasp_samm: Verification
csa_ccm: IAM-14
---

## Context

BUG-07: The `credential_health_check` Celery task code exists in `engines/onboarding/tasks/credential_health_check.py` but there is no Kubernetes Deployment manifest for the Celery beat scheduler. This means the task has never fired in production — it exists only as dead code. This story: (1) reviews and hardens the existing task code to query `cloud_accounts` using the `expires_at` column added in C1, (2) adds SES email notification for accounts expiring in 14 days, (3) sets `account_status = 'INACTIVE'` for accounts past day 90, and (4) creates the K8s Celery beat Deployment manifest as a second Deployment block in `engine-onboarding.yaml`. The beat Deployment must use `replicas: 1` (singleton) — multiple beat replicas would fire tasks multiple times.

## Acceptance Criteria

- [ ] AC1 (BUG-07): `deployment/aws/eks/engines/engine-onboarding.yaml` contains a second `Deployment` named `engine-onboarding-celery-beat` in namespace `threat-engine-engines`.
- [ ] AC2: The Celery beat Deployment uses `replicas: 1` (exactly one — never scale this up).
- [ ] AC3: The Celery beat container command is `["celery", "-A", "tasks.celery_app", "beat", "--loglevel=info"]`.
- [ ] AC4: The Celery beat Deployment uses the same image as the main onboarding Deployment (no `latest` tag — must use explicit version tag).
- [ ] AC5: Celery beat Deployment mounts `threat-engine-db-config` ConfigMap and `threat-engine-secrets` Secret as environment.
- [ ] AC6: `credential_health_check` task runs on schedule: weekly, Monday 3 AM UTC (crontab `0 3 * * 1`).
- [ ] AC7: Task queries `cloud_accounts` WHERE `expires_at <= NOW() + INTERVAL '14 days'` AND `account_status = 'active'` AND `validation_status != 'expired'`.
- [ ] AC8: For each qualifying account: sends SES email to org admin email + `PLATFORM_ADMIN_EMAIL` env var with expiry warning.
- [ ] AC9: Task queries `cloud_accounts` WHERE `expires_at <= NOW()` AND `account_status = 'active'` — sets `account_status = 'INACTIVE'` for these accounts.
- [ ] AC10: All SQL in the task uses `expires_at` column (added in C1) — no reference to `scan_runs` (fixed in C2).
- [ ] AC11: `kubectl logs -l app=engine-onboarding-celery-beat -n threat-engine-engines` shows beat scheduler startup message and first task schedule.

## Key Files

- `deployment/aws/eks/engines/engine-onboarding.yaml` — Add Celery beat Deployment block
- `engines/onboarding/tasks/credential_health_check.py` — Review and fix task code
- `engines/onboarding/tasks/celery_app.py` OR `engines/onboarding/celery_app.py` — Verify beat schedule is registered

## Technical Notes

**Celery beat Deployment YAML block (add to engine-onboarding.yaml):**
```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-onboarding-celery-beat
  namespace: threat-engine-engines
  labels:
    app: engine-onboarding-celery-beat
spec:
  replicas: 1  # SINGLETON — never increase
  selector:
    matchLabels:
      app: engine-onboarding-celery-beat
  template:
    metadata:
      labels:
        app: engine-onboarding-celery-beat
    spec:
      containers:
      - name: celery-beat
        image: yadavanup84/threat-engine-onboarding-api:<tag>  # same tag as main deployment
        command: ["celery", "-A", "tasks.celery_app", "beat", "--loglevel=info"]
        envFrom:
        - configMapRef:
            name: threat-engine-db-config
        - secretRef:
            name: threat-engine-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "200m"
```

**CRITICAL: No `latest` image tag.** Use the same explicit tag as the main engine-onboarding Deployment. After deploying C1-C10 as one image, use that tag here.

**Celery beat schedule registration:**
```python
# celery_app.py or tasks/__init__.py
from celery.schedules import crontab

app.conf.beat_schedule = {
    'credential-health-check': {
        'task': 'tasks.credential_health_check.run_credential_health_check',
        'schedule': crontab(hour=3, minute=0, day_of_week=1),  # Monday 3AM UTC
    },
}
app.conf.timezone = 'UTC'
```

**Task query using expires_at (added in C1):**
```python
# credential_health_check.py
async def run_credential_health_check():
    conn = await get_db_connection()
    try:
        # 14-day warning
        expiring_soon = await conn.fetch(
            """SELECT account_id, tenant_id, account_name
               FROM cloud_accounts
               WHERE expires_at <= NOW() + INTERVAL '14 days'
                 AND account_status = 'active'
                 AND validation_status != 'expired'"""
        )
        for acct in expiring_soon:
            await send_expiry_warning_email(acct)

        # Day 90+ — set INACTIVE
        await conn.execute(
            """UPDATE cloud_accounts
               SET account_status = 'INACTIVE', updated_at = NOW()
               WHERE expires_at <= NOW()
                 AND account_status = 'active'"""
        )
    finally:
        await conn.close()
```

**SES email:**
```python
import boto3, os

ses = boto3.client("ses", region_name="ap-south-1")
platform_admin_email = os.environ["PLATFORM_ADMIN_EMAIL"]

def send_expiry_warning_email(account: dict):
    ses.send_email(
        Source=os.environ["FROM_EMAIL"],  # must be SES-verified
        Destination={"ToAddresses": [platform_admin_email]},
        Message={
            "Subject": {"Data": f"Credential Expiry Warning: {account['account_name']}"},
            "Body": {"Text": {"Data": f"Account {account['account_id']} expires in 14 days."}},
        }
    )
```

**Verify Celery app module path:**
```bash
grep -rn "celery\|Celery" /Users/apple/Desktop/threat-engine/engines/onboarding/ --include="*.py" | \
  grep -i "app\|task" | head -10
```

**FROM_EMAIL must be SES-verified in ap-south-1** — verify this before deploy.

## Security Checklist

- [ ] No `latest` image tag in K8s manifest
- [ ] SES email uses `FROM_EMAIL` from env var — not hardcoded
- [ ] `PLATFORM_ADMIN_EMAIL` from env var — not hardcoded
- [ ] DB queries scope by `tenant_id` where applicable
- [ ] No hardcoded secrets or credentials
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `kubectl get deployments -n threat-engine-engines | grep celery-beat` shows 1/1 AVAILABLE
- [ ] `kubectl logs -l app=engine-onboarding-celery-beat` shows beat schedule registered
- [ ] Task code uses `expires_at` column (C1 prerequisite verified)
- [ ] No reference to `scan_runs` in task code (C2 prerequisite verified)
- [ ] bmad-security-reviewer: no BLOCKERs (BUG-07 resolved, S-06 resolved)
- [ ] Image tag in manifest is NOT `latest` — explicit version confirmed