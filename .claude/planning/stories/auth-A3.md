---
id: auth-A3
title: "Async Celery tenant sync + resync endpoint"
sprint: A
points: 1
depends_on: [auth-A2]
blocks: []
security_blocks: [BLOCK-12]
nist_csf: GV
owasp_samm: Implementation
csa_ccm: AIS-04
status: in_progress
---

## Context

BLOCK-12 identified that tenant provisioning in Django calls the onboarding engine synchronously during the user signup/invite-accept flow. This blocks the HTTP response and fails the whole flow if the onboarding engine is temporarily unreachable. This story wires a Celery task `sync_tenant_to_onboarding` that is dispatched asynchronously after `provision_tenant_for_new_user()` completes. It also adds a `POST /api/tenants/{id}/sync` endpoint so platform admins can manually re-trigger a failed sync. The Celery broker is Redis (added in the billing sprint and already live in the cluster). The `celery_tasks.py` file already exists in `platform/cspm-backend/user_auth/celery_tasks.py` — check what tasks exist before adding.

## Acceptance Criteria

- [ ] AC1: Celery task `sync_tenant_to_onboarding(tenant_id: str, customer_id: str)` exists in `platform/cspm-backend/user_auth/celery_tasks.py`.
- [ ] AC2: Task calls `POST /internal/tenants/sync` (or equivalent) on the onboarding engine with `tenant_id` and `customer_id` payload using `X-Internal-Secret` header.
- [ ] AC3: Task implements retry logic: `max_retries=3`, `countdown=30` seconds between retries.
- [ ] AC4: `provision_tenant_for_new_user()` (from auth-A2) calls `sync_tenant_to_onboarding.delay(tenant_id, customer_id)` after successful tenant creation — not `call()`.
- [ ] AC5: `POST /api/tenants/{tenant_id}/sync` endpoint exists in Django, requires `platform_admin` role, dispatches the Celery task.
- [ ] AC6: The resync endpoint returns 202 with `{"task_id": "<celery_task_id>", "tenant_id": str}`.
- [ ] AC7: If the onboarding engine call returns non-2xx after all retries, the task logs the failure but does NOT raise an exception that would crash the signup flow.
- [ ] AC8: BLOCK-12 addressed: HTTP response to user is never blocked by onboarding engine availability.
- [ ] AC9: Unit test: assert `sync_tenant_to_onboarding.delay` is called (not `sync_tenant_to_onboarding`) when `provision_tenant_for_new_user` runs.

## Key Files

- `platform/cspm-backend/user_auth/celery_tasks.py` — Add `sync_tenant_to_onboarding` task
- `platform/cspm-backend/services/provisioning.py` — Call `.delay()` after tenant creation (from auth-A2)
- `platform/cspm-backend/tenant_management/views.py` — Add `POST /api/tenants/{id}/sync` endpoint
- `platform/cspm-backend/tenant_management/urls.py` — Wire the new URL
- `platform/cspm-backend/celery_app.py` (or equivalent) — Ensure broker points to Redis

## Technical Notes

**Celery task signature:**
```python
from celery import shared_task
import requests
import os

@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def sync_tenant_to_onboarding(self, tenant_id: str, customer_id: str):
    """Async sync newly provisioned tenant to onboarding engine."""
    try:
        onboarding_url = os.environ["ONBOARDING_ENGINE_URL"]
        secret = os.environ["X_INTERNAL_SECRET"]
        resp = requests.post(
            f"{onboarding_url}/internal/tenants/sync",
            json={"tenant_id": tenant_id, "customer_id": customer_id},
            headers={"X-Internal-Secret": secret},
            timeout=10,
        )
        resp.raise_for_status()
    except Exception as exc:
        raise self.retry(exc=exc)
```

**Resync endpoint (Django view):**
```python
# requires permission: platform:admin
@require_permission_drf("platform:admin")
def sync_tenant(request, tenant_id):
    task = sync_tenant_to_onboarding.delay(tenant_id, request.user.customer_id)
    return JsonResponse({"task_id": task.id, "tenant_id": tenant_id}, status=202)
```

**Redis broker:** Already running as `redis-service.threat-engine-engines.svc.cluster.local:6379`. Check existing Celery config in `platform/cspm-backend/`.

**ONBOARDING_ENGINE_URL** env var value: `http://engine-onboarding.threat-engine-engines.svc.cluster.local:8008`

**X_INTERNAL_SECRET**: Must be sourced from `threat-engine-secrets` K8s secret — never hardcoded.

**Verify Celery broker config:**
```bash
grep -r "CELERY_BROKER_URL\|broker_url" /Users/apple/Desktop/threat-engine/platform/cspm-backend/ --include="*.py"
```

## Security Checklist

- [ ] `require_permission()` present on the resync endpoint (`platform:admin` permission)
- [ ] `tenant_id` sourced from path param (not request body) — validated against user's `customer_id`
- [ ] `X-Internal-Secret` loaded from environment, never hardcoded
- [ ] bmad-security-reviewer gate passed before merge

## Definition of Done

- [ ] All ACs pass
- [ ] `grep -r "organizations\|org_id" platform/` returns no new hits in changed files
- [ ] Unit tests: `.delay()` called (not `.call()`); retry logic exercised with mock
- [ ] bmad-security-reviewer: no BLOCKERs
- [ ] `kubectl rollout status deployment/cspm-backend -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl rollout status deployment/cspm-celery-worker -n threat-engine-engines` shows AVAILABLE
- [ ] `kubectl logs -l app=cspm-backend -n threat-engine-engines` shows no ERROR in first 60s
- [ ] Post-deploy: curl gateway health-check 200