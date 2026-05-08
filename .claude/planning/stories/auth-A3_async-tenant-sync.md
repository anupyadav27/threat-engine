# Story: Auth-A3 — Async Tenant Sync (Celery Task + Dead-Letter + Resync Endpoint)

## Status: ready

## Context

`_sync_tenant_to_onboarding()` currently runs inside `transaction.atomic()` in
`provision_first_tenant()`. This is an HTTP call to the onboarding engine running in a
separate pod. If the onboarding engine is slow or unavailable, the entire signup
transaction rolls back, leaving the user with a failed account creation and no clear
recovery path. This directly violates NIST CSF 2.0 RC (Recovery) and creates a DoS
vector (BLOCK-12 / T1499).

Story A-2 already removes the HTTP call from `transaction.atomic()`. This story adds the
async delivery mechanism: a Celery task `sync_tenant_to_onboarding` that runs outside the
transaction, with exponential backoff retries, a dead-letter handler that sets
`tenant.status='sync_failed'` and fires an alert, and a `POST /api/v1/tenants/{id}/resync`
endpoint for `platform_admin` to manually re-trigger a failed sync.

**Points:** Medium (1–2 days). New Celery task file, one new DRF endpoint, K8s env var
documentation. No new DB table. Requires Redis broker.

**Dependencies:** Auth-A1 (Tenants.status column must accept `'sync_failed'`), Auth-A2
(provision_org_and_tenant returns without calling sync — A-3 wires the post-transaction
task dispatch).

---

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [x] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV Govern  [ ] ID Identify  [ ] PR Protect  [ ] DE Detect  [x] RS Respond  [x] RC Recover

**CSA CCM v4 Domain(s)**
- CCM: BCR-11 (Business Continuity Management — sync failure recovery), SEF-02 (Incident
  Management), IVS-07 (Network Security — internal service call isolation)

---

## Threat Model

### STRIDE

| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Spoofing | Celery task message | Attacker injects fabricated task message into Redis queue to create arbitrary tenants in onboarding engine | Celery broker uses `CELERY_BROKER_URL` with auth; task accepts only `tenant_id` (UUID) + `customer_id` (UUID); onboarding engine validates tenant_id ownership on receipt |
| Tampering | Dead-letter handler | Persistent `sync_failed` status could be cleared by anyone with `tenants:write` | `/resync` endpoint restricted to `platform_admin` only; `sync_failed` status set by system only |
| Info Disclosure | Celery task payload | Task args might contain sensitive fields if payload is logged | Payload contains only UUIDs (tenant_id, customer_id) — no credentials, no PII |
| DoS | `/resync` endpoint | Malicious platform_admin repeatedly re-enqueues sync for a tenant, flooding onboarding engine | `/resync` returns 409 if tenant.status is already `active` (sync already completed); rate limit 10/min per admin |
| DoS | Exponential backoff exhausted | After 5 retries, `sync_failed` status is set — no infinite retry loop | `max_retries=5` with `countdown = 2^attempt`; after exhaustion, dead-letter handler is called exactly once |

### PASTA (credentials/IAM — internal service call)

| Stage | Adversary Goal | Attack Path | Countermeasure |
|-------|---------------|-------------|----------------|
| Lateral movement | Trigger arbitrary tenant creation in onboarding engine | POST to `ONBOARDING_ENGINE_URL/tenants` directly from attacker-controlled host | ONBOARDING_ENGINE_URL is K8s cluster-internal; not reachable from outside cluster (K8s NetworkPolicy) |
| SSRF | Redirect sync HTTP call to internal service | Craft `tenant_name` containing SSRF payload sent to onboarding URL | `ONBOARDING_ENGINE_URL` is a static env var, not derived from request body; payload is JSON-serialized UUIDs only |

---

## MITRE ATT&CK Techniques Addressed

| Technique ID | Name | D3FEND Countermeasure | How this story addresses it |
|-------------|------|----------------------|----------------------------|
| T1499 | Endpoint Denial of Service | D3-NTF Network Traffic Filtering | HTTP call moved out of transaction; onboarding engine unavailability no longer blocks signup |
| T1071.001 | Web Protocol C2 (SSRF via ONBOARDING_ENGINE_URL) | D3-NTF Network Traffic Filtering (K8s NetworkPolicy) | ONBOARDING_ENGINE_URL is static cluster-internal URL; task payload contains only UUIDs |

---

## Acceptance Criteria (Functional)

1. New file `platform/cspm-backend/user_auth/tasks/celery_tasks.py` (or `user_auth/celery_tasks.py`) contains `sync_tenant_to_onboarding` Celery task:
   - Signature: `@app.task(bind=True, max_retries=5, queue="tenant-sync") def sync_tenant_to_onboarding(self, tenant_id, customer_id)`
   - On HTTP 200 or 201: sets `Tenants.objects.filter(id=tenant_id).update(status="active")`, logs success.
   - On HTTP 409: treats as success (idempotent — tenant already exists in onboarding engine), sets status `active`.
   - On HTTP 4xx (not 409): does NOT retry; calls dead-letter handler immediately (configuration error, not transient).
   - On HTTP 5xx or network error: `self.retry(countdown=2 ** self.request.retries, exc=exc)`.
   - After `max_retries` exhausted (Celery raises `MaxRetriesExceededError`): dead-letter handler sets `tenant.status='sync_failed'` and calls `log_auth_event("tenant.sync_failed", extra={"tenant_id": tenant_id})`.
2. `provision_org_and_tenant()` in `tenant_utils.py` (from A-2) — after the `transaction.atomic()` block, calls:
   ```python
   from user_auth.celery_tasks import sync_tenant_to_onboarding
   sync_tenant_to_onboarding.apply_async(
       args=[tenant_id, str(user.customer_id)],
       queue="tenant-sync",
   )
   ```
3. New endpoint `POST /api/v1/tenants/{tenant_id}/resync/`:
   - Auth: `platform_admin` only — validated via cookie session + `platform_admin` role check.
   - Body: empty (no body required).
   - Action: re-enqueues `sync_tenant_to_onboarding.apply_async(args=[tenant_id, customer_id])`.
   - Returns 200 `{"message": "Resync enqueued"}` on success.
   - Returns 409 `{"message": "Tenant is already active"}` if `tenant.status == "active"`.
   - Returns 403 if caller is not `platform_admin`.
4. Django K8s deployment manifest (`deployment/aws/eks/engines/cspm-portal.yaml` or equivalent Django deployment) must document `CELERY_BROKER_URL` as a required env var. If Redis is not available, the task is called synchronously with a warning log (graceful degradation: `sync_tenant_to_onboarding.apply_async(...)` falls back to `.delay()` which fails gracefully if broker is down — the `sync_failed` dead-letter path handles recovery).
5. Celery worker K8s deployment or container spec documents `queues=tenant-sync` in the worker command.
6. `Tenants.status` field accepts the value `'sync_failed'` — no DB constraint prevents this (current `CharField(max_length=50)` already allows arbitrary strings).

---

## Acceptance Criteria (Security — must pass bmad-security-reviewer)

- [ ] Celery task payload contains ONLY `tenant_id` (UUID) and `customer_id` (UUID) — no email, no credentials, no company name, no org_id.
- [ ] Dead-letter handler uses `log_auth_event("tenant.sync_failed", ...)` — never logs full exception traceback at WARNING or above (use DEBUG for stack trace).
- [ ] `/resync` endpoint enforces `platform_admin` role — returns 403 for `org_admin`, `tenant_admin`, `analyst`, `viewer`.
- [ ] `/resync` does not expose `customer_id` from the response body.
- [ ] All new DB queries include `id=tenant_id` filter (single-row update) — no unbounded scans.
- [ ] `ONBOARDING_ENGINE_URL` is validated at Django startup to be an http/https URL — `AppConfig.ready()` check; raise `ImproperlyConfigured` if it contains `@` (credentials in URL) or resolves to a loopback/metadata address.
- [ ] No plaintext credentials in Celery task args or result backend.
- [ ] BLOCK-12 explicitly closed: async sync is now outside transaction.atomic() — confirmed by test that asserts the Celery task is called after `transaction.on_commit()` fires.
- [ ] New findings mapped to at least one CCM v4 control (BCR-11).

---

## Technical Notes

### Celery app setup

If a `celery.py` or `celery_app.py` does not yet exist in the Django project:
```python
# platform/cspm-backend/cspm_backend/celery.py
import os
from celery import Celery
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cspm_backend.settings')
app = Celery('cspm_backend')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
```
`CELERY_BROKER_URL` must be set in `settings.py` (read from env: `os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")`).

### transaction.on_commit pattern

The preferred pattern to guarantee the task fires only after the transaction commits:
```python
from django.db import transaction
transaction.on_commit(lambda: sync_tenant_to_onboarding.apply_async(
    args=[tenant_id, str(user.customer_id)],
    queue="tenant-sync",
))
```
This is placed in `provision_org_and_tenant()` AFTER the `with transaction.atomic():` block.

### Resync endpoint URL routing

Add to Django URL configuration:
```python
path("api/v1/tenants/<str:tenant_id>/resync/", ResyncTenantView.as_view()),
```

### Dead-letter handler note

Celery does not have a built-in dead-letter queue; the `MaxRetriesExceededError` is caught
in the task body:
```python
except MaxRetriesExceededError:
    Tenants.objects.filter(id=tenant_id).update(status="sync_failed")
    log_auth_event("tenant.sync_failed", extra={"tenant_id": tenant_id})
```

---

## Key Files

- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/utils/tenant_utils.py` — add `transaction.on_commit(...)` after atomic block
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/user_auth/celery_tasks.py` — new file
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/tenant_management/views.py` — add `ResyncTenantView`
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_backend/celery.py` — new file (if not exists)
- `/Users/apple/Desktop/threat-engine/platform/cspm-backend/cspm_backend/settings.py` — add `CELERY_BROKER_URL`
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/cspm-portal.yaml` — document env var

---

## Definition of Done

- [ ] Unit test: `test_sync_task_success` — mock HTTP 200, asserts tenant.status='active'
- [ ] Unit test: `test_sync_task_409_idempotent` — mock HTTP 409, asserts tenant.status='active' (not sync_failed)
- [ ] Unit test: `test_sync_task_dead_letter` — mock 5 consecutive 503s, asserts tenant.status='sync_failed' and log_auth_event called with "tenant.sync_failed"
- [ ] Unit test: `test_resync_endpoint_platform_admin_only` — org_admin gets 403, platform_admin gets 200
- [ ] `transaction.on_commit` assertion: task is NOT enqueued if the surrounding transaction rolls back
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] Memory updated: record `POST /api/v1/tenants/{id}/resync/` in API_REFERENCE_ALL_ENGINES.md
