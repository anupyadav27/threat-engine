---
title: "Architecture — Customer Onboarding & Credential Management"
type: architecture
status: approved
version: "1.0"
date: "2026-05-11"
prd: "_bmad-output/planning-artifacts/prd.md"
sprintPlan: ".claude/planning/SPRINT-PLAN-AUTH-ONBOARDING.md"
stepsCompleted:
  - step-01-init
  - step-02-project-analysis
  - step-03-system-prompt-stack
  - step-04-core-decisions
  - step-05-patterns
  - step-06-project-structure
  - step-07-validation
---

# Architecture: Customer Onboarding & Credential Management

> **Brownfield expansion** — extends existing engines; no new service is added. All decisions are constrained by live production state verified via 4 agent audits (onboarding, platform-admin, billing, vulnerability) on 2026-05-11.

---

## 1. Project Context

### 1.1 Scope

This architecture covers the full customer provisioning lifecycle:

```
Platform Admin creates Org
  └─ Org provisioned in Django (customer_id)
  └─ Billing trial started (org_id = customer_id)
  └─ Org User(s) created + invited
       └─ User logs in, creates Tenant
       └─ Tenant adds Cloud Account(s) + Credentials
       └─ Credentials stored in AWS Secrets Manager
       └─ Credential validation (CSP-specific API call)
       └─ Schedule set (Default daily OR Adhoc)
       └─ Scan pipeline triggered
            └─ Credential expiry monitored (day 76 alert, day 90 INACTIVE)
```

### 1.2 Complexity Assessment

- **Functional Requirement count:** 43 FRs across 8 capability areas
- **NFR categories:** 6 (security, performance, reliability, observability, compliance, operational)
- **Complexity:** HIGH — credentials, multi-tenant auth, brownfield bugs, 3 engine touchpoints
- **Security classification:** CRITICAL — stores and rotates cloud provider credentials

### 1.3 PRD Reference

Full requirements at `_bmad-output/planning-artifacts/prd.md` (version 2026-05-11, all 12 steps complete).

---

## 2. Technology Stack

> All technology choices are pre-determined by the existing platform. No new frameworks are introduced.

| Layer | Technology | Constraint |
|-------|-----------|------------|
| Onboarding engine | Python 3.11, FastAPI | Port 8008, existing codebase |
| Platform identity | Django 6, DRF | `platform/cspm-backend/` |
| Platform admin engine | Python 3.11, FastAPI | Separate microservice |
| Frontend | Next.js 15, React 19 | `frontend/` |
| Database | PostgreSQL 15 (AWS RDS) | Not publicly accessible |
| Credential store | AWS Secrets Manager | SM path: `threat-engine/account/{account_id}` |
| Background tasks | Celery + Redis | Broker: Redis (added in billing sprint) |
| Container orchestration | AWS EKS, Argo Workflows | `threat-engine-engines` namespace |
| API gateway | Custom FastAPI gateway | Port 8000, BFF pattern |
| Auth | Cookie-based JWT (Django), PKCE HS256 (onboarding engine) | |

---

## 3. Live Bug Inventory

> These are **confirmed production bugs** from the 2026-05-11 agent audit. All must be fixed before any new capability ships.

| Bug ID | File | Description | Fixed In |
|--------|------|-------------|----------|
| BUG-01 | `engines/onboarding/database/scan_run_operations.py` | Writes `INSERT INTO scan_runs` — table is `scan_orchestration` | Story C2 |
| BUG-02 | `engines/onboarding/api/scans.py` | Same `scan_runs` table name reference | Story C2 |
| BUG-03 | `engines/onboarding/api/ui_data_router.py` | Same `scan_runs` table name reference | Story C2 |
| BUG-04 | `engines/onboarding/api/credentials.py` | Zero auth on store/validate/delete endpoints — **SECURITY CRITICAL** | Story C3 |
| BUG-05 | `engines/onboarding/api/cloud_accounts.py` | Missing `Depends(require_permission())` on validate-credentials, log-sources PUT/GET | Story C3 |
| BUG-06 | `engines/onboarding/orchestrator/engine_orchestrator.py` | Hardcoded `engine-cdr` reference (was `engine-ciem`) — CDR rename not propagated | Story C2 |
| BUG-07 | `engines/onboarding/tasks/credential_health_check.py` | Celery beat task code exists but no K8s manifest — never fires in production | Story C10 |

---

## 4. Database Schema

### 4.1 Database: `threat_engine_onboarding`

#### 4.1.1 `cloud_accounts` — Additive Changes Only

```sql
-- Columns to ADD (migration onboarding-001)
ALTER TABLE cloud_accounts
  ADD COLUMN IF NOT EXISTS account_type        VARCHAR(50)  NOT NULL DEFAULT 'cloud_csp',
  ADD COLUMN IF NOT EXISTS expires_at          TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_rotated_at     TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS validation_status   VARCHAR(20)  NOT NULL DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS validated_at        TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS rotation_enabled    BOOLEAN      NOT NULL DEFAULT FALSE;

-- account_type discriminator values
-- 'cloud_csp'     → AWS / Azure / GCP / OCI / AliCloud
-- 'vulnerability' → agent-based scanning
-- 'secops'        → git repository (github/gitlab/bitbucket — already exists from SECOPS sprint)

-- validation_status values: 'pending' | 'pass' | 'fail'
-- expires_at    → set to created_at + INTERVAL '90 days' at write time
-- last_rotated_at → updated each time credentials are stored/rotated in SM
```

#### 4.1.2 `agent_registrations` — New Table

```sql
CREATE TABLE IF NOT EXISTS agent_registrations (
  id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id       UUID         NOT NULL REFERENCES cloud_accounts(account_id) ON DELETE CASCADE,
  tenant_id        VARCHAR(255) NOT NULL,
  agent_token_hash VARCHAR(64)  NOT NULL UNIQUE,  -- SHA-256 of raw token; raw token never stored in DB
  status           VARCHAR(20)  NOT NULL DEFAULT 'pending',  -- 'pending' | 'connected' | 'disconnected'
  last_heartbeat   TIMESTAMPTZ,
  registered_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  connected_at     TIMESTAMPTZ,
  agent_version    VARCHAR(50),
  agent_host       VARCHAR(255),
  created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
  updated_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agent_reg_account  ON agent_registrations(account_id);
CREATE INDEX idx_agent_reg_tenant   ON agent_registrations(tenant_id);
CREATE INDEX idx_agent_reg_status   ON agent_registrations(status);
```

> **Security invariant:** `agent_token_hash` stores the SHA-256 of the raw agent token. The raw token is returned exactly once at registration time and stored in AWS Secrets Manager at `threat-engine/account/{account_id}`. Never stored in DB plaintext.

#### 4.1.3 `schedules` — Additive Changes

```sql
ALTER TABLE schedules
  ADD COLUMN IF NOT EXISTS include_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_regions  TEXT[],
  ADD COLUMN IF NOT EXISTS include_services TEXT[],
  ADD COLUMN IF NOT EXISTS exclude_services TEXT[];
```

### 4.2 Database: `threat_engine_platform` (Django)

#### 4.2.1 Already-Existing Columns (verified 2026-05-11)

- `user_auth_users.customer_id` — EXISTS (migration 0007)
- `tenant_management_tenants.customer_id` — EXISTS (migration 0007)
- `csm_groups`, `group_members`, `tenant_group_access`, `account_group_access` — EXIST

#### 4.2.2 Migration 0016 — Cleanup and Backfill

```sql
-- Step 1: Backfill customer_id on legacy rows
UPDATE user_auth_users SET customer_id = tenant_id WHERE customer_id IS NULL;
UPDATE tenant_management_tenants SET customer_id = id WHERE customer_id IS NULL;

-- Step 2: Add tenant_type column
ALTER TABLE tenant_management_tenants
  ADD COLUMN IF NOT EXISTS tenant_type VARCHAR(30) NOT NULL DEFAULT 'cloud';
  -- values: 'cloud' | 'vulnerability' | 'secops'

-- Step 3 (post-deploy, manual): enforce NOT NULL after backfill verified
-- ALTER TABLE user_auth_users ALTER COLUMN customer_id SET NOT NULL;
-- ALTER TABLE tenant_management_tenants ALTER COLUMN customer_id SET NOT NULL;
```

---

## 5. API Contracts

### 5.1 Platform Admin Engine — New Endpoints

#### `POST /api/v1/padmin/orgs`

Creates a new customer org. Only callable by `platform_admin` role.

```
POST /api/v1/padmin/orgs
Authorization: access_token cookie (platform_admin role required)

Request:
{
  "org_name": "Acme Corp",
  "org_domain": "acme.com",
  "plan": "pro",            // "trial" | "pro" | "enterprise"
  "initial_users": [
    {
      "email": "admin@acme.com",
      "role": "org_admin",  // "org_admin" | "tenant_admin" | "analyst" | "viewer"
      "send_invite": true
    }
  ]
}

Response 201:
{
  "customer_id": "cust_<uuid>",
  "org_name": "Acme Corp",
  "billing_org_id": "cust_<uuid>",   // same value as customer_id — aligned on creation
  "trial_end_date": "2026-05-25",
  "initial_users_created": 1,
  "invite_emails_sent": 1
}
```

**Side effects (saga pattern; compensate on billing failure):**
1. Django: create org entry with `customer_id`
2. Billing: `POST /api/v1/billing/trial/provision` with `org_id = customer_id`
3. Django: create initial user accounts + send invite emails via SES
4. Onboarding: async `sync_tenant_to_onboarding` Celery task (non-blocking)

**Error cases:**
- 409 if `org_domain` already registered
- 503 if billing provision fails → rollback Django org creation

### 5.2 Onboarding Engine — New / Modified Endpoints

#### `POST /api/v1/cloud-accounts/{id}/agent-token` (exists — verify PKCE gate)

```
POST /api/v1/cloud-accounts/{id}/agent-token
Authorization: X-PKCE-Verifier header

Response 200:
{
  "install_command": "curl ... | bash -s -- --tenant <tid> --token <raw_token>",
  "token_expires_in": 1800,
  "account_id": "<id>"
}
```

#### `GET /api/v1/agent/heartbeat` (agent poll — new)

```
GET /api/v1/agent/heartbeat
Authorization: Bearer <raw_agent_token>

Response 200:
{
  "status": "ok",
  "run_now": false,   // set true when user triggers run-now for this agent account
  "updated_at": "<iso8601>"
}
```

#### `POST /api/v1/scans/run-now` (new)

```
POST /api/v1/scans/run-now
Requires: scans:create permission

Request: { "account_id": "<uuid>", "tenant_id": "<tid>" }
Response 202: { "scan_run_id": "<uuid>", "status": "queued" }
```

#### `POST /api/v1/scans/run-all` (new)

```
POST /api/v1/scans/run-all
Requires: scans:create + (platform_admin OR org_admin role)

Request: { "tenant_id": "<tid>" }
Response 202:
{
  "triggered": [{"account_id": "...", "scan_run_id": "..."}, ...],
  "skipped":   [{"account_id": "...", "reason": "INACTIVE credential"}]
}
```

#### `PATCH /api/v1/schedules/{id}` — Region/Service Scope (closes gap S-04)

```
PATCH /api/v1/schedules/{id}
{
  "include_regions": ["us-east-1", "us-west-2"],
  "exclude_regions": [],
  "include_services": [],
  "exclude_services": ["s3", "glacier"]
}
```

### 5.3 Django APIs — New Endpoints

| Method + Path | Story | Permission |
|---|---|---|
| `POST /api/users/invite` | D2 | users:write |
| `GET/POST /api/groups` | D1 | users:write |
| `PATCH/DELETE /api/groups/{id}` | D1 | users:write |
| `POST /api/groups/{id}/tenants` | D3 | users:write |
| `POST /api/groups/{id}/accounts` | D3 | users:write |
| `GET/PATCH /api/org/profile` | D4 | orgs:read / orgs:write |

---

## 6. Implementation Patterns

### 6.1 RBAC Enforcement — 3-Layer Rule

```
Gateway (middleware.js)
  ├─ Validates access_token cookie → builds AuthContext
  ├─ Sets X-Auth-Context header
  └─ Blocks 401 if token invalid

Engine (FastAPI)
  ├─ Depends(require_permission("feature:action"))
  ├─ tenant_id from X-Auth-Context ONLY — never from request body
  └─ 403 if permission missing

Database
  └─ WHERE tenant_id = $auth_context.tenant_id on ALL queries
```

**Required permissions by new endpoint:**

| Endpoint | Permission |
|----------|-----------|
| POST /padmin/orgs | padmin:write |
| GET /api/agent/heartbeat | accounts:read (agent token) |
| POST /scans/run-now | scans:create |
| POST /scans/run-all | scans:create (platform_admin or org_admin only) |
| PATCH /schedules/{id} | scans:create |
| POST /api/users/invite | users:write |
| GET/POST /api/groups | users:write |

### 6.2 Credential Lifecycle Pattern

```
Registration (frontend form submission)
  → PATCH /cloud-accounts/{id}/deployment
  → Validate required fields by account_type (table in §6.2.1)
  → NO credentials stored in DB — only metadata

Store (onboarding engine)
  → AWS SM PutSecretValue at threat-engine/account/{account_id}
  → On success: SET last_rotated_at = NOW(), expires_at = NOW() + INTERVAL '90 days'

Validate (onboarding engine)
  → SM GetSecretValue → call CSP validation API (table in §6.2.2)
  → UPDATE: validation_status = 'pass'|'fail', validated_at = NOW()

Expiry monitor (Celery beat — weekly, Monday 3AM UTC)
  → Scan WHERE expires_at < NOW() + INTERVAL '14 days'
  → Day 76 (14 days before): SES email → org_admin + platform_admin
  → Day 90+: SET status = 'INACTIVE' → scans blocked until re-provisioned
```

#### 6.2.1 Credential Fields by account_type

| account_type | provider | Required credential fields |
|---|---|---|
| cloud_csp | aws | `access_key_id` + `secret_access_key` OR `assume_role_arn` |
| cloud_csp | azure | `client_id`, `client_secret`, `tenant_id`, `subscription_id` |
| cloud_csp | gcp | `service_account_key_json` (base64-encoded) |
| cloud_csp | oci | `user_ocid`, `tenancy_ocid`, `key_fingerprint`, `private_key` |
| cloud_csp | alicloud | `access_key_id`, `access_key_secret` |
| vulnerability | any | `agent_token` (generated by platform; stored in SM) |
| secops | github/gitlab/bitbucket | `git_url` + `pat` OR `ssh_private_key` |

#### 6.2.2 Validation API by CSP

| provider | Validation call |
|----------|----------------|
| aws | `sts:GetCallerIdentity` |
| azure | ARM token exchange + `subscriptions/{id}/resourceGroups` GET |
| gcp | `projects.get` with SA token |
| oci | IAM `GetUser` |
| alicloud | STS `GetCallerIdentity` |
| vulnerability | GET `/api/v1/agent/status/{agent_token}` on VUL engine |
| secops | `git ls-remote` (read-only connectivity check) |

### 6.3 AWS Secrets Manager Pattern

```python
# Path convention — never deviate
SM_PATH = f"threat-engine/account/{account_id}"

# Write
sm_client.put_secret_value(
    SecretId=SM_PATH,
    SecretString=json.dumps(credential_dict),
    KmsKeyId=os.environ["AWS_SM_KMS_KEY_ID"]
)

# Read (validation time)
response = sm_client.get_secret_value(SecretId=SM_PATH)
creds = json.loads(response["SecretString"])
# SM returns a string — json.loads IS correct here (unlike psycopg2 JSONB)
```

### 6.4 org_id ↔ customer_id Alignment Pattern

Billing engine uses `org_id`. Django/onboarding uses `customer_id`. They MUST hold the same value, set at org creation time.

```python
# Platform admin org creation saga
async def create_org(org_data: OrgCreate) -> dict:
    customer_id = f"cust_{uuid4().hex[:12]}"

    # 1. Django org
    django_resp = await django_api.post("/api/orgs/", {"customer_id": customer_id, ...})

    # 2. Billing — pass customer_id AS org_id (alignment point)
    billing_resp = await billing_api.post(
        "/api/v1/billing/trial/provision",
        {"org_id": customer_id, "plan": org_data.plan, ...},
        headers={"X-Internal-Secret": INTERNAL_SECRET}
    )
    if billing_resp.status != 200:
        await django_api.delete(f"/api/orgs/{customer_id}")  # compensate
        raise BillingProvisionError(billing_resp.text)

    return {"customer_id": customer_id, "billing_org_id": customer_id}
```

### 6.5 VUL Agent Token Pattern (MVP)

```
1. Onboarding generates raw_agent_token = str(uuid4())
2. DB stores SHA-256(raw_agent_token) in agent_registrations.agent_token_hash
3. SM stores raw_agent_token at threat-engine/account/{account_id}
4. Install command: curl ... | bash -s -- --tenant <tid> --token <raw_agent_token>
5. VUL engine authenticates agent against static API_KEYS env var list
   → Platform admin injects raw_agent_token into VUL engine API_KEYS on account creation
```

> **Post-MVP:** Replace static API_KEYS injection with full JWT verification against onboarding PKCE endpoint. MVP uses env var injection for velocity.

### 6.6 scan_orchestration Table Name

The table is `scan_orchestration`. Never `scan_runs`. All 3 BUG-01/02/03 files must be fixed before any C-sprint work merges.

```bash
# Verify fix is complete
grep -r "scan_runs" engines/onboarding/ --include="*.py"
# Expected output: (empty)
```

### 6.7 JSONB Handling

```python
# psycopg2 JSONB → already a Python dict. Never call json.loads().
engines_completed = row["engines_completed"]   # already dict
include_services = row["include_services"]     # already list

# AWS Secrets Manager → returns str. Always call json.loads().
creds = json.loads(sm_response["SecretString"])  # correct
```

### 6.8 Celery Beat Deployment Pattern

The credential expiry task (`credential.health_check`) must run as a separate K8s container. Never co-locate Celery beat with the FastAPI server.

```yaml
# deployment/aws/eks/engines/engine-onboarding.yaml — add second Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: engine-onboarding-celery-beat
  namespace: threat-engine-engines
spec:
  replicas: 1   # exactly 1 replica — beat must be singleton
  template:
    spec:
      containers:
      - name: celery-beat
        image: yadavanup84/threat-engine-onboarding-api:<tag>
        command: ["celery", "-A", "tasks.celery_app", "beat", "--loglevel=info"]
        envFrom:
        - configMapRef: {name: threat-engine-db-config}
        - secretRef: {name: threat-engine-secrets}
```

---

## 7. Project Structure — File Mapping

### 7.1 New Files

| File | Story | Purpose |
|------|-------|---------|
| `engines/onboarding/database/migrations/onboarding-001-account-type.sql` | C1 | account_type, expires_at, agent_registrations, schedule regions |
| `engines/onboarding/routers/agent.py` | C4 | PKCE bootstrap + heartbeat endpoints |
| `engines/onboarding/routers/bulk_scans.py` | C9 | run-all endpoint |
| `engines/platform-admin/routers/org_provisioning.py` | D-saga | POST /padmin/orgs saga |
| `platform/cspm-backend/tenant_management/migrations/0016_cleanup_customer_id.py` | A1 | customer_id backfill + tenant_type |
| `platform/cspm-backend/user_management/views/invite.py` | D2 | User invite API |
| `platform/cspm-backend/group_management/` (dir) | D1, D3 | Group CRUD + assignment |
| `frontend/src/app/(portal)/onboarding/` (dir) | D7–D11 | Onboarding wizard pages |
| `frontend/src/app/(portal)/users/` (dir) | D12 | User/group management pages |

### 7.2 Files to Modify

| File | Stories | Changes |
|------|---------|---------|
| `engines/onboarding/database/scan_run_operations.py` | C2 | `scan_runs` → `scan_orchestration` |
| `engines/onboarding/api/scans.py` | C2 | `scan_runs` → `scan_orchestration` |
| `engines/onboarding/api/ui_data_router.py` | C2 | `scan_runs` → `scan_orchestration`; fix CDR name |
| `engines/onboarding/api/cloud_accounts.py` | C3, C5, C6 | Add `Depends(require_permission())` to 3 endpoints; account_type validation |
| `engines/onboarding/orchestrator/engine_orchestrator.py` | C2 | Fix `engine-cdr` hardcoded reference |
| `engines/onboarding/models/schedule.py` | C8 | Add include/exclude region + service fields |
| `engines/platform-admin/routers/orgs.py` | D-saga | Add POST org creation |
| `platform/cspm-backend/tenant_management/views.py` | B3 | Add `CookieTokenAuthentication` to TenantViewSet |
| `platform/cspm-backend/user_management/views.py` | B1, B2, B4 | Rate limiting, Google hd validation, org-boundary filter |
| `platform/cspm-backend/services/provisioning.py` | A2 | Rename to `provision_tenant_for_new_user()` |
| `shared/api_gateway/bff/onboarding.py` | D5, D6 | Schedule CRUD + scan history BFF views |
| `deployment/aws/eks/engines/engine-onboarding.yaml` | C10 | Add Celery beat Deployment block |

### 7.3 Files to Delete

| File | Reason |
|------|--------|
| `engines/onboarding/api/credentials.py` | BUG-04 — zero auth on all endpoints (SECURITY CRITICAL). All credential routes migrated into `cloud_accounts.py` with `require_permission()` guards. |

---

## 8. Security Architecture

### 8.1 STRIDE Threat Map

| Threat | Component | Mitigation |
|--------|-----------|-----------|
| **S**poofing | Credential endpoints | `require_permission()` on every endpoint; BUG-04/05 fix |
| **T**ampering | SM credential path | IAM policy: engine role → `threat-engine/account/*` prefix only |
| **R**epudiation | Org provisioning | Django audit log on every `POST /padmin/orgs` |
| **I**nformation disclosure | Agent token | Raw token returned once; SHA-256 hash only in DB |
| **D**enial of service | Auth endpoints | Django Ratelimit on login/registration (story B1) |
| **E**levation of privilege | Google OAuth / org boundary | `hd` domain validation (B2); customer_id scoping (B4) |

### 8.2 OWASP SAMM Controls

| Function | Control |
|----------|---------|
| Design/Threat Assessment | STRIDE above + PASTA credential model reviewed in B-sprint gate |
| Implementation/Secure Build | SLSA L1: pinned base images, no `latest` tags |
| Implementation/Secure Coding | Parameterized queries only; no raw SQL string concatenation |
| Verification/Security Testing | RBAC matrix (5 roles × all new endpoints) before D closes |

### 8.3 CSA CCM v4 Domain Mapping

| Capability | CCM Domain |
|-----------|-----------|
| Credential storage in SM | IAM-09 |
| 90-day expiry + rotation | IAM-14 |
| Org boundary enforcement | AIS-04 |
| Audit log on org creation | LOG-05 |

### 8.4 NIST CSF 2.0 Tags

| Sprint group | NIST function |
|-------------|--------------|
| Sprint A — DB foundation | GV (Govern) |
| Sprint B — auth fixes | PR.AC (Protect — Access Control) |
| Sprint C — onboarding engine | PR.DS (Protect — Data Security) |
| Sprint D — UI wizard | DE.AE (Detect — Adverse Events) |

---

## 9. Cross-Engine Dependencies

```
platform-admin engine
  ├──► Django API            POST /api/orgs/
  ├──► Billing engine        POST /api/v1/billing/trial/provision (X-Internal-Secret)
  └──► Onboarding Celery     sync_tenant_to_onboarding (async)

onboarding engine
  ├──► AWS Secrets Manager   PUT/GET threat-engine/account/{account_id}
  ├──► CSP APIs              sts:GetCallerIdentity, ARM token, projects.get, etc.
  ├──► VUL engine            GET /api/v1/agent/status/{token}
  └──► Argo Workflows        trigger-scan.sh → full pipeline

Celery beat (onboarding)
  ├──► cloud_accounts table  query expiring accounts
  └──► AWS SES               expiry notification emails

scan_orchestration table
  └──► ALL downstream engines read via get_orchestration_metadata(scan_run_id)
       BUG-01/02/03 fix ensures onboarding writes the correct table
```

---

## 10. Deployment Plan

### 10.1 Sprint A (DB + Django Foundation)

```bash
# 1. Apply Django migration
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py migrate tenant_management 0016

# 2. Verify backfill
kubectl exec -n threat-engine-engines deployment/cspm-backend -- \
  python manage.py shell -c \
  "from django.contrib.auth import get_user_model; \
   print(get_user_model().objects.filter(customer_id=None).count())"
# Expected: 0

# 3. Build + push + deploy cspm-backend
docker build -t yadavanup84/cspm-django-backend:v-onboard-a1 \
  -f platform/cspm-backend/Dockerfile .
docker push yadavanup84/cspm-django-backend:v-onboard-a1
kubectl set image deployment/cspm-backend \
  cspm-backend=yadavanup84/cspm-django-backend:v-onboard-a1 \
  -n threat-engine-engines
kubectl rollout status deployment/cspm-backend -n threat-engine-engines
```

### 10.2 Sprint C (Onboarding Engine — strict order)

1. Apply onboarding DB migration (C1) — verify `\d cloud_accounts` shows new columns
2. Deploy auth middleware (C3) — verify Argo pipeline callback still authenticates
3. Deploy remaining C stories as one image build
4. Deploy Celery beat manifest (C10) as separate Deployment — verify task fires

### 10.3 Sprint D (Frontend + Django APIs)

1. Deploy Django API stories D1–D6 as incremental cspm-backend images
2. Deploy platform-admin org provisioning after billing alignment verified
3. Deploy frontend stories D7–D12 as one frontend image build

### 10.4 Post-Deploy Manual Steps

```sql
-- After B4 confirmed working: grant org_admin writes
INSERT INTO role_permissions (id, role_id, permission_id, created_at, updated_at)
SELECT gen_random_uuid()::text, r.id, p.id, NOW(), NOW()
FROM roles r, permissions p
WHERE r.name = 'org_admin' AND p.key IN ('orgs:write', 'users:write')
ON CONFLICT DO NOTHING;

-- After A1 backfill verified: enforce NOT NULL
ALTER TABLE user_auth_users ALTER COLUMN customer_id SET NOT NULL;
ALTER TABLE tenant_management_tenants ALTER COLUMN customer_id SET NOT NULL;
```

---

## 11. Story File Index

> Story files live in `.claude/planning/stories/`. Create before implementation starts.

| Story ID | Title | Sprint |
|----------|-------|--------|
| auth-A1 | Django migrations — cleanup + customer_id backfill + tenant_type | A |
| auth-A2 | provision_tenant_for_new_user() | A |
| auth-A3 | Async Celery tenant sync + resync endpoint | A |
| auth-B1 | Email enumeration fix + rate limiting + CAPTCHA | B |
| auth-B2 | Google OAuth hd domain validation | B |
| auth-B3 | TenantViewSet DRF auth + export filter + IDP rate limit | B |
| auth-B4 | org_admin org-boundary + remove developer bypass | B |
| onboarding-C1 | Apply account_type + agent_registrations migration | C |
| onboarding-C2 | Fix scan_runs → scan_orchestration (3 files) + CDR reference + delete credentials.py | C |
| onboarding-C3 | Auth middleware (BUG-04/05) — add require_permission() to 3 endpoints | C |
| onboarding-C4 | PKCE agent bootstrap + heartbeat endpoint | C |
| onboarding-C5 | account_type validation against tenant_type | C |
| onboarding-C6 | RBAC on schedule + cloud_account endpoints | C |
| onboarding-C7 | Ad-hoc scan endpoint (run-now) | C |
| onboarding-C8 | exclude_regions / include_regions on Schedule ORM | C |
| onboarding-C9 | Bulk run-all schedules endpoint | C |
| onboarding-C10 | Credential expiry Celery health-check task + K8s beat manifest | C |
| onboarding-D1 | Group management API (Django) | D |
| onboarding-D2 | User invite flow API (Django) | D |
| onboarding-D3 | Group access assignment API (Django) | D |
| onboarding-D4 | Org profile + tenant-type API (Django) | D |
| onboarding-D5 | Schedule CRUD API with region/service scope (BFF) | D |
| onboarding-D6 | Scan run history + re-run API (BFF) | D |
| onboarding-D7 | Frontend: tenant-type selector + org/tenant switcher | D |
| onboarding-D8 | Frontend: onboarding wizard credential form (catalog-driven) | D |
| onboarding-D9 | Frontend: agent install flow (PKCE) UI | D |
| onboarding-D10 | Frontend: schedule modal + region/service scope selection | D |
| onboarding-D11 | Frontend: run-now + bulk scan-all + scan progress page | D |
| onboarding-D12 | Frontend: user/group management pages | D |

---

## 12. Architecture Validation Checklist

- [x] No new technology introduced — brownfield constraint honored
- [x] All 43 FRs have a story or file reference addressing them
- [x] All 7 live bugs cataloged with fix assignment (BUG-01 through BUG-07)
- [x] DB schema changes are additive only — no destructive column changes in live tables
- [x] `customer_id` backfill strategy defined before NOT NULL constraint applied
- [x] `org_id` ↔ `customer_id` alignment enforced at org creation time
- [x] Agent token: raw token never stored in DB; SHA-256 hash only
- [x] SM path convention: `threat-engine/account/{account_id}` throughout
- [x] `scan_orchestration` table name enforced — grep gate in story C2 DoD
- [x] `json.loads()` only on SM responses; never on psycopg2 JSONB results
- [x] RBAC: 3-layer enforcement documented for all new endpoints
- [x] Celery beat: separate K8s Deployment (singleton replica — not co-located with FastAPI)
- [x] Legacy `credentials.py` router deleted (BUG-04 SECURITY CRITICAL)
- [x] Billing compensation pattern defined for org creation saga failure
- [x] VUL agent token injection: MVP = API_KEYS; post-MVP = JWT — decision documented
- [x] STRIDE, OWASP SAMM, NIST CSF 2.0, CSA CCM v4 mappings present

**Architecture approved. Next: generate 29 story files (bmad-po) → implement (bmad-dev).**
