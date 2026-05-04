# Architecture Design — Auth, Onboarding & Scheduling

**Date:** 2026-05-03  
**Status:** Approved for sprint planning  
**Sprints covered:** A (DB Foundation), B (Auth Security), C (Onboarding Engine), D (Frontend Wizard)

---

## Section 1 — System Component Map

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│  BROWSER                                                                        │
│  Next.js 15 / React 19                                                          │
│  - AuthContext: {customer_id, tenant_ids, selectedTenant, permissions}         │
│  - Wizard state machine (reads catalog/account_types/auth_requirements.yaml)   │
│  - Cookie: access_token (httponly, secure)                                      │
└──────────────────────────────┬──────────────────────────────────────────────────┘
                               │ HTTPS (all requests carry access_token cookie)
                               ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│  API GATEWAY  (shared/api_gateway — port 8000)                                  │
│  AuthMiddleware (shared/auth/fastapi/middleware.py)                             │
│    1. Read access_token cookie                                                  │
│    2. asyncpg → cspm DB → user_sessions table (direct DB read, NOT via Django) │
│    3. Verify token PBKDF2 hash                                                  │
│    4. Build AuthContext {customer_id, tenant_ids, account_ids, permissions}    │
│    5. Set X-Auth-Context header (JSON) on forwarded request                    │
│  BFF (bff/) — fetchView() aggregation for dashboard charts                     │
└───────┬─────────────────┬──────────────────────────┬────────────────────────────┘
        │                 │                          │
        ▼                 ▼                          ▼
┌───────────────┐  ┌────────────────────┐   ┌──────────────────────────────────┐
│ Django        │  │ Onboarding Engine  │   │ Scanning Engines (20+)           │
│ cspm-backend  │  │ FastAPI port 8008  │   │ discoveries/check/threat/iam/    │
│ (Django 6)    │  │                    │   │ network/datasec/compliance/      │
│               │  │ - cloud_accounts   │   │ risk/ciem/vuln/secops/...        │
│ - Auth views  │  │ - schedules        │   │                                  │
│ - Tenant CRUD │  │ - scan_runs        │   │ Each engine:                     │
│ - User/group  │  │ - agent_registr.   │   │  Depends(require_permission(...))│
│ - Invite flow │  │ - SchedulerService │   │  X-Auth-Context → AuthContext    │
│ - Celery tasks│  │   (asyncio 60s)    │   │  all queries scoped tenant_id    │
└───────┬───────┘  └────────┬───────────┘   └──────────────────────────────────┘
        │                   │
        ▼                   ▼
┌───────────────┐  ┌────────────────────┐   ┌──────────────────────────────────┐
│  cspm DB      │  │ threat_engine_     │   │  Engine DBs (per engine)         │
│  (PostgreSQL) │  │ onboarding DB      │   │  threat_engine_check             │
│               │  │ (PostgreSQL)       │   │  threat_engine_threat            │
│ users         │  │                    │   │  threat_engine_inventory         │
│ user_sessions │  │ cloud_accounts     │   │  threat_engine_iam               │
│ tenants       │  │ schedules          │   │  threat_engine_datasec           │
│ tenant_users  │  │ scan_runs          │   │  threat_engine_network           │
│ roles/perms   │  │ agent_registrations│   │  threat_engine_compliance        │
│ user_admin_   │  │ tenants (mirror)   │   │  vulnerability_db  ...           │
│  scope        │  │                    │   │                                  │
│ cspm_groups   │  │                    │   │                                  │
│ group_members │  │                    │   │                                  │
│ tenant_group_ │  │                    │   │                                  │
│  access       │  │                    │   │                                  │
│ account_group_│  │                    │   │                                  │
│  access       │  │                    │   │                                  │
└───────────────┘  └────────┬───────────┘   └──────────────────────────────────┘
                            │ Argo submit (HTTP to argo-server.argo:2746)
                            ▼
              ┌─────────────────────────────┐
              │  Argo Workflows             │
              │  cspm-scan-pipeline         │
              │  (argo namespace)           │
              │  params: scan-run-id,       │
              │  tenant-id, account-id,     │
              │  provider, credential-*,    │
              │  include-services/regions   │
              └─────────────────────────────┘
                            │
                            ▼
              ┌─────────────────────────────┐
              │  AWS Secrets Manager        │
              │  path: threat-engine/       │
              │        account/{account_id} │
              │  Stores: all CSP creds,     │
              │  kubeconfigs, git tokens    │
              └─────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────────┐
│  ASYNC LAYER                                                                  │
│  Django cspm-backend → Celery Worker → Redis                                 │
│                                                                               │
│  Tasks:                                                                       │
│    sync_tenant_to_onboarding(tenant_id, company_name, customer_id)           │
│      → POST threat_engine_onboarding /api/v1/tenants/                        │
│      → retries 3×, dead-letter: tenant.status='sync_failed'                  │
│    provision_billing_trial(customer_id)                                       │
│      → POST billing engine /api/v1/subscriptions/trial                       │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Section 2 — Data Architecture

### 2.1 cspm DB — Auth/Identity Database

**Tables to KEEP (live data)**

| Table | Key Columns | Purpose |
|-------|------------|---------|
| `user_auth_users` | id, email, name, password, **customer_id** (NEW), is_active, created_at | All platform users |
| `user_sessions` | id, user_id, token_hash, scope_cache (JSONB), expires_at, created_at | JWT sessions — Gateway reads this directly via asyncpg |
| `audit_logs` | id, user_id, event_type, resource_type, resource_id, ip_addr, created_at | Auth audit trail |
| `tenant_management_tenants` | id, name, status, **tenant_type** (NEW), **customer_id** (NEW), engine_tenant_id, created_at | Workspaces |
| `tenant_management_tenantusers` | id, user_id, tenant_id, role_id, created_at | User → Tenant membership |
| `user_auth_roles` | id, name, level, scope_level, created_at | Role definitions |
| `user_auth_permissions` | id, key, description, created_at | Feature:action permissions |
| `user_auth_rolepermissions` | id, role_id, permission_id | Role → permission mapping |
| `user_auth_useradminscope` | id, user_id, scope_type ('organization'), scope_id (=customer_id) | Org-level scope assignment |
| `tenant_management_useraccountaccess` | id, user_id, tenant_id, account_id, **role_id** (NEW FK), created_at | Account-level access |
| `user_invitations` | id, email, customer_id, invited_by, tenant_ids (JSONB), account_ids (JSONB), role_id, token_hash, expires_at | Pending invites |
| `password_reset_tokens` | id, user_id, token_hash, expires_at, used_at | Password reset flow |
| `tenant_idp_configs` | id, tenant_id, idp_type, domain, metadata_url, client_id, created_at | SAML/OIDC per-tenant SSO |
| `django_migrations` | id, app, name, applied | Django migration state |
| `django_content_type` | id, app_label, model | Django internal |
| `auth_permission` | id, name, codename, content_type_id | Django internal |
| `django_session` | session_key, session_data, expire_date | Django session (for admin) |

**Tables to DROP (0 rows, replaced by engine DBs)**

| Table | Replaced By |
|-------|-------------|
| `organizations` | `customer_id = user.id` — no org table needed |
| `onboarding_tenants/accounts/providers/executions/scan_results/schedules` | `threat_engine_onboarding` DB |
| `assets`, `asset_compliance`, `asset_tags`, `asset_threats` | Inventory engine DB |
| `scan_findings`, `scan_findings_assets`, `scan_results` | Per-engine finding DBs |
| `compliance_summary` | Compliance engine DB |
| `threats`, `threat_related_findings`, `threat_remediation_steps` | Threat engine DB |
| `agents` | `agent_registrations` in onboarding DB |
| `auth_group`, `auth_group_permissions` | Custom RBAC (roles/permissions) |
| `users_groups`, `users_user_permissions` | Custom RBAC |
| `oauth_providers` | `tenant_idp_configs` |
| `invite_tokens` | `user_invitations` |
| `user_roles` | `tenant_management_tenantusers` |

**NEW Tables to ADD**

```sql
-- Groups (customer_id-scoped user collections)
tenant_management_csmgroups (
    id VARCHAR(255) PK,
    customer_id VARCHAR(255) NOT NULL,        -- org boundary
    name VARCHAR(255) NOT NULL,
    description TEXT,
    created_by VARCHAR(255) → user_auth_users,
    created_at, updated_at TIMESTAMPTZ,
    UNIQUE(customer_id, name)
)

-- Group membership
tenant_management_groupmembers (
    id, group_id → csm_groups, user_id → users,
    added_at TIMESTAMPTZ,
    UNIQUE(group_id, user_id)
)

-- Group → Tenant access assignment
tenant_management_tenantgroupaccess (
    id, group_id → csm_groups, tenant_id → tenants,
    role_id → roles, granted_at,
    UNIQUE(group_id, tenant_id)
)

-- Group → specific Account access
tenant_management_accountgroupaccess (
    id, group_id → csm_groups, tenant_id → tenants,
    account_id VARCHAR(512),         -- onboarding DB account_id
    role_id → roles, granted_at,
    UNIQUE(group_id, tenant_id, account_id)
)
```

### 2.2 threat_engine_onboarding DB

**Changes needed (migration 20260503_account_type_and_agent_registrations.sql — not yet applied)**

```sql
-- ADD to cloud_accounts:
account_type VARCHAR(50) NOT NULL DEFAULT 'cloud_csp'
    -- values: cloud_csp | vulnerability | secops | database | middleware | technology
auth_config JSONB DEFAULT '{}'
    -- flexible per-type metadata (e.g. git branch, db type)
exclude_regions JSONB DEFAULT NULL    -- currently missing from ORM model

-- NEW table: agent_registrations (PKCE bootstrap)
agent_registrations (
    registration_id UUID PK,
    account_id → cloud_accounts,
    tenant_id, customer_id VARCHAR,
    code_challenge_hash VARCHAR(512),  -- make_password(code_challenge) — NOT SHA-256
    agent_version, agent_hostname, agent_ip INET, agent_os,
    status VARCHAR(30),               -- issued|active|expired|revoked
    issued_at, expires_at (15min TTL for bootstrap, 30d after activation),
    activated_at, last_heartbeat_at, revoked_at, revoke_reason,
    INDEX on (status, expires_at), INDEX on account_id, INDEX on tenant_id
)

-- ADD to schedules (currently missing from ORM model):
exclude_regions JSONB DEFAULT NULL
```

---

## Section 3 — API Surface Design

### 3.1 Django cspm-backend Endpoints

**Authentication**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| POST | `/api/auth/signup/` | None | — | Email dedup→200, CAPTCHA, rate 10/hr. BLOCK-01/02 |
| POST | `/api/auth/login/` | None | — | Rate 20/hr. Returns access_token cookie |
| POST | `/api/auth/logout/` | Cookie | — | Delete user_session row |
| POST | `/api/auth/refresh/` | Cookie | — | Rate 60/hr (WARN-02) |
| POST | `/api/auth/password-reset/` | None | — | Always 200, rate 10/hr |
| POST | `/api/auth/password-reset/confirm/` | None | — | Validate token, set password |
| GET | `/api/auth/me/` | Cookie | — | Returns user profile + orgs + tenants |
| GET | `/api/auth/google/` | None | — | Initiate Google OAuth |
| GET | `/api/auth/google/callback/` | None | — | hd validation (BLOCK-03) |
| GET | `/api/auth/saml/{tenant}/` | None | — | Initiate SAML |
| POST | `/api/auth/saml/{tenant}/callback/` | None | — | SAML assertion handler |

**Tenant Management**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| GET | `/api/v1/tenants/` | Cookie+DRF | `tenants:read` | Filtered by customer_id. BLOCK-08 |
| POST | `/api/v1/tenants/` | Cookie+DRF | `tenants:write` | Creates tenant with tenant_type |
| GET | `/api/v1/tenants/{id}/` | Cookie+DRF | `tenants:read` | Org-boundary enforced |
| PATCH | `/api/v1/tenants/{id}/` | Cookie+DRF | `tenants:write` | Explicit allow-list model |
| DELETE | `/api/v1/tenants/{id}/` | Cookie+DRF | `tenants:write` | Soft delete |
| GET | `/api/v1/tenants/{id}/export/` | Cookie+DRF | `tenants:read` | Explicit id__in filter. BLOCK-09 |
| POST | `/api/v1/tenants/{id}/resync/` | Cookie+DRF | platform_admin | Re-trigger Celery sync task |
| GET | `/api/v1/tenants/{id}/sync-status/` | Cookie+DRF | `tenants:read` | Returns tenant.status |
| GET | `/api/v1/tenants/idp-by-domain/` | None | — | Rate 5/min, no tenant_id in response. BLOCK-10 |
| POST | `/api/v1/tenants/{id}/idp/` | Cookie+DRF | `settings:write` | org-boundary check. BLOCK-11 |

**User & Group Management**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| GET | `/api/v1/users/` | Cookie+DRF | `users:read` | Scoped to customer_id |
| GET | `/api/v1/users/{id}/` | Cookie+DRF | `users:read` | Own profile or same org |
| PATCH | `/api/v1/users/{id}/` | Cookie+DRF | `users:write` | Own profile only (or platform_admin) |
| POST | `/api/v1/invites/` | Cookie+DRF | `users:write` | Creates user_invitations row |
| GET | `/api/v1/invites/` | Cookie+DRF | `users:read` | List pending invites for org |
| DELETE | `/api/v1/invites/{id}/` | Cookie+DRF | `users:write` | Revoke invite |
| POST | `/api/v1/invites/accept/` | None | — | Token validation, customer_id inherit |
| GET | `/api/v1/groups/` | Cookie+DRF | `groups:read` | Scoped to customer_id |
| POST | `/api/v1/groups/` | Cookie+DRF | `groups:write` | Creates cspm_groups row |
| GET | `/api/v1/groups/{id}/` | Cookie+DRF | `groups:read` | |
| PATCH | `/api/v1/groups/{id}/` | Cookie+DRF | `groups:write` | |
| DELETE | `/api/v1/groups/{id}/` | Cookie+DRF | `groups:write` | Cascades group_members |
| POST | `/api/v1/groups/{id}/members/` | Cookie+DRF | `groups:write` | Add user to group |
| DELETE | `/api/v1/groups/{id}/members/{user_id}/` | Cookie+DRF | `groups:write` | Remove from group |
| POST | `/api/v1/tenants/{id}/group-access/` | Cookie+DRF | `tenants:write` | Assign group to tenant |
| DELETE | `/api/v1/tenants/{id}/group-access/{group_id}/` | Cookie+DRF | `tenants:write` | Remove group from tenant |

### 3.2 Onboarding Engine Endpoints

**Cloud Accounts**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| GET | `/api/v1/cloud-accounts/` | X-Auth-Context | `cloud_accounts:read` | |
| POST | `/api/v1/cloud-accounts/` | X-Auth-Context | `cloud_accounts:write` | account_type field required |
| GET | `/api/v1/cloud-accounts/{id}/` | X-Auth-Context | `cloud_accounts:read` | |
| PATCH | `/api/v1/cloud-accounts/{id}/` | X-Auth-Context | `cloud_accounts:write` | Pydantic allow-list. BLOCK-06 |
| DELETE | `/api/v1/cloud-accounts/{id}/` | X-Auth-Context | `cloud_accounts:write` | |
| POST | `/api/v1/cloud-accounts/{id}/credentials` | X-Auth-Context | `cloud_accounts:write` | Full validate+store |
| POST | `/api/v1/cloud-accounts/{id}/validate-credentials` | X-Auth-Context | `cloud_accounts:read` | Re-test stored creds |
| POST | `/api/v1/cloud-accounts/{id}/scan` | X-Auth-Context | `scans:create` | **NEW** Ad-hoc, no schedule needed |
| POST | `/api/v1/cloud-accounts/{id}/signal-scan` | X-Auth-Context | `scans:create` | **NEW** Signal agent to scan |
| POST | `/api/v1/cloud-accounts/{id}/agent-token` | X-Auth-Context | `cloud_accounts:write` | PKCE bootstrap. BLOCK-04 |

**Schedules**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| GET | `/api/v1/schedules/` | X-Auth-Context | `scans:read` | **RBAC missing today** |
| POST | `/api/v1/schedules/` | X-Auth-Context | `scans:create` | **RBAC missing today** |
| GET | `/api/v1/schedules/{id}/` | X-Auth-Context | `scans:read` | |
| PATCH | `/api/v1/schedules/{id}/` | X-Auth-Context | `scans:create` | |
| DELETE | `/api/v1/schedules/{id}/` | X-Auth-Context | `scans:create` | |
| POST | `/api/v1/schedules/{id}/enable` | X-Auth-Context | `scans:create` | |
| POST | `/api/v1/schedules/{id}/disable` | X-Auth-Context | `scans:create` | |
| POST | `/api/v1/schedules/{id}/run-now` | X-Auth-Context | `scans:create` | Exists today |
| POST | `/api/v1/tenants/{id}/scan-all` | X-Auth-Context | `scans:create` | **NEW** Bulk run-now |

**Scan Runs**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| GET | `/api/v1/scan-runs/` | X-Auth-Context | `scans:read` | Filter by account_id |
| GET | `/api/v1/scan-runs/{id}/` | X-Auth-Context | `scans:read` | |
| POST | `/api/v1/scan-runs/{id}/engine-status` | Internal | — | Engine webhook to update status |

**Agent Bootstrap**

| Method | Path | Auth | Permission | Notes |
|--------|------|------|-----------|-------|
| POST | `/api/v1/agents/bootstrap` | None (PKCE) | — | registration_id + code_verifier |
| POST | `/api/v1/agents/heartbeat` | agent_token | — | Agent health + schedule signal |

---

## Section 4 — Auth & RBAC Architecture

### 4.1 Complete Request Auth Chain

```
1. Browser sends request with cookie: access_token=<jwt>
         │
2. API Gateway AuthMiddleware (shared/auth/fastapi/middleware.py)
   asyncpg connection to cspm DB:
     SELECT user_id, scope_cache, expires_at
     FROM user_sessions
     WHERE token_hint = $1         ← first 8 chars of token (pre-filter)
     AND expires_at > NOW()
   PBKDF2 verify: check_password(raw_token, row.token_hash)
   FAIL → 401 Unauthorized
         │
3. Build AuthContext from scope_cache JSONB:
   AuthContext {
     user_id, email, role_level,
     customer_id,                  ← org key
     tenant_ids: [...],            ← tenants user belongs to
     account_ids: [...],           ← accounts user has explicit access to
     permissions: [...],           ← flat list of feature:action strings
     engine_tenant_id              ← currently selected tenant
   }
         │
4. Set X-Auth-Context header (base64 JSON) on forwarded request
         │
5. Engine (FastAPI) Depends(require_permission("feature:action"))
   Reads X-Auth-Context header → deserializes AuthContext
   Checks permissions list
   FAIL → 403 Forbidden
         │
6. Engine DB query — always scoped:
   WHERE tenant_id = auth_context.engine_tenant_id
```

### 4.2 scope_cache JSONB Structure

```json
{
  "user_id": "uuid",
  "email": "user@example.com",
  "role": "org_admin",
  "role_level": 2,
  "customer_id": "uuid-of-founding-user",
  "tenant_ids": ["t1", "t2"],
  "account_ids": ["acct1", "acct2"],
  "engine_tenant_id": "t1",
  "permissions": [
    "tenants:read", "tenants:write",
    "scans:read", "scans:create",
    "cloud_accounts:read", "cloud_accounts:write",
    "users:read", "groups:read", "orgs:read"
  ],
  "groups": ["g1", "g2"]
}
```

Rebuilt on every login. Cached in `user_sessions`. Invalidated on logout.

### 4.3 customer_id Propagation

| Trigger | How customer_id is set |
|---------|----------------------|
| Self-signup (local/Google/SAML new user) | `user.customer_id = str(user.id)` — this user IS the org founder |
| Invited user accepts invite | `user.customer_id = invite.customer_id` — inherits org's customer_id |
| Cross-org invite detected | `user.customer_id` stays unchanged; role capped at `viewer` |
| SAML JIT provision (existing org domain) | `user.customer_id` = org's customer_id from `tenant_idp_configs` |

### 4.4 Three-Level Scope Model

```
customer_id (org level)
    └── Tenant [has tenant_type]
            └── Account [has account_type, provider]
                    └── Scan Run → Findings

Authorization resolution (checked in order):
  1. UserAdminScope (scope_type='organization', scope_id=customer_id)
     → platform_admin: global; org_admin: all tenants with same customer_id
  2. TenantUsers (tenant_id, role_id)
     → tenant_admin, analyst, viewer: specific tenants
  3. tenant_group_access (group_id → tenant_id with role)
     → inherited via group membership
  4. UserAccountAccess / account_group_access (account_id within tenant)
     → fine-grained per-account restriction
```

### 4.5 Role Hierarchy & Permissions

| Role | Level | scope_level | Key Permissions |
|------|-------|------------|-----------------|
| platform_admin | 1 | global | All permissions + resync tenants |
| org_admin | 2 | organization | tenants:write, users:write*, groups:write, scans:create, cloud_accounts:write, orgs:read |
| tenant_admin | 4 | tenant | tenants:read, scans:create, cloud_accounts:write, users:read |
| analyst | 4 | tenant | scans:read, cloud_accounts:read, all findings:read |
| viewer | 4 | tenant | tenants:read, scans:read (no sensitive engines) |

*`users:write` for org_admin activated ONLY after B-4 boundary enforcement is validated (manual SQL post-deploy).

### 4.6 org_admin Boundary Enforcement

Every query involving tenants for org_admin MUST filter by `customer_id`:
```python
def get_org_scoped_tenants(user):
    if not user.customer_id:
        return Tenants.objects.none()
    return Tenants.objects.filter(customer_id=user.customer_id)
```

Applied in: `build_tenant_query()`, `TenantIDPConfigListCreateView`, `TenantViewSet.export`, invite acceptance.

---

## Section 5 — Onboarding Wizard Architecture

### 5.1 State Machine

```
START
  │
  ▼
[SELECT_TECHNOLOGY]
  UI: grid of tiles from catalog/account_types/*.yaml
  Tiles: AWS | Azure | GCP | OCI | AliCloud | IBM | K8s |
         GitHub | GitLab | Bitbucket | Azure DevOps |
         Vulnerability Agent | Database Agent | Middleware Agent |
         K8s Technology
  → sets: account_type_id, tenant_type
  │
  ▼
[SET_TENANT_TYPE]  (skip if adding account to existing tenant)
  UI: "Add to existing tenant" OR "Create new tenant"
  If new tenant: name input + tenant_type pre-filled from selection
  → POST /api/v1/tenants/ {name, tenant_type, customer_id}
  │
  ▼
[SHOW_PREREQUISITES]
  UI: numbered checklist from auth_requirements.yaml → admin_prerequisites
  Each step has: title + collapsible detail instructions
  "I've completed these steps" checkbox → enables Next
  │
  ▼
[CREDENTIAL_FORM]  ← dispatch on auth_model
  │
  ├── auth_model = api_secret | file_upload | git_token
  │     Render fields from auth_requirements.yaml → credential_fields
  │     type: text | password | file | textarea
  │     Submit → POST /api/v1/cloud-accounts/{id}/credentials
  │
  ├── auth_model = iam_role
  │     Render role_arn + external_id fields
  │     Show CloudFormation/Terraform template for customer to create role
  │     Submit → POST /api/v1/cloud-accounts/{id}/credentials
  │
  └── auth_model = agent
        No form — show PKCE install command flow:
        [AGENT_WAITING sub-states]:
          GENERATE_TOKEN:
            JS: code_verifier = crypto.getRandomValues(32 bytes) → hex
            JS: code_challenge = await crypto.subtle.digest('SHA-256', code_verifier) → hex
            POST /api/v1/cloud-accounts/{id}/agent-token {code_challenge, account_type}
            Response: {registration_id}
          SHOW_COMMAND:
            Display: install.sh --registration-id {registration_id} --verifier {code_verifier}
            code_verifier shown once, cleared from state on navigate away
            Countdown: "Token expires in 14:32"
          WAITING_FOR_AGENT:
            Poll GET /api/v1/cloud-accounts/{id}/ every 5s
            When account_onboarding_status='deployed' → next state
  │
  ▼
[VALIDATE]  (for non-agent types)
  Show: spinner "Validating credentials…"
  POST result:
    PASS → green check, show detected account_id
           show missing_permissions warnings (yellow banner if any)
           → [ATTACH_SCHEDULE]
    FAIL → red error, show CSP-specific error message
           "Try Again" → back to CREDENTIAL_FORM
  │
  ▼
[ATTACH_SCHEDULE]
  UI: schedule creation card
    Cron preset picker (6 options) + timezone + custom
    Scope selector: Full Account | Selected Regions | Selected Services | Custom
    Engine preset: Full Scan | Compliance Only | Security Focus | Custom
    Notifications: email(s) for failure alerts
  Submit → POST /api/v1/schedules/ {account_id, tenant_id, cron, scope, engines}
  Shows: "First scan scheduled for {next_run_at}"
  Option: "Scan Now" button also present
  │
  ▼
[FIRST_SCAN]  (optional, user-initiated)
  "Scan Now" → POST /api/v1/schedules/{id}/run-now
  → redirect /scans/{scan_run_id}/progress
  OR "Skip — I'll wait for the schedule" → /dashboard
```

### 5.2 Catalog Loading

```javascript
// frontend/src/lib/accountTypeCatalog.js
import catalog from '@/../catalog/account_types/auth_requirements.yaml'
// bundled at build time via yaml-loader webpack plugin

export function getAccountType(id) {
  return catalog.account_types.find(t => t.id === id)
}

export function getAuthModel(accountTypeId, authModelId) {
  const at = getAccountType(accountTypeId)
  return at?.auth_models.find(m => m.id === authModelId)
}

export function getCredentialFields(accountTypeId, authModelId) {
  return getAuthModel(accountTypeId, authModelId)?.credential_fields ?? []
}
```

---

## Section 6 — Scheduling Architecture

### 6.1 Asyncio Scheduler Loop

```
onboarding engine startup event → asyncio.create_task(scheduler_loop())

Every SCHEDULER_INTERVAL_SECONDS (60):
  async with asyncio.Lock():
    due = await get_due_schedules()        ← next_run_at <= NOW()
    running = await count_running_scans()
    slots = MAX_CONCURRENT_SCANS - running ← default 10

    for schedule in due[:slots]:
      scan_run_id = uuid4()
      await create_scan_run(scan_run_id, schedule, trigger='scheduled')
      ok = await argo_client.submit_pipeline(
          scan_run_id=scan_run_id,
          tenant_id=schedule.tenant_id,
          account_id=schedule.account_id,
          provider=schedule.cloud_account.provider,
          credential_type=schedule.cloud_account.credential_type,
          credential_ref=schedule.cloud_account.credential_ref,
          include_services=schedule.include_services,
          include_regions=schedule.include_regions,
          exclude_services=schedule.exclude_services,
          engines_requested=schedule.engines_requested,
      )
      if ok:
          await mark_scan_run_started(scan_run_id)
          await bump_schedule(schedule.id, success=True)
      else:
          await mark_scan_run_failed(scan_run_id, "Argo submit failed")
          await bump_schedule(schedule.id, success=False)
```

### 6.2 Credential Health-Check Design (NEW — Sprint C6)

```
Celery beat task: credential_health_check (weekly, Sunday 03:00 UTC)

For each cloud_account WHERE credential_validation_status='valid':
  validator = get_validator(account.provider, account.credential_type)
  creds = secrets_manager.retrieve(account.credential_ref)
  result = validator.quick_check(creds)  ← minimal API call (STS/subscription get)
  if not result.valid:
    UPDATE cloud_accounts SET credential_validation_status='expired'
    UPDATE schedules SET enabled=false WHERE account_id=account.id
    send_notification(account.notification_emails, "Credentials expired")
    log_audit_event("credentials.expired", account_id=account.id)
```

### 6.3 Agent Scheduling via Heartbeat Response

```
Agent → POST /api/v1/agents/heartbeat
  {registration_id, agent_version, hostname, last_scan_at}

Server reads:
  schedule = get_active_schedule(account_id)
  scan_requested = agent_registrations.scan_requested

Response:
  {
    "run_now": scan_requested OR (schedule AND now >= schedule.next_run_at),
    "scan_config": {
      "include_services": schedule.include_services,
      "engines_requested": schedule.engines_requested
    },
    "next_check_in_seconds": 300
  }

Agent obeys run_now=true → starts local scan → POST results back
```

---

## Section 7 — Security Architecture

### 7.1 All 12 BLOCK Controls

| # | Where Fixed | Component | Architectural Change |
|---|------------|-----------|---------------------|
| BLOCK-01 | Sprint B1 | `local_auth.py` SignupView | Return 200 on duplicate email. Never 409. |
| BLOCK-02 | Sprint B1 | `local_auth.py` + `throttles.py` | `AnonRateThrottle(10/hr)` on SignupView. CAPTCHA via hCaptcha. |
| BLOCK-03 | Sprint B2 | `google_auth.py` | Validate `email.split("@")[1] == requested_hd`. `FRONTEND_URL` allowlist check at startup. |
| BLOCK-04 | Sprint C10 | `cloud_accounts.py` | `require_permission("cloud_accounts:write")`. `make_password(code_challenge)` instead of SHA-256. |
| BLOCK-05 | Sprint C8 | Onboarding engine `main.py` | Apply `AuthMiddleware` (X-Auth-Context validation) to ALL routes. |
| BLOCK-06 | Sprint C9 | `cloud_accounts.py` PATCH | Replace `updates: dict` with `CloudAccountUpdate` Pydantic model. Explicit allow-list of patchable fields. |
| BLOCK-07 | Sprint B4 | `tenant_management/filters.py` | Remove `user_has_developer_role()`. Fix `build_tenant_query` org_admin branch. |
| BLOCK-08 | Sprint B3 | `TenantViewSet` | `authentication_classes = [CookieTokenAuthentication]`, `permission_classes = [HasPermission("tenants:read")]`. |
| BLOCK-09 | Sprint B3 | `TenantViewSet.export` | Explicit `id__in=user_tenant_ids` filter, independent of `get_queryset()`. |
| BLOCK-10 | Sprint B3 | `/tenants/idp-by-domain/` | Rate limit 5/min per IP. Remove `tenant_id` from response. Return only `{idp_type, redirect_url}`. |
| BLOCK-11 | Sprint B4 | `filters.py`, `views.py`, `tenant_utils.py` | All org_admin writes filtered by `tenant.customer_id = user.customer_id`. |
| BLOCK-12 | Sprint A3 | `tenant_utils.py`, Celery | Move `_sync_tenant_to_onboarding` outside `transaction.atomic()`. Celery task with 3 retries + dead-letter. |

### 7.2 PKCE Agent Bootstrap Token Flow

```
UI (browser JavaScript):
  code_verifier  = crypto.getRandomValues(new Uint8Array(32)) → hex string
  code_challenge = hex(await crypto.subtle.digest('SHA-256', encoder.encode(code_verifier)))

  POST /api/v1/cloud-accounts/{id}/agent-token
    {code_challenge: "abcd1234...", account_type: "vulnerability"}
  Response: {registration_id: "uuid"}

Server stores:
  agent_registrations.code_challenge_hash = make_password(code_challenge)
  (make_password uses PBKDF2+salt — NOT raw SHA-256)

Install command shown to user:
  install.sh --registration-id {registration_id} --verifier {code_verifier}
  ← code_verifier NEVER in a URL, NEVER in a log, shown once in UI

Agent bootstrap:
  POST /api/v1/agents/bootstrap
    {registration_id, code_verifier}
  Server: check_password(code_verifier, stored.code_challenge_hash)
  PASS → status='active', create cloud_account row, return agent_token
  FAIL → 401, no account created
```

### 7.3 Credential Storage Architecture

| Auth Model | Storage | Path | Rotation |
|-----------|---------|------|---------|
| api_secret | Secrets Manager | `threat-engine/account/{account_id}` | Manual + weekly health-check |
| file_upload | Secrets Manager | `threat-engine/account/{account_id}` | Manual |
| git_token | Secrets Manager | `threat-engine/account/{account_id}` | Manual + weekly health-check |
| iam_role | Not stored | Role assumed at scan time via STS | Not needed |
| agent | Not stored on platform | Agent keystore on target host | Agent re-registration |

### 7.4 Rate Limiting

| Endpoint | Throttle Class | Rate | Keyed By |
|----------|---------------|------|---------|
| `POST /api/auth/signup/` | `SignupRateThrottle` | 10/hour | IP |
| `POST /api/auth/login/` | `LoginRateThrottle` | 20/hour | IP |
| `POST /api/auth/refresh/` | `RefreshRateThrottle` | 60/hour | IP |
| `POST /api/auth/password-reset/` | `SignupRateThrottle` | 10/hour | IP |
| `GET /api/v1/tenants/idp-by-domain/` | `ScopedRateThrottle` | 5/min | IP |

---

## Section 8 — Migration Strategy (Zero-Downtime)

### Phase 1 — Database Only (no code deploy yet)

**Step 1: Apply cspm DB cleanup migration**
```bash
# File: shared/database/migrations/20260503_cspm_cleanup_and_org_foundation.sql
kubectl cp /tmp/cspm_migration.sql threat-engine-engines/$CSPM_POD:/tmp/
kubectl exec -n threat-engine-engines $CSPM_POD -- \
  psql -h $DB_HOST -U $DB_USER -d cspm -f /tmp/cspm_migration.sql
```
Safe because: all dropped tables have 0 rows. New columns are nullable. No engine touches these tables.

**Step 2: Apply onboarding DB migration**
```bash
# File: shared/database/migrations/20260503_account_type_and_agent_registrations.sql
# (already written, just needs applying)
kubectl exec -n threat-engine-engines deployment/engine-onboarding -- \
  python3 -c "from database.migrations import apply_pending; apply_pending()"
```
Safe because: new columns are nullable with defaults. Existing scan_runs/schedules unaffected.

### Phase 2 — Sprint A Code Deploy

**Step 3: Deploy cspm-backend Sprint A** (after both migrations applied)
- `provision_org_and_tenant()` replaces `provision_first_tenant()`
- `sync_tenant_to_onboarding` as Celery task (outside atomic)
- Django ORM models updated for new columns + group tables
- Deploy: `kubectl rollout restart deployment/cspm-backend`

Feature guard: `customer_id` column exists check in `provision_org_and_tenant()`:
```python
from django.db import connection
def customer_id_column_exists():
    with connection.cursor() as c:
        c.execute("SELECT 1 FROM information_schema.columns WHERE table_name='user_auth_users' AND column_name='customer_id'")
        return bool(c.fetchone())
```

### Phase 3 — Sprint B Code Deploy

**Step 4: Deploy Sprint B security fixes**
- B1: Email enumeration fix + throttles
- B2: Google OAuth hd validation
- B3: TenantViewSet DRF auth + export filter + IDP rate limit
- B4: org_admin boundary (customer_id-based) + remove developer bypass
- Deploy cspm-backend + new image tag

### Phase 4 — Sprint C + D

**Step 5: Deploy onboarding engine Sprint C**
- Apply RBAC to schedule endpoints
- Add ad-hoc scan + bulk scan-all endpoints
- Add exclude_regions to Schedule ORM
- Add credential expiry Celery task
- BLOCK-05: auth middleware on all routes
- BLOCK-06: Pydantic allow-list for PATCH
- PKCE agent bootstrap endpoint

**Step 6: Deploy frontend Sprint D**
- Onboarding wizard with catalog-driven forms
- Schedule creation modal
- Scan progress page

### Backfill Script (run after Step 3)

Included in `20260503_cspm_cleanup_and_org_foundation.sql` Step 6:
```sql
-- Backfill users: customer_id = their own id (all existing users are founders)
UPDATE user_auth_users SET customer_id = id WHERE customer_id IS NULL;

-- Backfill tenants: customer_id from the org_admin TenantUser row
UPDATE tenant_management_tenants t
SET customer_id = (
    SELECT u.customer_id FROM tenant_management_tenantusers tu
    JOIN user_auth_users u ON u.id = tu.user_id
    JOIN user_auth_roles r ON r.id = tu.role_id
    WHERE tu.tenant_id = t.id AND r.name IN ('org_admin','tenant_admin')
    ORDER BY tu.created_at LIMIT 1
)
WHERE t.customer_id IS NULL;
```

---

## Section 9 — Component Interface Contracts

### 9.1 X-Auth-Context Header

Base64-encoded JSON set by Gateway, read by every engine:
```json
{
  "user_id": "uuid",
  "email": "admin@acme.com",
  "role": "org_admin",
  "role_level": 2,
  "customer_id": "uuid",
  "engine_tenant_id": "uuid",
  "tenant_ids": ["uuid1", "uuid2"],
  "account_ids": ["acct1"],
  "permissions": ["scans:read", "cloud_accounts:read", "..."],
  "groups": ["group_uuid1"]
}
```

### 9.2 Celery Task Signatures

```python
# Task 1: Sync tenant to onboarding engine
@shared_task(bind=True, max_retries=3, default_retry_delay=30)
def sync_tenant_to_onboarding(self, tenant_id: str, company_name: str, customer_id: str) -> None:
    # POST to onboarding engine /api/v1/tenants/
    # On MaxRetriesExceededError:
    #   Tenants.objects.filter(id=tenant_id).update(status='sync_failed')
    #   log_auth_event("tenant.sync_failed", tenant_id=tenant_id)

# Task 2: Provision billing trial
@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def provision_billing_trial(self, customer_id: str) -> None:
    # POST to billing engine /api/v1/subscriptions/trial {customer_id}

# Task 3: Credential health check (Celery beat)
@shared_task
def credential_health_check() -> None:
    # Runs weekly — checks all valid credentials still authenticate
```

### 9.3 Argo Pipeline Submission Parameters

```python
await argo_client.submit_pipeline(
    workflow_template="cspm-scan-pipeline",
    parameters={
        "scan-run-id":      str(scan_run_id),
        "tenant-id":        str(tenant_id),
        "account-id":       str(account_id),
        "provider":         provider,              # aws|azure|gcp|oci|alicloud|ibm|k8s
        "credential-type":  credential_type,       # access_key|iam_role|service_principal|...
        "credential-ref":   credential_ref,        # Secrets Manager path
        "include-services": json.dumps(include_services or []),
        "include-regions":  json.dumps(include_regions or []),
        "exclude-services": json.dumps(exclude_services or []),
        "engines-requested": json.dumps(engines_requested),
    }
)
```

### 9.4 Agent Heartbeat Contract

**Request** `POST /api/v1/agents/heartbeat`:
```json
{
  "registration_id": "uuid",
  "agent_version": "1.2.3",
  "hostname": "prod-db-01",
  "os": "Ubuntu 22.04",
  "last_scan_at": "2026-05-03T02:00:00Z",
  "scan_status": "idle"
}
```

**Response**:
```json
{
  "run_now": false,
  "scan_config": {
    "include_services": null,
    "engines_requested": ["vulnerability"]
  },
  "next_check_in_seconds": 300,
  "agent_token_expires_at": "2026-06-02T12:00:00Z"
}
```

### 9.5 Onboarding Wizard ↔ Catalog Contract

Frontend loads `catalog/account_types/auth_requirements.yaml` at build time.
For each account_type:
- `id` → unique key for form routing
- `tenant_type` → auto-set on new tenant creation
- `auth_models[].credential_fields` → rendered as form fields
- `auth_models[].admin_prerequisites` → shown as checklist before form
- `auth_models[].agent_install.show_install_command` → triggers PKCE flow instead of form
- `scope_capabilities` → controls which scope options shown in schedule modal

---

## Section 10 — Sprint Impact Map

### Sprint A — DB Foundation (cspm DB)

| Component Touched | Change |
|------------------|--------|
| cspm DB | Drop 17 tables, add tenant_type + customer_id + role FK + 4 group tables |
| Django ORM | New models: CsmGroups, GroupMembers, TenantGroupAccess, AccountGroupAccess |
| Django ORM | Modified: Tenants (+tenant_type, +customer_id), Users (+customer_id), UserAccountAccess (+role) |
| `tenant_utils.py` | `provision_org_and_tenant()` replaces `provision_first_tenant()` |
| `google_auth.py` | New user: call `provision_org_and_tenant()` |
| Celery tasks | `sync_tenant_to_onboarding` and `provision_billing_trial` as async tasks |

**Dependencies:** None. Sprint A is the foundation. All other sprints depend on A.

**Deployment order:** Migration first → verify backfill → deploy code.

**Risks:** Backfill of customer_id must complete before B4 customer_id filtering activates.

---

### Sprint B — Auth Security Fixes

| Story | Component | BLOCK(s) |
|-------|-----------|---------|
| B1 | `local_auth.py`, `throttles.py`, frontend signup | BLOCK-01, BLOCK-02 |
| B2 | `google_auth.py`, `settings.py` | BLOCK-03 |
| B3 | `TenantViewSet`, `drf/backends.py`, IDP view | BLOCK-08, BLOCK-09, BLOCK-10 |
| B4 | `filters.py`, `views.py`, `tenant_utils.py`, `scope_resolver.py` | BLOCK-07, BLOCK-11 |

**Dependencies:** A1 (customer_id column) must exist before B4 can filter on it.

**Deployment order:** B1 + B2 can deploy in parallel (no deps). B3 before B4 (DRF auth needed first). B4 after A deploys.

**Risks:** B3 introduces DRF authentication on TenantViewSet — test all tenant API callers (frontend, Celery tasks) are sending the cookie.

---

### Sprint C — Onboarding Engine

| Story | Component | Gap(s) |
|-------|-----------|--------|
| C1 | Apply 20260503 migration | S-03 |
| C2 | `api/schedules.py` + `api/cloud_accounts.py` | S-01 (RBAC missing) |
| C3 | `api/cloud_accounts.py` | S-02 (ad-hoc scan) |
| C4 | `database/models.py` Schedule | S-04 (exclude_regions) |
| C5 | `api/schedules.py` | S-05 (bulk scan-all) |
| C6 | Celery task | S-06 (cred expiry) |
| C7 | `api/cloud_accounts.py` | S-07 (agent signal) |
| C8 | `main.py` | BLOCK-05 (auth middleware) |
| C9 | `api/cloud_accounts.py` | BLOCK-06 (Pydantic allow-list) |
| C10 | `api/cloud_accounts.py` | BLOCK-04 (PKCE bootstrap) |

**Dependencies:** C1 (migration) must apply before C2-C10 code deploys.

**Deployment order:** C1 first. Then C8 (auth middleware — enables C2's RBAC to actually enforce). Then C2-C10 in any order.

**Risks:** C8 (adding auth middleware to all onboarding endpoints) — ensure all callers (frontend, Celery sync task, Argo callback) are sending valid auth before deploying.

---

### Sprint D — Frontend Wizard

| Story | Depends On |
|-------|-----------|
| D1 Tenant-type selector | A deploys |
| D2 Credential form (catalog-driven) | C1 (account_type migration) |
| D3 Schedule creation modal | C2 (RBAC on schedules) |
| D4 Account card (next run, run-now) | C2 |
| D5 Ad-hoc scan modal | C3 |
| D6 Bulk run-all | C5 |
| D7 Scan progress page | C2 |
| D8 Scan history + re-run | existing |
| D9 Credential validation result display | existing |
| D10 Agent install flow UI (PKCE) | C10 |
| D11 User/group assignment UI | A3 group tables |
| D12 Org/tenant switcher | A deploys (customer_id in scope_cache) |

**Dependencies:** Sprint D is entirely frontend — requires A + C to be deployed. D12 (org switcher) can ship after A. D10 (agent flow) requires C10.

---

### Cross-Reference: BLOCK → Sprint → Story

| BLOCK | Sprint | Story |
|-------|--------|-------|
| BLOCK-01 | B | B1 |
| BLOCK-02 | B | B1 |
| BLOCK-03 | B | B2 |
| BLOCK-04 | C | C10 |
| BLOCK-05 | C | C8 |
| BLOCK-06 | C | C9 |
| BLOCK-07 | B | B4 |
| BLOCK-08 | B | B3 |
| BLOCK-09 | B | B3 |
| BLOCK-10 | B | B3 |
| BLOCK-11 | B | B4 |
| BLOCK-12 | A | A3 |

### Cross-Reference: User Flow Step → API Endpoint

| Flow | Key Step | Endpoint |
|------|---------|---------|
| 1 Signup | Create user + org | `POST /api/auth/signup/` |
| 2 Login | Session creation | `POST /api/auth/login/` |
| 3 Google OAuth | hd validation | `GET /api/auth/google/callback/` |
| 4 SAML | IDP lookup | `GET /api/v1/tenants/idp-by-domain/` |
| 6 Onboarding wizard | Create account | `POST /api/v1/cloud-accounts/` |
| 6 Onboarding wizard | Submit creds | `POST /api/v1/cloud-accounts/{id}/credentials` |
| 6 Onboarding wizard | Agent token | `POST /api/v1/cloud-accounts/{id}/agent-token` |
| 6 Onboarding wizard | Attach schedule | `POST /api/v1/schedules/` |
| 7 Add tenant | Create | `POST /api/v1/tenants/` |
| 9 Invite user | Create invite | `POST /api/v1/invites/` |
| 10 Accept invite | Accept | `POST /api/v1/invites/accept/` |
| 11 Group assign | Create group | `POST /api/v1/groups/` |
| 11 Group assign | Assign to tenant | `POST /api/v1/tenants/{id}/group-access/` |
| 13 Scan trigger | Run now | `POST /api/v1/schedules/{id}/run-now` |
| 13 Scan trigger | Ad-hoc | `POST /api/v1/cloud-accounts/{id}/scan` |
| 14 Agent bootstrap | Bootstrap | `POST /api/v1/agents/bootstrap` |