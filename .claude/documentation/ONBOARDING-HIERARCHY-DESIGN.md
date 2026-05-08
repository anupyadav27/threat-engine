# Onboarding Hierarchy — Full Design
**Status:** Approved Design  
**Date:** 2026-05-03  
**Covers:** Cloud, SecOps, Vulnerability, Database, Middleware, Technology, SaaS

---

## 1. Entity Hierarchy

```
Organization
│  Created by self-service signup. One billing entity. One org_admin.
│  Contains all tenants, users, and their assignments.
│
├── User  (org-scoped)
│   Created by org_admin invite. Assigned to one or more tenants with a role.
│
└── Tenant  [has a tenant_type]
    │  Created by tenant_admin (or org_admin).
    │  Groups related accounts of the same security domain.
    │
    └── Account  [has an account_type, defined by tenant_type]
        │  Added by tenant_admin, analyst, or org_admin.
        │  Holds credentials / agent token / git URL etc.
        │
        └── Scan Run  ──►  Findings (check, threat, network, iam, datasec, secops, vuln …)
```

---

## 2. Tenant Types + Supported Account Types

Each tenant has a `tenant_type` that determines which engines scan it and which account types are valid inside it.

### 2.1 `cloud` — Cloud Infrastructure
Engines: discovery → inventory → check → threat → compliance → iam → datasec → network → risk → ciem → encryption → container-sec → dbsec → ai-security

| Account Type | Auth Method | Provider |
|---|---|---|
| `aws_account` | IAM Role / Access Key | AWS |
| `azure_subscription` | Service Principal (client_id + secret) | Azure |
| `gcp_project` | Service Account JSON | GCP |
| `oci_tenancy` | API Key (tenancy + user OCIDs + private key) | OCI |
| `alicloud_account` | Access Key ID + Secret | AliCloud |
| `ibm_account` | API Key | IBM Cloud |
| `kubernetes_cluster` | Kubeconfig / Service Account token | K8s (any) |

### 2.2 `secops` — Code & IaC Security
Engines: secops (SAST/DAST/SCA/IaC — 14 languages, 2852 rules)

| Account Type | Auth Method | Target |
|---|---|---|
| `github_repo` | Personal Access Token / GitHub App | GitHub repo or org |
| `gitlab_project` | PAT / Deploy Key | GitLab project or group |
| `bitbucket_repo` | App Password / SSH Key | Bitbucket workspace |
| `azure_devops_repo` | PAT | Azure DevOps project |
| `generic_git_repo` | SSH Key / PAT | Self-hosted Git |

### 2.3 `vulnerability` — Workload Vulnerability Scanning
Engines: vulnerability (SBOM, CVE, EPSS/CVSS scoring)

| Account Type | Auth Method | Target |
|---|---|---|
| `vuln_agent` | Bootstrap token → agent JWT | Linux/Windows server or container host |
| `container_registry` | Registry credentials | ECR / ACR / GCR / DockerHub |

Agent install flow: UI generates PKCE code_verifier → displays `install.sh --registration-id {id} --verifier {verifier}` → agent exchanges at `POST /api/v1/agents/bootstrap`.

### 2.4 `database` — Database Security
Engines: dbsec (access control, encryption, audit logging, backup/recovery)

| Account Type | Auth Method | Target |
|---|---|---|
| `postgres_db` | Connection string (host/port/user/password) or `db_agent` | PostgreSQL |
| `mysql_db` | Connection string or `db_agent` | MySQL / MariaDB |
| `mssql_db` | Connection string or `db_agent` | SQL Server |
| `mongodb_db` | Connection URI or `db_agent` | MongoDB |
| `oracle_db` | TNS string or `db_agent` | Oracle DB |
| `redis_db` | Connection string | Redis |

Agent mode: download DB agent → runs on-prem → phones home to onboarding engine via bootstrap token.

### 2.5 `middleware` — Application Middleware Security
Engines: technology-engine (tech-check, tech-inventory)

| Account Type | Auth Method | Target |
|---|---|---|
| `middleware_agent` | Bootstrap token → agent JWT | Nginx, Apache, Tomcat, JBoss, IIS, HAProxy, Kafka, RabbitMQ |

### 2.6 `technology` — Technology Inventory & Posture
Engines: technology-engine (4 sub-engines: tech-discovery/inventory/check/ciem)

| Account Type | Auth Method | Target |
|---|---|---|
| `tech_agent` | Bootstrap token → agent JWT | Any server/VM for tech stack discovery |
| (can also link to existing `cloud` accounts) | — | Scan via cloud discovery data |

### 2.7 `saas` — SaaS Platform Security *(future)*
Engines: TBD (dedicated saas-engine or routed through check engine)

| Account Type | Auth Method | Target |
|---|---|---|
| `github_org` | GitHub App | GitHub organization-level posture |
| `okta_org` | API Token | Okta tenant |
| `salesforce_org` | Connected App OAuth | Salesforce |
| `slack_workspace` | Bot Token | Slack workspace |
| `jira_project` | API Token | Jira/Confluence |

---

## 3. RBAC Matrix

### 3.1 Roles (unchanged seeded set + position in hierarchy)

| Role | Scope | Level |
|------|-------|-------|
| `platform_admin` | All organizations | 1 |
| `org_admin` | One organization | 2 |
| `tenant_admin` | One or more tenants (within an org) | 3 |
| `analyst` | One or more tenants | 4 |
| `viewer` | One or more tenants | 4 |

### 3.2 Permissions by Action

| Action | platform_admin | org_admin | tenant_admin | analyst | viewer |
|--------|:-:|:-:|:-:|:-:|:-:|
| **Organization** |
| Create org (signup) | ✓ | ✓ (own) | — | — | — |
| Update org name/slug | ✓ | ✓ (own) | — | — | — |
| Delete org | ✓ | — | — | — | — |
| View org | ✓ | ✓ (own) | ✓ (assigned) | ✓ (assigned) | ✓ (assigned) |
| **Users** |
| Invite user to org | ✓ | ✓ (own org) | — | — | — |
| Assign user to tenant + role | ✓ | ✓ (own org) | ✓ (own tenants) | — | — |
| Remove user from tenant | ✓ | ✓ (own org) | ✓ (own tenants) | — | — |
| View user list | ✓ | ✓ (own org) | ✓ (own tenants) | — | — |
| **Tenants** |
| Create tenant in org | ✓ | ✓ | ✓ | — | — |
| Update tenant | ✓ | ✓ (own org) | ✓ (own) | — | — |
| Delete tenant | ✓ | ✓ (own org) | ✓ (own) | — | — |
| View tenant list | ✓ | ✓ (own org) | ✓ (assigned) | ✓ (assigned) | ✓ (assigned) |
| **Accounts** |
| Add account to tenant | ✓ | ✓ (own org) | ✓ (own tenants) | ✓ (own tenants) | — |
| Update account | ✓ | ✓ (own org) | ✓ (own tenants) | ✓ (own tenants) | — |
| Delete account | ✓ | ✓ (own org) | ✓ (own tenants) | — | — |
| View accounts | ✓ | ✓ (own org) | ✓ (assigned) | ✓ (assigned) | ✓ (assigned) |
| **Scans** |
| Trigger scan | ✓ | ✓ | ✓ | ✓ | — |
| View scan results | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Reports** |
| Export findings/report | ✓ | ✓ | ✓ | ✓ | ✓ |
| **Billing** |
| View billing | ✓ | ✓ (own org) | — | — | — |
| Update plan | ✓ | ✓ (own org) | — | — | — |

---

## 4. User Assignment Flow

```
Step 1 — Signup
  POST /api/auth/signup/
  → Creates: User + Organization + default Tenant (type=cloud) + assigns org_admin role
  → Redirects to onboarding wizard

Step 2 — org_admin invites user
  POST /api/v1/organizations/{org_id}/invite/
  Body: { email, role: "tenant_admin" | "analyst" | "viewer", tenant_ids: [uuid, uuid] }
  → Creates InviteToken (48h TTL) → sends SES email
  → On accept: User created + TenantUser rows for each tenant_id + UserAdminScope if tenant_admin

Step 3 — tenant_admin creates tenants
  POST /api/v1/organizations/{org_id}/tenants/
  Body: { tenant_name: "Production AWS", tenant_type: "cloud" }
  → Creates Tenant row with org_id FK

Step 4 — tenant_admin (or org_admin, or analyst) adds account
  POST /api/v1/tenants/{tenant_id}/accounts/
  Body: { account_name, account_type, credentials: {...} }
  → Credential stored in Secrets Manager
  → account_type validated against tenant_type (e.g. can't add github_repo to a cloud tenant)

Step 5 — Account triggers first scan
  POST /api/v1/accounts/{account_id}/scan
  → Creates scan_run_id → Argo pipeline starts with tenant_type-appropriate engines
```

---

## 5. Tenant Type → Engine Routing

| Tenant Type | Engines Triggered |
|---|---|
| `cloud` | discovery → inventory → check → threat → compliance → iam → datasec → network → risk → ciem → encryption → container-sec → dbsec → ai-security |
| `secops` | secops (SAST/DAST/SCA/IaC) |
| `vulnerability` | vulnerability (SBOM, CVE, EPSS) |
| `database` | dbsec |
| `middleware` | technology-engine (tech-check, tech-inventory) |
| `technology` | technology-engine (all 4 sub-engines) |
| `saas` | *(future: saas-engine)* |

CNAPP and CWPP aggregate across multiple tenants (one org may have `cloud` + `vulnerability` + `secops` tenants — CNAPP score spans all three).

---

## 6. Data Model Changes Required

### Django Platform DB

```sql
-- organizations table (new)
CREATE TABLE organizations (
    id                  TEXT PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    slug                VARCHAR(100) UNIQUE NOT NULL,
    status              VARCHAR(50) DEFAULT 'active',
    billing_customer_id VARCHAR(255),
    created_by          TEXT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW()
);

-- organization_users table (new)
CREATE TABLE organization_users (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     TEXT NOT NULL REFERENCES roles(id),
    is_active   BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(org_id, user_id)
);

-- user_admin_scope table (new — fixes scope_resolver.py import error)
CREATE TABLE user_admin_scope (
    id          TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope_type  VARCHAR(50) NOT NULL,   -- 'organization' | 'tenant' | 'account'
    scope_id    TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, scope_type, scope_id)
);

-- tenants — add org FK and tenant_type
ALTER TABLE tenants ADD COLUMN organization_id TEXT REFERENCES organizations(id);
ALTER TABLE tenants ADD COLUMN tenant_type VARCHAR(50) DEFAULT 'cloud';
-- tenant_type: cloud | secops | vulnerability | database | middleware | technology | saas
```

### Onboarding Engine DB

```sql
-- cloud_accounts — add account_type (migration already exists: 20260503_account_type_and_agent_registrations.sql)
-- account_type: aws_account | azure_subscription | gcp_project | oci_tenancy | alicloud_account
--               ibm_account | kubernetes_cluster | github_repo | gitlab_project | bitbucket_repo
--               vuln_agent | container_registry | postgres_db | mysql_db | mssql_db | mongodb_db
--               oracle_db | redis_db | middleware_agent | tech_agent | saas_connector

-- tenants — add org_id and tenant_type
ALTER TABLE tenants ADD COLUMN org_id VARCHAR(255);
ALTER TABLE tenants ADD COLUMN tenant_type VARCHAR(50) DEFAULT 'cloud';

-- agent_registrations — already in 20260503 migration
```

---

## 7. Account Type Validation Rules

The API must enforce that `account_type` is valid for the parent tenant's `tenant_type`:

```python
VALID_ACCOUNT_TYPES = {
    "cloud":         {"aws_account", "azure_subscription", "gcp_project", "oci_tenancy", "alicloud_account", "ibm_account", "kubernetes_cluster"},
    "secops":        {"github_repo", "gitlab_project", "bitbucket_repo", "azure_devops_repo", "generic_git_repo"},
    "vulnerability": {"vuln_agent", "container_registry"},
    "database":      {"postgres_db", "mysql_db", "mssql_db", "mongodb_db", "oracle_db", "redis_db"},
    "middleware":    {"middleware_agent"},
    "technology":    {"tech_agent"},
    "saas":          {"github_org", "okta_org", "salesforce_org", "slack_workspace", "jira_project"},
}
```

---

## 8. Frontend Onboarding Wizard Flow

```
[Signup] → Creates Org + default cloud Tenant
    ↓
[Org Dashboard]
    ├── Add Tenant button → Choose tenant_type → Name it → Creates tenant
    │       ↓
    │   [Tenant Dashboard]
    │       ├── Add Account → wizard branches by account_type
    │       │       ├── cloud: choose CSP → enter credentials → validate → save
    │       │       ├── secops: enter git URL + PAT → validate → save
    │       │       ├── vulnerability: download agent → show install command (PKCE) → poll for registration
    │       │       ├── database: enter connection string OR download db_agent
    │       │       ├── middleware: download middleware_agent → show install command
    │       │       └── technology: download tech_agent → show install command
    │       │
    │       └── Manage Users → assign existing org users to this tenant with a role
    │
    └── Manage Users button → Invite new users to org → assign tenant(s) + role
```

---

## 9. Invite & User Assignment Flow Detail

```
org_admin perspective:
  1. /org/{org_id}/users → see all users in org
  2. Invite button → email + role + tenant_ids[]
     → system creates InviteToken(48h) + sends email
     → on accept: User + TenantUser rows + UserAdminScope (if tenant_admin)

tenant_admin perspective:
  1. /tenant/{tenant_id}/users → see users assigned to this tenant
  2. Add existing org user → assign role for this tenant (no invite needed)
  3. Cannot invite net-new users to org (org_admin only)

User can see: all tenants they are assigned to across the org
Tenant admin can see: their tenants only, not other tenants in the org
org_admin can see: everything in the org
platform_admin can see: everything across all orgs
```

---

## 10. API Endpoint Map

### Organization endpoints (Django)
```
POST   /api/v1/organizations/                          # signup / org_admin create sub-org
GET    /api/v1/organizations/                          # list orgs for current user
GET    /api/v1/organizations/{org_id}/                 # org detail
PATCH  /api/v1/organizations/{org_id}/                 # update name/slug
POST   /api/v1/organizations/{org_id}/invite/          # invite user to org + assign tenants
GET    /api/v1/organizations/{org_id}/users/           # list org users
DELETE /api/v1/organizations/{org_id}/users/{user_id}/ # remove user from org
```

### Tenant endpoints (Django → synced to onboarding engine)
```
POST   /api/v1/organizations/{org_id}/tenants/         # create tenant (tenant_admin or org_admin)
GET    /api/v1/organizations/{org_id}/tenants/         # list tenants in org
GET    /api/v1/tenants/{tenant_id}/                    # tenant detail
PATCH  /api/v1/tenants/{tenant_id}/                    # update tenant
DELETE /api/v1/tenants/{tenant_id}/                    # soft-delete
POST   /api/v1/tenants/{tenant_id}/users/              # assign org user to this tenant
GET    /api/v1/tenants/{tenant_id}/users/              # list users on this tenant
```

### Account endpoints (onboarding engine — via gateway)
```
POST   /api/v1/tenants/{tenant_id}/accounts/           # add account (validates account_type vs tenant_type)
GET    /api/v1/tenants/{tenant_id}/accounts/           # list accounts
GET    /api/v1/accounts/{account_id}/                  # account detail + last scan status
PATCH  /api/v1/accounts/{account_id}/                  # update (allow-list only)
DELETE /api/v1/accounts/{account_id}/                  # soft-delete
POST   /api/v1/accounts/{account_id}/credentials       # store/rotate credentials
POST   /api/v1/accounts/{account_id}/validate          # validate credentials
POST   /api/v1/accounts/{account_id}/scan              # trigger manual scan
POST   /api/v1/accounts/{account_id}/agent-token       # issue PKCE code_challenge for agent accounts
POST   /api/v1/agents/bootstrap                        # agent exchanges code_verifier for session JWT
```

---

## 11. CNAPP/CWPP Aggregation Across Tenant Types

CNAPP and CWPP aggregate security posture across multiple engines. With the new hierarchy, aggregation scopes by **organization** (across all tenants the user can see):

```
CNAPP score for Org "Acme Corp":
  cloud tenants   → cspm + iam + network + datasec + encryption + container-sec + dbsec + ai-security
  secops tenants  → secops findings
  vuln tenants    → vulnerability findings
  db tenants      → dbsec findings (agent-based)

CWPP score:
  cloud tenants   → container workloads + serverless + EC2/VMs
  vuln tenants    → agent-based workload scans
```

BFF aggregates by `org_id` when `scope=organization`, by `tenant_id` when `scope=tenant`.

---

## 12. Sprint Story Breakdown

### Sprint A — Foundation (must be done first, blocks everything)
| Story | What | Owner |
|-------|------|-------|
| A-1 | Django migrations 0011/0012/0013: organizations + organization_users + user_admin_scope + tenant_type column | bmad-dev |
| A-2 | Fix scope_resolver.py UserAdminScope import error + line 104 logic bug | bmad-dev |
| A-3 | provision_org_and_tenant() replacing provision_first_tenant() | bmad-dev |
| A-4 | Async tenant sync (Celery task, dead-letter, /resync endpoint) | bmad-dev |

### Sprint B — Auth Security Fixes (parallel with A after A-1 merges)
| Story | What | Owner |
|-------|------|-------|
| B-1 | Email enumeration fix (BLOCK-01), rate limiting (BLOCK-02), CAPTCHA | bmad-dev |
| B-2 | Google OAuth hd validation (BLOCK-03), FRONTEND_URL allowlist | bmad-dev |
| B-3 | TenantViewSet DRF auth (BLOCK-08), export scoping (BLOCK-09), IDP domain rate-limit (BLOCK-10) | bmad-dev |
| B-4 | Remove developer_role bypass (BLOCK-07), org-boundary enforcement (BLOCK-11) | bmad-dev |

### Sprint C — Onboarding Engine Revamp (parallel with B)
| Story | What | Owner |
|-------|------|-------|
| C-1 | Apply migration 20260503, fix account_type INSERT + ORM model | bmad-dev |
| C-2 | Verify scan_runs vs scan_orchestration naming in live RDS | bmad-dev |
| C-3 | Auth middleware on onboarding engine (BLOCK-05), PATCH allow-list (BLOCK-06) | bmad-dev |
| C-4 | Agent bootstrap PKCE endpoint (POST /agents/bootstrap) | bmad-dev |
| C-5 | Account type validation against tenant_type in API | bmad-dev |

### Sprint D — Organization API + Frontend (after A completes)
| Story | What | Owner |
|-------|------|-------|
| D-1 | Organization CRUD API views (Django) | bmad-dev |
| D-2 | Tenant CRUD scoped to org (POST /organizations/{org_id}/tenants/) | bmad-dev |
| D-3 | MeView response — add organizations[] array, fix subscription org_id | bmad-dev |
| D-4 | Frontend: org/tenant switcher, AuthContext selectedOrg/selectedTenant | bmad-dev |
| D-5 | Frontend: onboarding wizard — tenant_type selection + account_type branching | bmad-dev |
| D-6 | Frontend: invite flow — org invite with tenant assignment | bmad-dev |
