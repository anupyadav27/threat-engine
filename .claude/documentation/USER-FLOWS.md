# CSPM Platform — All User Flows (Block Level)

**Date:** 2026-05-03  
**Hierarchy:** `customer_id` (org) → Tenant [typed] → Account [typed] → Scan Run → Findings

---

## Flow 1 — New User Self-Signup

```
┌─────────────────────────────────────────────────────────────────┐
│  USER                    │  FRONTEND              │  BACKEND     │
├─────────────────────────────────────────────────────────────────┤
│  Opens /signup           │                        │              │
│  Fills form:             │  Renders signup form   │              │
│  name, email,            │  + hCaptcha widget     │              │
│  company, password       │                        │              │
│                          │                        │              │
│  Submits form            │  POST /api/auth/signup/│              │
│                          │  {name, email,         │              │
│                          │   password, company,   │              │
│                          │   hcaptcha_token}      │              │
│                          │                        │ Verify CAPTCHA│
│                          │                        │ Check email   │
│                          │                        │   exists?     │
│                          │                        │   YES → 200   │
│                          │                        │   "verification│
│                          │                        │    email sent" │
│                          │                        │   NO ↓        │
│                          │                        │ Create User   │
│                          │                        │ customer_id   │
│                          │                        │ = str(user.id)│ ← ORG FOUNDED
│                          │                        │ Create Tenant │
│                          │                        │ (type='cloud')│
│                          │                        │ Create        │
│                          │                        │ TenantUsers   │
│                          │                        │ (org_admin)   │
│                          │                        │ Create        │
│                          │                        │ UserAdminScope│
│                          │                        │ COMMIT txn    │
│                          │                        │ → Celery:     │
│                          │                        │   sync_tenant │
│                          │                        │   to_onboarding│
│                          │                        │ → Celery:     │
│                          │                        │   billing_trial│
│                          │                        │ Return 201    │
│                          │  Redirect /onboarding  │              │
│  Sees onboarding wizard  │                        │              │
└─────────────────────────────────────────────────────────────────┘
```

**Rate limits:** 10 signups/hour per IP  
**CAPTCHA:** hCaptcha (skipped if HCAPTCHA_SECRET_KEY not set in dev)  
**Email enumeration:** duplicate email always returns 200 generic message, never 409  

---

## Flow 2 — Login (Local Email + Password)

```
┌─────────────────────────────────────────────────────────────────┐
│  /login → POST /api/auth/login/ {email, password}               │
│           │                                                      │
│           ├─ Rate limit: 20/hr per IP                           │
│           │                                                      │
│           ├─ Invalid credentials → 401 (no info leak)           │
│           │                                                      │
│           └─ Valid ↓                                            │
│              Build scope_cache:                                  │
│                customer_id: user.customer_id                    │
│                tenant_ids: [from TenantUsers]                   │
│                account_ids: [from UserAccountAccess]            │
│                permissions: [from role → role_permissions]      │
│              Create UserSession (access_token, refresh_token)   │
│              Set cookie: access_token (httponly, secure)        │
│              Return 200 → redirect /dashboard                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 3 — Login (Google OAuth)

```
┌─────────────────────────────────────────────────────────────────┐
│  /login → "Sign in with Google"                                  │
│           │                                                      │
│           └─ Redirect to Google OAuth consent                   │
│              Google callback: /api/auth/google/callback/?code=..│
│              │                                                    │
│              ├─ Exchange code for token                          │
│              ├─ Get profile: {email, name, hd, picture}         │
│              ├─ Validate hd: email.split("@")[1] == requested_hd│ ← BLOCK-03
│              │   FAIL → 403 "Domain mismatch"                   │
│              │   PASS ↓                                          │
│              ├─ User exists by email?                            │
│              │   YES → update last_login → create session       │
│              │   NO  → create User                              │
│              │         customer_id = str(user.id)               │
│              │         provision_org_and_tenant()               │
│              └─ Set cookie → redirect /dashboard                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 4 — Login (SAML SSO)

```
┌─────────────────────────────────────────────────────────────────┐
│  /login → user enters email domain                               │
│           │                                                      │
│           GET /api/v1/tenants/idp-by-domain/?domain=acme.com    │
│           Rate limit: 5/min per IP                              │ ← BLOCK-10
│           Response: {idp_type, redirect_url}  (NO tenant_id)   │ ← BLOCK-10
│           │                                                      │
│           Redirect to SAML IdP                                  │
│           SAML assertion callback: /api/auth/saml/callback/     │
│           │                                                      │
│           ├─ Validate assertion signature                        │
│           ├─ Extract email from NameID                          │
│           ├─ Lookup tenant_idp_configs for this domain           │
│           ├─ User exists?                                        │
│           │   YES → create session                              │
│           │   NO  → JIT provision: create User                  │
│           │         inherit customer_id from org's config       │
│           └─ Set cookie → redirect /dashboard                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 5 — Password Reset

```
┌─────────────────────────────────────────────────────────────────┐
│  /login → "Forgot Password" → enter email                        │
│           │                                                      │
│           POST /api/auth/password-reset/                        │
│           ALWAYS return 200 generic message                     │ ← no enumeration
│           │                                                      │
│           [If user exists]:                                     │
│             create password_reset_tokens row (TTL 1hr)          │
│             send email with reset link                           │
│           │                                                      │
│           User clicks link → /reset-password?token=...          │
│           POST /api/auth/password-reset/confirm/                │
│             validate token → update User.password               │
│             invalidate all active UserSessions for this user    │
│             return 200 → redirect /login                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 6 — Onboarding Wizard (First Login After Signup)

```
┌─────────────────────────────────────────────────────────────────┐
│  New user lands on /onboarding (has 1 tenant: type=cloud)        │
│                                                                  │
│  STEP 1 — Choose what to connect                                │
│  ┌──────────┬──────────┬────────────┬──────────┬──────────┐    │
│  │  Cloud   │  SecOps  │  Vuln Scan │ Database │Middleware│    │
│  │ AWS/GCP  │ Git repos│ Agent-based│  Agents  │  Agents  │    │
│  │ Azure etc│ IaC scan │            │          │          │    │
│  └──────────┴──────────┴────────────┴──────────┴──────────┘    │
│                                                                  │
│  Selection determines:                                           │
│    a) Tenant type (cloud | secops | vulnerability | ...)        │
│    b) Auth steps that follow                                     │
│                                                                  │
│  (If user skips: lands on /dashboard with empty state)          │
└─────────────────────────────────────────────────────────────────┘
```

**Branch A — Cloud Account (AWS/Azure/GCP/OCI/AliCloud)**
```
STEP 2: Select CSP
STEP 3: Provide credentials
  AWS:   access_key_id + secret_access_key  OR  assume-role ARN
  Azure: client_id + tenant_id + client_secret
  GCP:   service account JSON upload
  OCI:   config file + key pem upload
  K8s:   kubeconfig upload
STEP 4: Validate credentials (test connection via onboarding engine)
  FAIL → show error, re-enter credentials
  PASS → account_id auto-detected (e.g. AWS account number)
STEP 5: Name the account (optional label)
STEP 6: Create cloud_account in onboarding DB
STEP 7: Choose: scan now | schedule
  → If "scan now" → trigger Argo pipeline → redirect /scan/{scan_run_id}/progress
  → If "schedule" → set cron → /dashboard
```

**Branch B — SecOps (IaC / Code Repos)**
```
STEP 2: Enter Git repo URL
STEP 3: Auth method
  GitHub PAT | GitLab token | SSH key | GitHub App install
STEP 4: Select branches to scan
STEP 5: Validate access (test clone)
STEP 6: Create cloud_account (account_type='secops')
STEP 7: Trigger scan or schedule
```

**Branch C — Vulnerability Scanning (Agent-Based)**
```
STEP 2: Show install instructions
  "Install the Vulnerability Agent on your target system"
STEP 3: Backend generates agent bootstrap token
  POST /api/v1/tenants/{id}/agent-token (PKCE-like, 15min TTL)
  require_permission("cloud_accounts:write")               ← BLOCK-04
  Hash: make_password(token) stored in agent_registrations ← BLOCK-04
STEP 4: Show install command:
  curl -sSL https://install.cspm.io | bash \
    --registration-id {registration_id} \
    --verifier {code_verifier}
STEP 5: Wait for agent to phone home
  Agent calls POST /api/v1/agents/bootstrap
  Agent registered → cloud_account auto-created
STEP 6: /dashboard (agent shows as "connected")
```

**Branch D — Database / Middleware (Agent-Based)**
Same as Branch C — agent download model with docker/apt install command.

**Branch E — Technology (SaaS/Tech inventory)**
```
STEP 2: Select tech type (Kubernetes / SaaS platform)
STEP 3: API key or kubeconfig
STEP 4: Validate + create account
```

---

## Flow 7 — Existing User: Add New Tenant

```
┌─────────────────────────────────────────────────────────────────┐
│  /dashboard → Settings → Tenants → "New Tenant"                  │
│                                                                  │
│  STEP 1: Tenant Name + Tenant Type                               │
│          cloud | secops | vulnerability | database |             │
│          middleware | technology | saas                         │
│                                                                  │
│  Backend (org_admin or platform_admin only):                    │
│    Verify user.customer_id is set                               │
│    Create Tenant (customer_id = user.customer_id, type = picked)│
│    Create TenantUsers (user → new_tenant, role = org_admin)     │
│    Celery: sync_tenant_to_onboarding (async, outside atomic())  │
│    Return new tenant_id                                         │
│                                                                  │
│  STEP 2: Redirect → /tenants/{id}/add-account                   │
│    (same as Onboarding Wizard from STEP 1 above)                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 8 — Existing User: Add New Account to Existing Tenant

```
┌─────────────────────────────────────────────────────────────────┐
│  /tenants/{id} → "Add Account"                                   │
│                                                                  │
│  Tenant type determines which account types are valid:           │
│  ┌─────────────────┬────────────────────────────────────┐       │
│  │ Tenant Type     │ Valid Account Types                 │       │
│  ├─────────────────┼────────────────────────────────────┤       │
│  │ cloud           │ aws, azure, gcp, oci, alicloud, k8s│       │
│  │ secops          │ github, gitlab, bitbucket, local   │       │
│  │ vulnerability   │ agent (vuln-agent)                  │       │
│  │ database        │ agent (db-agent)                    │       │
│  │ middleware      │ agent (mw-agent)                    │       │
│  │ technology      │ k8s, saas-api                       │       │
│  │ saas            │ api-key, oauth                      │       │
│  └─────────────────┴────────────────────────────────────┘       │
│                                                                  │
│  → Same credential steps as Onboarding Wizard branches A-E      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 9 — Invite User to Org / Tenant / Account

```
┌─────────────────────────────────────────────────────────────────┐
│  WHO CAN INVITE?                                                  │
│    platform_admin: invite anyone to any org/tenant              │
│    org_admin: invite within their customer_id                   │
│    tenant_admin: invite within their tenant only                │
│                                                                  │
│  Settings → Users → "Invite User"                                │
│                                                                  │
│  STEP 1: Enter email                                             │
│  STEP 2: Select scope                                            │
│    Option A: Entire org (all current + future tenants)          │
│              → role: org_admin (only org_admin can grant this)  │
│    Option B: One or more specific tenants                        │
│              → role: tenant_admin | analyst | viewer            │
│    Option C: Specific account(s) within a tenant                │
│              → role: account_admin | analyst | viewer           │
│  STEP 3: Select role for the chosen scope                        │
│                                                                  │
│  Backend:                                                        │
│    Validate inviter has permission for chosen scope             │
│    Create user_invitations row:                                  │
│      {email, customer_id (inviter's), tenant_ids, role,         │
│       account_ids (if account-scoped), expires_at=+48h}         │
│    Send invite email with signed token                          │
│    Return 201                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 10 — Accept Invite

```
┌─────────────────────────────────────────────────────────────────┐
│  Invitee clicks link: /accept-invite?token=...                   │
│                                                                  │
│  Backend:                                                        │
│    Look up user_invitations by token                            │
│    Token expired? → 410 "Invite expired. Request a new one."    │
│                                                                  │
│    Is invitee email already a user?                             │
│      NO  → Show signup form (name, password)                    │
│            Create User                                          │
│            customer_id = invite.customer_id  ← INHERIT ORG     │
│      YES → Verify identity (login if not already logged in)     │
│                                                                  │
│    Is invite cross-org? (invitee.customer_id != invite.customer_id)
│      YES → CAP role at viewer, log audit event                  │
│      NO  → use invited role as-is                               │
│                                                                  │
│    Create TenantUsers rows (one per invited tenant_id)          │
│    If account-scoped: create UserAccountAccess rows             │
│    Delete user_invitations row                                  │
│    Create UserSession → set cookie                              │
│    Redirect /dashboard                                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 11 — Assign User or Group to Tenant/Account (Post-Invite)

```
┌─────────────────────────────────────────────────────────────────┐
│  DIRECT USER ASSIGNMENT                                           │
│  /tenants/{id}/members → "Add Member"                           │
│    Search user by email → select role → Save                    │
│    Backend: INSERT INTO tenant_users (user, tenant, role)       │
│                                                                  │
│  GROUP-BASED ASSIGNMENT                                          │
│  Step 1: Create Group                                            │
│    /settings/groups → "New Group" → name → Add members          │
│    Backend: INSERT INTO cspm_groups + group_members             │
│                                                                  │
│  Step 2: Assign Group to Tenant                                  │
│    /tenants/{id}/groups → "Assign Group" → select role          │
│    Backend: INSERT INTO tenant_group_access (group, tenant, role)│
│                                                                  │
│  Step 3: (Optional) Restrict to specific account                │
│    /tenants/{id}/accounts/{account_id}/access                   │
│    → assign user or group with role                             │
│    Backend: INSERT INTO account_group_access or                 │
│             user_account_access (with role FK)                  │
│                                                                  │
│  AuthContext resolution order:                                   │
│    1. UserAdminScope (org-level) → broadest access              │
│    2. TenantUsers (tenant-level)                                │
│    3. tenant_group_access (group → tenant)                      │
│    4. UserAccountAccess / account_group_access (account-level)  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 12 — Switch Tenant / Org (Logged-In User)

```
┌─────────────────────────────────────────────────────────────────┐
│  [Header] → Org/Tenant switcher dropdown                         │
│                                                                  │
│  Shows: orgs the user belongs to (from UserAdminScope)           │
│         tenants within each org (from TenantUsers + groups)     │
│                                                                  │
│  User selects different tenant:                                  │
│    Frontend: set selectedTenant in AuthContext (no re-login)    │
│    All BFF fetchView() calls use new engine_tenant_id           │
│                                                                  │
│  User selects different org (multi-org user):                    │
│    Frontend: set selectedOrg + reset selectedTenant             │
│    No backend call needed (scope_cache already has all orgs)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 13 — Trigger / Monitor a Scan

```
┌─────────────────────────────────────────────────────────────────┐
│  /tenants/{id}/accounts → account card → "Scan Now"              │
│                                                                  │
│  POST /api/v1/scans/ {account_id, tenant_id, scan_type}         │
│    require_permission("scans:create")                           │
│    Create scan_runs row in onboarding DB                        │
│    Trigger Argo workflow (via scan trigger script)              │
│    Return {scan_run_id}                                         │
│                                                                  │
│  Redirect /scans/{scan_run_id}/progress                         │
│    SSE stream from pipeline-monitor engine                      │
│    Shows per-engine progress bars                               │
│    On complete → redirect /dashboard (findings loaded)          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Flow 14 — Agent Bootstrap (Vulnerability / DB / Middleware Agents)

```
┌─────────────────────────────────────────────────────────────────┐
│  PKCE-LIKE DESIGN (no raw token in shell history)                │
│                                                                  │
│  1. UI (JavaScript) generates:                                   │
│       code_verifier = crypto.randomBytes(32)                    │
│       code_challenge = SHA256(code_verifier)                    │
│                                                                  │
│  2. POST /api/v1/tenants/{id}/agent-token                        │
│       {code_challenge, account_type, label}                     │
│     Backend:                                                     │
│       require_permission("cloud_accounts:write")                │
│       Verify tenant belongs to user's customer_id               │
│       Store: agent_registrations row                            │
│         {id=registration_id, tenant_id,                         │
│          code_challenge_hash=make_password(code_challenge),     │
│          status='pending', expires_at=NOW()+15min}              │
│     Returns: {registration_id} (NOT the verifier)               │
│                                                                  │
│  3. UI shows install command:                                    │
│       install.sh \                                              │
│         --registration-id {registration_id} \                  │
│         --verifier {code_verifier}                              │
│       (code_verifier is shown ONCE, then discarded by UI)       │
│                                                                  │
│  4. Agent runs install.sh:                                       │
│     POST /api/v1/agents/bootstrap                               │
│       {registration_id, code_verifier}                          │
│     Backend:                                                     │
│       Look up agent_registrations by registration_id            │
│       check_password(code_verifier, code_challenge_hash)        │
│       FAIL → 401                                                │
│       PASS → mark status='active'                               │
│              create cloud_account row in onboarding DB          │
│              return {agent_token, tenant_id}  (for ongoing use) │
│                                                                  │
│  5. Agent stores agent_token locally (encrypted keystore)       │
│     Uses for all subsequent scan calls                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## Decision Matrix — Who Can Do What

```
┌────────────────────────────┬──────────┬──────────┬──────────┬──────────┬──────────┐
│ Action                     │platform  │ org_     │ tenant_  │ analyst  │ viewer   │
│                            │ _admin   │ admin    │ admin    │          │          │
├────────────────────────────┼──────────┼──────────┼──────────┼──────────┼──────────┤
│ Create org (customer_id)   │    ✓     │  self    │          │          │          │
│ Create tenant              │    ✓     │  own org │          │          │          │
│ Add cloud account          │    ✓     │  own org │  own     │          │          │
│                            │          │          │ tenant   │          │          │
│ Invite user (org level)    │    ✓     │  own org │          │          │          │
│ Invite user (tenant level) │    ✓     │  own org │  own     │          │          │
│                            │          │          │ tenant   │          │          │
│ Create group               │    ✓     │  own org │          │          │          │
│ Assign group to tenant     │    ✓     │  own org │  own     │          │          │
│                            │          │          │ tenant   │          │          │
│ Trigger scan               │    ✓     │    ✓     │    ✓     │          │          │
│ View findings              │    ✓     │    ✓     │    ✓     │    ✓     │    ✓     │
│ Export findings            │    ✓     │    ✓     │    ✓     │    ✓     │          │
│ View IAM/DataSec/          │    ✓     │    ✓     │    ✓     │    ✓     │    ✗     │
│ SecOps/Vuln detail         │          │          │          │          │ (403)    │
│ Platform admin panel       │    ✓     │          │          │          │          │
│ Billing management         │    ✓     │    ✓     │          │          │          │
│ Delete tenant              │    ✓     │  own org │          │          │          │
│ Resync tenant              │    ✓     │          │          │          │          │
│ (sync_failed recovery)     │          │          │          │          │          │
└────────────────────────────┴──────────┴──────────┴──────────┴──────────┴──────────┘

Note: org_admin scope is ALWAYS bounded by tenant.customer_id = user.customer_id
```

---

## State Machine — Tenant Status

```
    provision_org_and_tenant()
            │
            ▼
      ┌──────────┐
      │provisioning│ ← Celery task queued
      └──────────┘
          │  │
          │  └── Celery task fails (3 retries) ──► ┌────────────┐
          │                                          │ sync_failed│◄── POST /resync
          ▼                                          └────────────┘
      ┌────────┐                                           │
      │ active │◄──────────────────────────────────────────┘
      └────────┘                                    (Celery retry)
          │
          └── platform_admin action ──► ┌───────────┐
                                        │ suspended │
                                        └───────────┘
```

---

## State Machine — Agent Registration Status

```
POST /agent-token
       │
       ▼
  ┌─────────┐
  │ pending │ (15 min TTL)
  └─────────┘
      │  │
      │  └── TTL expires ──► ┌─────────┐
      │                      │ expired │
      ▼                      └─────────┘
  ┌────────┐
  │ active │ ◄── agent bootstrap success
  └────────┘
      │
      └── org_admin revoke ──► ┌──────────┐
                                │ revoked  │
                                └──────────┘
```

---

## Sprint Execution Order

```
Sprint A (DB Foundation)
  A1: Migrations 0011/0012/0013 (drop dead tables, add tenant_type, customer_id, groups)
  A2: provision_org_and_tenant() — replace provision_first_tenant()
  A3: Async Celery tenant sync + dead-letter + resync endpoint
         │
         ▼
Sprint B (Auth Security Fixes — BLOCK-01 to BLOCK-12)
  B1: Signup enumeration fix + rate limits + CAPTCHA
  B2: Google OAuth hd validation + redirect safety
  B3: TenantViewSet DRF auth + export filter + IDP rate limit
  B4: org_admin boundary (customer_id) + remove developer bypass
         │
         ▼
Sprint C (Onboarding Engine)
  C1: Add account_type + auth_config to cloud_accounts (apply existing migration)
  C2: Fix onboarding engine ORM models (account_type on CREATE)
  C3: Onboarding engine auth middleware (BLOCK-05)
  C4: CloudAccountUpdate Pydantic allow-list (BLOCK-06)
  C5: Agent bootstrap endpoint (PKCE)
         │
         ▼
Sprint D (Frontend Wizard)
  D1: Tenant-type selector in onboarding
  D2: Credential form branching (by account_type)
  D3: Agent install flow UI (vuln/db/middleware)
  D4: User/group assignment UI
  D5: Tenant switcher + org context
  D6: Scan trigger + progress monitor integration
```
