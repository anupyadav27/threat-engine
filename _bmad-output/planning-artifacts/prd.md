---
stepsCompleted: ['step-01-init', 'step-02-discovery', 'step-02b-vision', 'step-02c-executive-summary', 'step-03-success', 'step-04-journeys', 'step-05-domain-requirements', 'step-06-innovation', 'step-07-b2b-requirements', 'step-08-scoping', 'step-09-functional', 'step-10-nonfunctional', 'step-11-polish', 'step-12-complete']
inputDocuments:
  - 'memory/project_onboarding_revamp.md'
  - 'memory/project_auth_onboarding_sprint.md'
  - '.claude/planning/SPRINT-PLAN-AUTH-ONBOARDING.md'
  - 'engines/onboarding/api/cloud_accounts.py'
  - 'engines/onboarding/api/agents.py'
  - 'engines/onboarding/api/schedules.py'
  - 'engines/onboarding/api/credentials.py'
  - 'engines/onboarding/api/scans.py'
  - 'engines/onboarding/database/models.py'
  - 'engines/onboarding/database/scan_run_operations.py'
  - 'engines/onboarding/tasks/credential_health_check.py'
  - 'engines/onboarding/storage/secrets_manager_storage.py'
  - 'engines/platform-admin/routers/orgs.py'
  - 'platform/cspm-backend/user_auth/models.py'
  - 'platform/cspm-backend/user_auth/urls.py'
  - 'platform/cspm-backend/tenant_management/models.py'
  - 'platform/cspm-backend/tenant_management/urls.py'
workflowType: 'prd'
releaseMode: 'single-release'
classification:
  projectType: saas_b2b
  domain: cloud_security_credential_management
  complexity: high
  projectContext: brownfield
groundTruthAudit:
  auditedBy: ['onboarding-engine-expert', 'platform-admin-engine', 'billing-engine', 'vulnerability-engine']
  auditDate: '2026-05-11'
---

# Product Requirements Document — Customer Onboarding & Credential Management

**Author:** Anup Yadave
**Date:** 2026-05-11
**Status:** Final
**Feature Area:** Platform Onboarding, Credential Lifecycle, User Provisioning

---

## Executive Summary

The Onam Security CSPM platform has 18+ scanning engines in production but no controlled customer provisioning path. Every customer org is created through self-service signup, credentials are partially managed through AWS Secrets Manager but lack expiry tracking, and the vulnerability agent's auth system is entirely disconnected from the onboarding engine's PKCE bootstrap. A legacy credential router with zero authentication sits live in production. This PRD defines the **Customer Onboarding & Credential Management** system: a single-release effort that closes these gaps, introduces a platform-admin-controlled org creation flow, and establishes a complete 4-stage credential lifecycle across all account types.

**Target personas:**
- **Platform Admin:** Onam Security operator who provisions new customer orgs, creates initial users, and assigns org-level access. Currently has no endpoint to create orgs — this is the primary new capability.
- **Org Admin:** Customer security lead who adds tenants, cloud accounts, and credentials. Onboarding wizard drives them from account creation to first validated scan.
- **Tenant Admin:** Scoped to a specific tenant; adds cloud accounts, manages credentials, triggers scans, monitors pipeline status.
- **VUL Agent (system actor):** The installed vulnerability scanning agent that phones home to register itself and submit scan results. Currently disconnected from onboarding auth.

**Problem being solved:** Customers cannot be provisioned in a controlled, operator-managed way. Credential expiry is not tracked in the database, so expiry notifications cannot fire. The agent install flow issues a JWT that the vulnerability engine ignores. Seven endpoints accept credential operations with no authentication. The platform captures security value but has no governed entry point for new enterprise customers.

### What Makes This Special

The enforcement layer already exists: AWS Secrets Manager integration, PKCE agent bootstrap, real CSP validation API calls (STS, ARM, GCP IAM), Django SAML/OAuth, RBAC, and group tables are all implemented. The differentiator is **connective tissue** — wiring these components into a governed, end-to-end flow where platform admin controls org creation, credentials follow a tracked 4-stage lifecycle, and agents self-register through a consistent auth path. No competitor offers an operator-controlled provisioning model that spans cloud, code, and agent-based scan types in a single wizard.

---

## Project Classification

- **Project Type:** SaaS B2B — multi-tenant cloud security platform
- **Domain:** Cloud Security / Credential Management / DevSecOps
- **Complexity:** High — cross-engine auth dependencies, multi-CSP credential validation, regulated credential data, real-time agent callbacks, billing initialization coupling
- **Project Context:** Brownfield — 4 partially-built components (onboarding engine, platform-admin engine, Django auth backend, VUL agent) with confirmed gaps from live code audit conducted 2026-05-11

---

## Success Criteria

### User Success

- A platform admin can create a new customer org, provision initial users, and set access scope entirely within the CSPM portal — no direct DB inserts or manual steps required.
- An org admin reaches a validated, scan-ready cloud account within 10 minutes of entering credentials.
- A tenant admin installs the vulnerability agent, sees status flip from **Pending** to **Connected** in the UI within 60 seconds of the agent phoning home, without any manual backend intervention.
- Org admins and platform admins receive credential expiry email alerts at day 76 and are never surprised by a scan blockage at day 90.

### Business Success

- 100% of new enterprise customer orgs provisioned through the platform admin flow — zero orgs created via direct Django admin or DB access.
- Credential expiry rate drops to zero within 90 days of launch, measured by active accounts with `credential_validation_status = expired`.
- All inbound scan pipeline triggers succeed (zero failures from the `scan_runs` vs `scan_orchestration` table name mismatch bug).

### Technical Success

- Zero unauthenticated credential endpoints in the onboarding engine (legacy `/api/v1/accounts` router removed or fully gated).
- `cloud_accounts` table has `expires_at` and `last_rotated_at` columns and all active accounts have these populated.
- Credential expiry Celery beat task is deployed as a running K8s pod — not just code — and fires on schedule.
- Billing trial record (`org_subscriptions`, status `trialing`) is auto-initialized on every new org creation via `POST /api/v1/billing/trial/provision`.
- `org_id` in billing aligns with `customer_id` in Django and onboarding engines — single consistent identifier across all services.

### Measurable Outcomes

| Metric | Target | How Measured |
|---|---|---|
| Time to first validated scan | ≤ 10 min | Timestamp delta: account_created_at → credential_validated_at |
| Unauthenticated credential endpoints | 0 | Security audit of all `/api/v1/accounts` and `/api/v1/cloud-accounts` routes |
| Active creds with expiry tracked | 100% | `SELECT COUNT(*) FROM cloud_accounts WHERE expires_at IS NULL AND account_status='active'` = 0 |
| Expiry notifications fired on time | 100% | Celery task log: alert sent before day 76 for all qualifying accounts |
| Scan pipeline trigger success rate | 100% | `scan_orchestration` write success rate after table name fix |

---

## User Journeys

### Journey 1 — Platform Admin: Onboarding a New Enterprise Customer

**Opening scene:** Priya is a platform admin at Onam Security. A new enterprise customer, FinVault, has signed a contract. Priya logs into the CSPM portal with her `platform_admin` role.

**Rising action:** Priya navigates to Platform Admin → Customer Orgs → New Customer. She enters FinVault's org name and contact email. The system creates a new `customer_id`, calls `POST /api/v1/billing/trial/provision` to initialize a 14-day Pro trial, and the org appears in the org list as `status=active`.

Priya then clicks "Add Users" and enters two email addresses — a security engineer (org-level access) and a team lead (org-group-level access to only the production tenant). The system sends invite emails via SES. She assigns both users to the `org_admin` role for the first, and `tenant_admin` scoped to the prod-tenant group for the second.

**Climax:** Priya clicks "Complete Provisioning." The portal sends both invite emails and shows FinVault in the customer list with status `Provisioned`, trial days remaining, and zero tenants. She copies the portal login URL and sends it to FinVault.

**Resolution:** FinVault's security engineer receives the invite email, clicks the link, sets their password (or authenticates via Google OAuth), and lands on the Onam portal with a clean onboarding wizard waiting for them.

---

### Journey 2 — Org Admin: Cloud Account Onboarding (AWS)

**Opening scene:** Marcus is FinVault's org admin. He accepts his invite, logs in, and sees the "Add your first tenant" wizard step.

**Rising action:** Marcus creates a tenant named "FinVault AWS Production" with `tenant_type=cloud`. The wizard then steps him to "Add Cloud Account." He selects AWS as the provider, enters his AWS access key ID and secret. The UI shows a clear field map: which credential goes where, what minimum IAM permissions are needed.

He clicks "Save & Validate." The onboarding engine retrieves the credential reference from AWS Secrets Manager at `threat-engine/account/{account_id}`, calls `sts:GetCallerIdentity`, and returns PASS in under 5 seconds. The AWS account number auto-fills the `account_number` field.

**Climax:** Marcus sees a green checkmark on the Credentials step. The wizard automatically enrolls the account on the default daily scan schedule. He clicks "Trigger First Scan" — an ad-hoc scan fires immediately.

**Resolution:** Within minutes, the pipeline status page shows Discovery → Inventory → Check progressing. Marcus bookmarks the scan status page and reports to his team: "We're scanning AWS production."

---

### Journey 3 — Tenant Admin: Vulnerability Agent Install

**Opening scene:** Fatima is a tenant admin at FinVault responsible for container security. She needs to onboard their Kubernetes cluster for vulnerability scanning.

**Rising action:** Fatima adds a new account under the FinVault tenant, selects `account_type=vulnerability`. The wizard shows: "Install the Onam Vulnerability Agent on your target environment." A code block appears:

```bash
curl -sSL https://agents.onam.cloud/install.sh | bash -s -- \
  --tenant FinVault-prod \
  --token <generated-agent-token> \
  --endpoint https://api.onam.cloud/vuln
```

She copies the command, runs it on the target VM. The agent installs, calls `POST /api/v1/agents/register` on the VUL engine with the token, and the VUL engine records the registration.

**Climax:** Back in the portal, Fatima watches the agent status card. Within 60 seconds it flips from **Pending** to **Connected** — the onboarding engine has polled `GET /api/v1/agents/{id}/status` and confirmed the heartbeat. The account `credential_validation_status` is set to `valid`.

**Resolution:** The first vulnerability scan runs automatically on the agent's default 1-hour interval. Fatima sees CVEs appearing in the Vulnerability page. No credentials were entered, no API keys stored in her config files.

---

### Journey 4 — System: Credential Expiry Notification

**Opening scene:** It's day 76 since FinVault's AWS credentials were created. The Celery beat task fires at 3 AM UTC on Monday.

**Rising action:** The `credential_health_check` task queries:
```sql
SELECT account_id, tenant_id, customer_id, expires_at
FROM cloud_accounts
WHERE expires_at <= NOW() + INTERVAL '14 days'
  AND account_status = 'active'
  AND credential_validation_status != 'expired';
```

It finds FinVault's AWS Production account. It sends an SES email to Marcus (org admin) and Priya (platform admin): "AWS Production credentials expire in 14 days. Log in to rotate them."

**Climax:** Marcus logs in, navigates to the account, clicks "Rotate Credentials." He enters new access keys. The engine stores them in AWS SM, calls `sts:GetCallerIdentity` again, updates `credential_validated_at`, `last_rotated_at`, and resets `expires_at` to 90 days from now. Status stays `valid`.

**Resolution:** No scan disruption. No day-90 INACTIVE flip. The next expiry reminder won't fire for another 76 days.

---

### Journey 5 — Platform Admin: Visibility Across All Customers

**Opening scene:** Priya starts her Monday morning review of the platform health dashboard.

**Rising action:** She opens Platform Admin → All Customers. She sees FinVault: 2 tenants, 4 accounts, all credentials valid, last scan 6 hours ago. She sees another customer, RetailCo: 1 account with `credential_validation_status=expired` — scan blocked for 3 days. She clicks into RetailCo.

**Climax:** Priya sees the org admin's email. She clicks "Send Reminder" which fires a manual SES notification. She can also see their trial is expiring in 2 days and clicks "Extend Trial by 7 days" which calls the billing engine's trial extension endpoint.

**Resolution:** RetailCo org admin gets the reminder and rotates credentials within the hour. Priya's dashboard shows all customers green again.

### Journey Requirements Summary

| Journey | Capabilities Required |
|---|---|
| J1 Platform Admin Provisioning | Org creation endpoint, billing initialization, user invite, role/group assignment |
| J2 Cloud Account Onboarding | Account creation wizard, credential storage in SM, real CSP validation, scan trigger |
| J3 VUL Agent Install | Agent token generation, install command UI, agent status polling, VUL engine registration |
| J4 Credential Expiry | DB-queryable expires_at, Celery beat K8s deployment, SES notification, credential rotation UI |
| J5 Platform Admin Visibility | Org overview with scan/credential status, trial management, manual SES trigger |

---

## Domain-Specific Requirements

### Security & Credential Handling

Cloud credentials are among the most sensitive data the platform handles. A leaked AWS access key can result in full account compromise. Requirements driven by this risk:

- **No plaintext credentials in DB.** `cloud_accounts.credential_ref` stores only the AWS SM path. The actual key material never enters PostgreSQL.
- **Credential isolation per account.** SM path convention: `threat-engine/account/{account_id}`. One secret per account, no shared secrets.
- **Authentication on all credential endpoints.** Every endpoint that reads, writes, or deletes a credential must require a valid `X-Auth-Context` session with appropriate permission. The current legacy `/api/v1/accounts` router has zero auth on store/validate/delete and must be removed.
- **Tenant isolation.** Every cloud_accounts DB query must be scoped by both `tenant_id` and `customer_id`. Cross-tenant credential reads are a P0 security incident.
- **Webhook auth.** The `POST /engine-status` callback endpoint must require a shared secret or signed payload — currently it accepts unauthenticated calls from any party with a known `scan_run_id`.

### Compliance & Regulatory

- Credential data retention: credentials deleted from SM when account is deleted (7-day recovery window maintained per SM default).
- Audit trail: all credential create/rotate/delete operations must generate an audit log entry in Django's audit log system.
- RBAC: Platform Admin (`l1`) → Org Admin (`l2`) → Tenant Admin (`l4`) → Analyst → Viewer. Credential write operations require `cloud_accounts:write`. Viewer role has no credential access.

### Identifier Alignment

- Billing engine uses `org_id` (VARCHAR). Django uses `customer_id`. These must carry the same value. When platform admin creates an org, `customer_id = str(user.id)` (Django convention) must be passed as `org_id` to the billing trial provision call.
- All engines (onboarding, billing, platform-admin) must use the same string as the org identifier. No silent divergence.

### Agent Auth Alignment (VUL Engine)

- The onboarding engine issues a PKCE-derived 30-day JWT as the agent token. The VUL engine currently uses a static `API_KEYS` env var list and ignores JWTs.
- **Resolution path:** The generated agent token (from `POST /cloud-accounts/{id}/agent-token`) must be added to the VUL engine's `API_KEYS` list at install time, OR the VUL engine must be updated to verify the onboarding-issued JWT. The simpler path (static key injection) is preferred for MVP. The token is written into SM and injected into the VUL engine's environment as part of the agent install command.

---

## SaaS B2B Specific Requirements

### Tenant Model

```
Platform Admin (Onam Security operator)
  └── Customer / Org  [customer_id = org_id in billing]
       ├── Org Users  (provisioned by platform admin; org-level or org-group access)
       │    └── can invite additional users after initial provisioning
       └── Tenant(s)  [tenant_type: cloud | security | database]
            └── Cloud Account(s)  [account_type: cloud_csp | vulnerability | secops | database]
                 └── Credentials  [stored in AWS SM at threat-engine/account/{account_id}]
```

### RBAC Matrix for Onboarding Operations

| Operation | platform_admin | org_admin | tenant_admin | analyst | viewer |
|---|---|---|---|---|---|
| Create customer org | ✓ | ✗ | ✗ | ✗ | ✗ |
| Invite org users | ✓ | ✓ | ✗ | ✗ | ✗ |
| Create tenant | ✓ | ✓ | ✗ | ✗ | ✗ |
| Create cloud account | ✓ | ✓ | ✓ | ✗ | ✗ |
| Store credentials | ✓ | ✓ | ✓ | ✗ | ✗ |
| View credential status | ✓ | ✓ | ✓ | ✓ | ✗ |
| Trigger scan | ✓ | ✓ | ✓ | ✗ | ✗ |
| View scan status | ✓ | ✓ | ✓ | ✓ | ✓ |
| Suspend org | ✓ | ✗ | ✗ | ✗ | ✗ |
| Extend trial | ✓ | ✗ | ✗ | ✗ | ✗ |

### Multi-Tenancy Rules

- Every onboarding engine DB query scoped by `tenant_id` from `AuthContext`.
- Org boundary enforced by `customer_id`: org_admin can only read/write accounts within their `customer_id`.
- Platform admin bypasses org boundary (reads across all `customer_id`s) — requires `platform:admin` permission.
- Group-scoped access: `tenant_group_access` and `account_group_access` tables already exist; group checks applied after `customer_id` boundary check.

### SSO & Auth

- Self-service signup: disabled by default (`ALLOW_LOCAL_SIGNUP=false`). Customer users are always invite-provisioned.
- Google OAuth: ✓ wired. Microsoft OIDC: ✓ wired. Per-tenant SAML 2.0: ✓ wired.
- IDP group sync (SCIM): deferred — not in scope for this release. Users are manually invited or provisioned by platform admin.

### Scheduling

- **Default schedule:** daily 2 AM UTC, auto-applied to all new accounts.
- **Adhoc:** `POST /cloud-accounts/{id}/scan` — manual trigger, no schedule required.
- No custom schedule options for this release. The preset cron options (hourly/daily/weekly) exist in the DB but are not surfaced to end users in this release.

---

## Project Scoping

### Approach

Single release — all requirements listed in this document are in scope. No phasing. The sprint plan (SPRINT-PLAN-AUTH-ONBOARDING.md) already defines 4 implementation sprints (A→B→C→D) within this single release.

### Must-Have Capabilities (All In Scope)

1. Platform admin org creation endpoint (`POST /padmin/orgs`)
2. Billing trial auto-initialization on org creation
3. Platform admin user provisioning and group access assignment
4. Org admin invite flow (email + SSO accept)
5. Tenant creation with tenant_type selection
6. Cloud account creation wizard (all 6 account types)
7. Credential storage in AWS SM for all CSP types
8. Real CSP API validation on credential entry (per-provider validators)
9. Credential expiry DB columns (`expires_at`, `last_rotated_at`) on `cloud_accounts`
10. Credential expiry notification (day 76 alert via SES, day 90 INACTIVE flip)
11. Celery beat task deployed as K8s pod (not just code)
12. VUL agent PKCE token generation + install command UI
13. VUL agent phone-home status polling in UI
14. VUL agent token injected into VUL engine `API_KEYS` at install
15. Legacy zero-auth credential router (`/api/v1/accounts`) removed
16. `engine-status` webhook auth-gated
17. `scan_runs` → `scan_orchestration` table name fix across all onboarding files
18. `org_id` (billing) = `customer_id` (Django) alignment
19. Scan status / pipeline progress view for tenant admin + platform admin
20. Bulk scan-all endpoint surfaced in UI

### Technical Debt in Scope (Must Fix)

| Debt Item | File | Fix |
|---|---|---|
| `scan_runs` table name | `scan_run_operations.py`, `scans.py`, `ui_data_router.py` | Replace with `scan_orchestration` |
| Legacy auth-free router | `api/credentials.py` | Remove entirely |
| Missing auth on 3 endpoints | `cloud_accounts.py` validate-credentials, log-sources | Add `Depends(require_permission(...))` |
| `engine-status` no auth | `scan_runs.py` line 176 | Require shared secret |
| `exclude_regions` not forwarded to Argo | `scheduler_service.py`, `schedules.py` run-now | Pass to `ArgoClient.submit_pipeline()` |
| Celery worker not deployed | — | Add K8s CronJob/Beat manifest |
| `engine-cdr` stale ref in platform-admin | `engines.py` health URL map | Update to `engine-cdr` |

### Risk Mitigation

- **Table name fix risk:** Run as a migration/hotfix first (Sprint A) before any other code changes ship. Validate with a known scan_run_id.
- **VUL agent auth gap:** Token injection via install command (static `API_KEYS` addition) is the safe path. Full JWT verification in VUL engine is a post-release enhancement.
- **Billing trial init:** If `POST /billing/trial/provision` fails during org creation, org creation must roll back (transactional). Do not leave orphan orgs without billing records.
- **org_id alignment:** Map `customer_id` → `org_id` in the Django org-creation call. All billing queries must use this value. Validate with a query after first org creation.

---

## Functional Requirements

### Customer Org Management

- **FR1:** Platform Admin can create a new customer org by providing org name and contact email, resulting in a provisioned org with `customer_id`, active status, and an initialized billing trial record.
- **FR2:** Platform Admin can view all customer orgs with their subscription tier, trial days remaining, account count, and last scan timestamp.
- **FR3:** Platform Admin can suspend and unsuspend a customer org, which blocks all scans for that org while suspended.
- **FR4:** Platform Admin can extend a customer org's trial period.
- **FR5:** Platform Admin can view credential expiry status across all accounts in all customer orgs.
- **FR6:** System automatically initializes a 14-day Pro billing trial record when a new customer org is created.

### User & Access Management

- **FR7:** Platform Admin can provision one or more initial users for a customer org, specifying their email and access scope (org-level or org-group-level).
- **FR8:** Org Admin can invite additional users to their org via email; invited users receive an SES email with an accept link.
- **FR9:** Invited users can accept an invite by setting a password or authenticating via Google OAuth, Microsoft OIDC, or per-tenant SAML SSO.
- **FR10:** Org Admin can create named user groups and assign groups to specific tenants or cloud accounts with a role.
- **FR11:** Org Admin can assign org-level RBAC roles (`org_admin`, `tenant_admin`, `analyst`, `viewer`) to users.
- **FR12:** Users can authenticate via Google OAuth, Microsoft OIDC, or per-tenant SAML 2.0 SSO without a local password.

### Tenant & Account Structure

- **FR13:** Org Admin can create multiple tenants under their org, assigning a `tenant_type` (`cloud`, `security`, or `database`) that constrains which account types may be added.
- **FR14:** Tenant Admin can add cloud accounts under their assigned tenant; account type selection is constrained by the tenant's `tenant_type`.
- **FR15:** System validates that the selected `account_type` is permitted for the parent tenant's `tenant_type` before creating the account.

### Credential Management

- **FR16:** Tenant Admin can register credentials for a cloud account by entering type-appropriate fields (e.g., access key + secret for AWS, service principal for Azure, service account JSON for GCP).
- **FR17:** All credentials are stored exclusively in AWS Secrets Manager at path `threat-engine/account/{account_id}` — no credential material is stored in the PostgreSQL DB.
- **FR18:** Tenant Admin can optionally enable 30-day credential rotation via AWS SM's managed rotation feature for any cloud account.
- **FR19:** Tenant Admin can trigger a manual re-validation of credentials for any existing account, which calls the CSP-specific validation API and updates the validation status.
- **FR20:** System validates credentials against real CSP APIs on initial entry: `sts:GetCallerIdentity` (AWS), ARM token exchange (Azure), `projects.get` (GCP), IAM API (OCI), STS (AliCloud).
- **FR21:** Validation result (`valid`, `invalid`, `pending`, `expired`) and timestamp are stored on the `cloud_accounts` record and displayed in the account list.
- **FR22:** Tenant Admin can view per-account credential status (validation state, validated_at, expires_at, days until expiry).
- **FR23:** Credential expiry is tracked at 90 days per account via `expires_at` column on `cloud_accounts` (DB-queryable, not only in SM payload).
- **FR24:** On credential entry or rotation, `last_rotated_at` is updated on the `cloud_accounts` record.

### Agent-Based Onboarding (Vulnerability Engine)

- **FR25:** Tenant Admin can generate an agent install token for a `vulnerability`-type account.
- **FR26:** UI displays a ready-to-run shell install command containing the tenant ID, generated token, and VUL engine endpoint.
- **FR27:** The generated agent token is provisioned into the VUL engine's accepted token list so the agent's `POST /api/v1/agents/register` call is authenticated upon install.
- **FR28:** UI polls agent connection status (Pending → Connected) and displays a live status indicator without page reload.
- **FR29:** Account `credential_validation_status` flips to `valid` automatically once the VUL agent successfully phones home.

### Credential Expiry & Notifications

- **FR30:** System sends an email notification to org admins and the platform admin 14 days before credential expiry (day 76) for all active accounts with tracked `expires_at`.
- **FR31:** On credential expiry (day 90), account `account_status` flips to `INACTIVE` and all scans for that account are blocked until credentials are re-provisioned.
- **FR32:** Tenant Admin can re-provision credentials for an INACTIVE account, which resets the expiry clock and re-activates the account.
- **FR33:** Credential expiry notification is delivered via SES using the org contact email and platform admin email.

### Scan Scheduling & Triggering

- **FR34:** Tenant Admin can trigger an ad-hoc scan for any active cloud account without requiring a schedule to exist.
- **FR35:** All new accounts are automatically enrolled in a default daily scan schedule (2 AM UTC) upon creation.
- **FR36:** Tenant Admin can disable the default schedule for any account, leaving it in adhoc-only mode.
- **FR37:** Org Admin can trigger a bulk re-scan across all accounts in a tenant.
- **FR38:** Region exclusions configured on a schedule are forwarded to the Argo pipeline at scan submission time.

### Pipeline Observability

- **FR39:** Tenant Admin and Org Admin can view real-time scan pipeline status for any scan, showing per-engine progress (Discovery → Inventory → Check → Threat → …).
- **FR40:** Platform Admin can view scan pipeline status across all tenants and customer orgs from a unified view.
- **FR41:** Scan engine status callbacks are authenticated — only the Argo pipeline controller can update engine completion status for a scan run.
- **FR42:** Tenant Admin can view scan run history (all past scans, timestamps, status, engines completed) for their accounts.
- **FR43:** Org Admin or Tenant Admin can re-trigger a failed scan run without re-entering credentials.

---

## Non-Functional Requirements

### Security

- **NFR-S1:** All credential read, write, delete, and validate endpoints require an authenticated session with `cloud_accounts:write` or `cloud_accounts:read` permission. Zero unauthenticated credential endpoints permitted.
- **NFR-S2:** RBAC enforced at three layers: API Gateway (`X-Auth-Context`), Engine (`Depends(require_permission(...))`), and DB (queries scoped by `tenant_id` + `customer_id`).
- **NFR-S3:** The legacy `/api/v1/accounts` credential router (currently zero-auth) must be removed from the onboarding engine before this release ships. No phased deprecation — hard removal.
- **NFR-S4:** Engine-status callback (`POST /scan-runs/{id}/engine-status`) must verify a shared secret header (`X-Pipeline-Secret`) before updating scan state. Unauthenticated calls return 401.
- **NFR-S5:** All credential material stored in AWS SM must use the platform's KMS key (`SECRETS_MANAGER_KMS_KEY_ID`). No SM secrets with default AWS-managed keys for customer credentials.
- **NFR-S6:** Cross-tenant reads of cloud accounts or credentials are a P0 security violation. Every DB query in the onboarding engine must include both `tenant_id` and `customer_id` predicates.

### Performance

- **NFR-P1:** CSP credential validation (API call + status write) completes within 30 seconds. Validation is async-safe — the UI shows a spinner and polls rather than blocking the HTTP response.
- **NFR-P2:** Agent status polling UI updates within 5 seconds of the agent's first heartbeat being recorded.
- **NFR-P3:** Platform Admin org list renders within 2 seconds for up to 500 customer orgs (paginated, 50 per page).

### Reliability

- **NFR-R1:** The credential expiry Celery beat task must be deployed as a running K8s Deployment or CronJob — not latent code. Absence of this pod is a deployment failure.
- **NFR-R2:** Billing trial initialization (`POST /billing/trial/provision`) must be called transactionally with org creation. If the billing call fails, org creation must roll back. No orphaned orgs.
- **NFR-R3:** The `scan_orchestration` table name must be used consistently across all onboarding engine files. Any reference to `scan_runs` in SQL queries is a bug and a blocker.

### Data Integrity

- **NFR-D1:** `cloud_accounts.expires_at` (TIMESTAMPTZ) and `cloud_accounts.last_rotated_at` (TIMESTAMPTZ) columns must exist before any credential lifecycle features are shipped. Migration is a Sprint A prerequisite.
- **NFR-D2:** `org_id` in `org_subscriptions` (billing DB) must carry the same string value as `customer_id` in `user_auth_users` (Django DB) and `cloud_accounts` (onboarding DB). All org creation code must set this consistently.
- **NFR-D3:** Credential paths in SM must follow the convention `threat-engine/account/{account_id}`. The onboarding engine regex validates this at write time — no exceptions.

### Integration

- **NFR-I1:** VUL agent install command must include a token that the VUL engine will accept. The generated agent token must be provisioned into the VUL engine's `API_KEYS` list (either via SM injection or direct env update) before the install command is displayed to the user.
- **NFR-I2:** `exclude_regions` configured on a scan schedule must be forwarded in the `ArgoClient.submit_pipeline()` call. Dropping it silently at submission (current behavior) is a bug.
- **NFR-I3:** SES emails (invite, credential expiry, manual reminder) must be sent from a verified SES identity. The `FROM_EMAIL` must be SES-verified in `ap-south-1` before this feature ships.

---

## Open Questions & Decisions Locked

The following were explicitly decided in the product session on 2026-05-11:

| Question | Decision |
|---|---|
| Self-service registration? | No — platform admin only creates customer orgs |
| IdP group sync (SCIM)? | Deferred — not in this release |
| Custom scan schedules? | No — Default (daily) + Adhoc only |
| Multiple credential vaults (HashiCorp, Azure KV)? | No — AWS SM only in this release |
| Full JWT verification in VUL engine? | Deferred — static API_KEYS injection for MVP |
| Org creation rollback on billing failure? | Yes — transactional, org creation rolls back |

---

## Implementation Sprint Map

This PRD is implemented across 4 sequential sprints defined in `.claude/planning/SPRINT-PLAN-AUTH-ONBOARDING.md`:

| Sprint | Focus | Gate |
|---|---|---|
| **A** | DB migrations (`customer_id`, groups, `expires_at`, `last_rotated_at`), `provision_tenant_for_new_user()` update, async Celery sync | Migration applied, `customer_id` backfilled on all rows |
| **B** | Auth security fixes (email enumeration, rate limiting, Google hd validation, org-boundary enforcement, remove developer bypass) | All 7 BLOCKs resolved in Django backend |
| **C** | Onboarding engine: table name fix, auth middleware hardening, PKCE hardening, RBAC, region forwarding, Celery deployment | Engine deployed with zero unauthenticated endpoints |
| **D** | Frontend wizard (catalog-driven), schedule UI, agent install flow, user/group management pages | Full onboarding wizard live end-to-end |

**Story count:** 29 stories, 43 points, ~8 weeks estimated.
**Security gate:** 12 BLOCKs from bmad-security-architect review, all mapped to stories in Sprint B/C.
