# CSPM Platform — Scheduling & Scan Trigger User Flows

**Date:** 2026-05-03  
**Based on:** Live onboarding engine audit (see onboarding-engine-expert report)

---

## What Already Exists (Do Not Re-Build)

| Feature | Status | Location |
|---------|--------|----------|
| `schedules` table (cron, scope, engines_requested) | ✅ Complete | `onboarding DB` |
| Cron presets + custom expression | ✅ Complete | `api/schedules.py` |
| enable/disable schedule toggle | ✅ Complete | `PATCH /schedules/{id}/enable` |
| `run-now` endpoint (via schedule) | ✅ Complete | `POST /schedules/{id}/run-now` |
| Argo pipeline trigger (asyncio 60s poll) | ✅ Complete | `scheduler_service.py` |
| Scope: include_regions, include_services, exclude_services | ✅ Complete | `Schedule` model |
| Multiple schedules per account | ✅ Supported | `schedules.account_id` FK |
| Per-engine status (`engine_statuses` JSONB) | ✅ Complete | `scan_runs` table |
| Credential validation (all 7 CSPs, real API calls) | ✅ Complete | `validators/` |
| Secrets Manager storage after validation | ✅ Complete | `secrets_manager_storage.py` |
| Re-validate credentials endpoint | ✅ Complete | `POST /cloud-accounts/{id}/validate-credentials` |
| `account_type` discriminator on cloud_accounts | 🔶 Code done, migration not applied | `20260503_*.sql` |
| `agent_registrations` table + bootstrap endpoint | 🔶 Code done, migration not applied | `20260503_*.sql` |
| RBAC (`require_permission()`) on schedule endpoints | ❌ Missing | `api/schedules.py` |
| `exclude_regions` on Schedule model | ❌ Missing | ORM model gap |
| Run Now directly on account (no pre-existing schedule needed) | ❌ Missing | must have schedule first |
| Scan profiles (named presets) | ❌ Missing | design gap |
| SecOps / Vuln / Agent account scheduling UI path | ❌ Missing | only cloud_csp today |

---

## Flow 1 — Add Account + Validate Credentials + Attach Schedule + First Scan

This is the END-TO-END flow every account goes through after being created in the onboarding wizard.

```
┌───────────────────────────────────────────────────────────────────────────┐
│  PHASE 1: CREATE ACCOUNT                                                   │
│                                                                            │
│  POST /api/v1/cloud-accounts/                                              │
│    {tenant_id, account_name, account_type, provider, label}               │
│  → Creates cloud_accounts row                                              │
│    account_onboarding_status = 'pending'                                  │
│    credential_validation_status = 'pending'                               │
└───────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  PHASE 2: SUBMIT CREDENTIALS                                               │
│                                                                            │
│  POST /api/v1/cloud-accounts/{account_id}/credentials                     │
│  Payload varies by account_type + provider:                                │
│                                                                            │
│  ┌──────────────────┬────────────────────────────────────────────────┐    │
│  │ Provider         │ Credential Fields                              │    │
│  ├──────────────────┼────────────────────────────────────────────────┤    │
│  │ AWS (access_key) │ access_key_id, secret_access_key               │    │
│  │ AWS (iam_role)   │ role_arn, external_id (optional)               │    │
│  │ Azure            │ client_id, tenant_id, client_secret,           │    │
│  │                  │ subscription_id                                │    │
│  │ GCP              │ service_account_json (upload)                  │    │
│  │ OCI              │ config_file + key.pem (upload)                 │    │
│  │ AliCloud         │ access_key_id, access_key_secret               │    │
│  │ IBM              │ api_key, account_id                            │    │
│  │ K8s (kubeconfig) │ kubeconfig (upload)                            │    │
│  │ K8s (in_cluster) │ (no creds — uses pod service account)          │    │
│  └──────────────────┴────────────────────────────────────────────────┘    │
│                                                                            │
│  Backend validation sequence:                                              │
│    1. Call CSP API to verify creds are valid (see Phase 3 below)          │
│    2. PASS → store creds in Secrets Manager                               │
│             (path: threat-engine/account/{account_id})                    │
│             set credential_validation_status = 'valid'                    │
│             set account_onboarding_status   = 'deployed'                  │
│             auto-detect + set account_id (e.g. AWS account number)        │
│    3. FAIL → return {success: false, error: "..."} (HTTP 200)             │
│             set credential_validation_status = 'invalid'                  │
│             creds NOT stored                                               │
└───────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼ (on success)
┌───────────────────────────────────────────────────────────────────────────┐
│  PHASE 3: CREDENTIAL VALIDATION DETAILS (per CSP)                          │
│                                                                            │
│  AWS (access_key):                                                         │
│    ① sts.get_caller_identity()          → confirms key is active          │
│    ② ec2.describe_regions()             → confirms EC2 read access        │
│    ③ Extract account_id from STS response → stored on cloud_accounts      │
│    Minimum required: SecurityAudit policy (AWS-managed, read-only)        │
│                                                                            │
│  AWS (iam_role / assume-role):                                             │
│    ① sts.assume_role(RoleArn, ExternalId) → get temp credentials         │
│    ② sts.get_caller_identity() on temp creds → confirm role assumed      │
│    ③ Verify assumed role account matches expected account                 │
│                                                                            │
│  Azure (service principal):                                                │
│    ① ClientSecretCredential(tenant_id, client_id, secret)                 │
│    ② SubscriptionClient.subscriptions.get(subscription_id)               │
│    ③ Extract subscription display name + state                            │
│    Minimum required: Reader role on subscription                          │
│                                                                            │
│  GCP (service account JSON):                                               │
│    ① Parse JSON → validate required fields (type, project_id, etc.)      │
│    ② resourcemanager.ProjectsClient.get_project(project_id)              │
│    ③ Extract project number + name                                        │
│    Minimum required: roles/viewer or SecurityReviewer on project          │
│                                                                            │
│  OCI:                                                                      │
│    ① oci.config.validate_config(config)  → check required keys           │
│    ② identity.IdentityClient.get_user(user_ocid) → confirms user exists  │
│    ③ Extract tenancy_ocid → stored as account_id                          │
│                                                                            │
│  K8s (kubeconfig):                                                         │
│    ① Write kubeconfig to temp file                                        │
│    ② CoreV1Api.list_namespace(limit=1)   → confirms cluster connectivity │
│    ③ Extract cluster server URL → stored as account_id                    │
│                                                                            │
│  POST-VALIDATION result display:                                           │
│  ┌──────────────────────────────────────┬───────────────────────────┐     │
│  │ Validation Result                    │ UI Action                 │     │
│  ├──────────────────────────────────────┼───────────────────────────┤     │
│  │ All required permissions: PASS       │ Green check, proceed      │     │
│  │ Auth valid, some perms missing: WARN │ Yellow warning, list gaps │     │
│  │                                      │ "Some checks may fail"    │     │
│  │ Auth failed: FAIL                    │ Red error, show message   │     │
│  │                                      │ Retry credentials button  │     │
│  └──────────────────────────────────────┴───────────────────────────┘     │
└───────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼ (credential_validation_status = valid)
┌───────────────────────────────────────────────────────────────────────────┐
│  PHASE 4: ATTACH SCHEDULE                                                  │
│                                                                            │
│  POST /api/v1/schedules/                                                   │
│  {                                                                         │
│    "account_id": "...",                                                    │
│    "tenant_id": "...",                                                     │
│    "schedule_name": "Weekly Full Scan",           ← optional label         │
│    "cron_expression": "0 2 * * 0",                ← Sunday 2AM UTC        │
│    "timezone": "UTC",                                                      │
│    "enabled": true,                                                        │
│                                                                            │
│    // SCOPE — what to scan                                                 │
│    "include_regions": ["us-east-1", "eu-west-1"], ← null = all regions   │
│    "include_services": ["ec2", "s3", "rds"],       ← null = all services  │
│    "exclude_services": ["glacier"],                ← fine exclusions      │
│                                                                            │
│    // ENGINES — which CSPM engines to run                                  │
│    "engines_requested": [                                                  │
│        "discovery", "inventory", "check",                                 │
│        "threat", "compliance", "iam", "datasec"                           │
│    ],                                                                      │
│                                                                            │
│    // NOTIFICATIONS                                                        │
│    "notify_on_failure": true,                                              │
│    "notify_on_success": false,                                             │
│    "notification_emails": ["admin@acme.com"]                               │
│  }                                                                         │
│                                                                            │
│  Backend:                                                                  │
│    require_permission("scans:create")    ← MISSING TODAY — must add      │
│    Verify account belongs to user's tenant                                │
│    Compute next_run_at from cron + timezone (croniter)                    │
│    Insert schedules row                                                    │
│    Return {schedule_id, next_run_at, "next 3 runs": [...]}                │
└───────────────────────────────────────────────────────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────────────────────────────────┐
│  PHASE 5: FIRST SCAN                                                       │
│                                                                            │
│  Option A — "Scan Now" button (uses schedule scope)                        │
│    POST /api/v1/schedules/{schedule_id}/run-now                           │
│    trigger_type = "manual"                                                 │
│    Returns {scan_run_id} → redirect /scans/{id}/progress                  │
│                                                                            │
│  Option B — Wait for scheduled auto-fire                                   │
│    Scheduler polls every 60s; fires when next_run_at <= NOW()             │
│    trigger_type = "scheduled"                                              │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 2 — Scan Scope Selection (What to Scan)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  SCOPE SELECTOR (schedule create / edit modal)                             │
│                                                                            │
│  ┌─────────────────┬──────────────────────────────────────────────────┐   │
│  │ Scope Option    │ DB values stored                                 │   │
│  ├─────────────────┼──────────────────────────────────────────────────┤   │
│  │ Full Account    │ include_regions=null, include_services=null      │   │
│  │                 │ Scans everything, all regions, all services      │   │
│  │                 │                                                  │   │
│  │ Selected Regions│ include_regions=["us-east-1","eu-west-1"]        │   │
│  │                 │ include_services=null (all services in region)   │   │
│  │                 │                                                  │   │
│  │ Selected        │ include_regions=null (all regions)               │   │
│  │ Services Only   │ include_services=["ec2","s3","rds","iam"]        │   │
│  │                 │                                                  │   │
│  │ Custom          │ include_regions + include_services both set      │   │
│  │                 │ + exclude_services for exceptions                │   │
│  └─────────────────┴──────────────────────────────────────────────────┘   │
│                                                                            │
│  ENGINE PRESET SELECTOR:                                                   │
│  ┌─────────────────┬──────────────────────────────────────────────────┐   │
│  │ Preset          │ engines_requested                                │   │
│  ├─────────────────┼──────────────────────────────────────────────────┤   │
│  │ Full Scan       │ discovery, inventory, check, threat,             │   │
│  │                 │ compliance, iam, datasec, network, risk          │   │
│  │                 │                                                  │   │
│  │ Compliance Only │ discovery, inventory, check, compliance          │   │
│  │                 │                                                  │   │
│  │ Security Focus  │ discovery, inventory, check, threat, iam, risk   │   │
│  │                 │                                                  │   │
│  │ Custom          │ user picks individual checkboxes                 │   │
│  └─────────────────┴──────────────────────────────────────────────────┘   │
│                                                                            │
│  UI shows estimated duration based on historical run_count data            │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 3 — Schedule Management (Full CRUD)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  Multiple schedules per account are supported (e.g. daily compliance +    │
│  weekly full scan + monthly IAM deep-dive)                                │
│                                                                            │
│  LIST:    GET    /api/v1/schedules/?account_id={id}                        │
│  CREATE:  POST   /api/v1/schedules/                                        │
│  VIEW:    GET    /api/v1/schedules/{schedule_id}                           │
│  EDIT:    PATCH  /api/v1/schedules/{schedule_id}                           │
│  DELETE:  DELETE /api/v1/schedules/{schedule_id}                           │
│  ENABLE:  POST   /api/v1/schedules/{schedule_id}/enable                    │
│  DISABLE: POST   /api/v1/schedules/{schedule_id}/disable                   │
│  RUN NOW: POST   /api/v1/schedules/{schedule_id}/run-now                   │
│                                                                            │
│  Multi-schedule example for one Production AWS account:                    │
│    Schedule A: Daily 02:00 UTC — compliance-only                          │
│                engines: [discovery, check, compliance]                    │
│    Schedule B: Weekly Sunday 01:00 UTC — full security scan               │
│                engines: [all 9]                                           │
│    Schedule C: Monthly 1st 00:00 UTC — IAM deep-dive                     │
│                engines: [discovery, iam]                                  │
│                include_services: [iam, cognito, sts]                      │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 4 — Run Now (Three Paths)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  PATH A: Via existing schedule (current — works today)                     │
│                                                                            │
│  Account card → pick schedule → "Run Now"                                 │
│    POST /api/v1/schedules/{schedule_id}/run-now                           │
│    trigger_type = "manual"                                                 │
│    Inherits: include_regions, include_services, engines_requested          │
│              from schedule row                                             │
│    Returns: {scan_run_id}                                                  │
│    → Redirect /scans/{scan_run_id}/progress                               │
│                                                                            │
├───────────────────────────────────────────────────────────────────────────┤
│  PATH B: Ad-hoc scan — NO schedule required (GAP — needs build)            │
│                                                                            │
│  Account card → "Quick Scan" → inline scope modal                         │
│    POST /api/v1/cloud-accounts/{account_id}/scan                          │
│    {                                                                       │
│      "include_regions": [...] or null,                                     │
│      "include_services": [...] or null,                                    │
│      "engines_requested": [...],                                           │
│      "scan_name": "Ad-hoc — 2026-05-03"  ← auto-generated label          │
│    }                                                                       │
│    Backend:                                                                │
│      Verify account has valid credentials                                  │
│      Create scan_run (schedule_uuid=null, trigger_type="manual")          │
│      Trigger Argo pipeline directly                                       │
│      Return {scan_run_id}                                                  │
│                                                                            │
├───────────────────────────────────────────────────────────────────────────┤
│  PATH C: Bulk Run Now — scan ALL accounts in a tenant immediately         │
│          (GAP — needs build)                                               │
│                                                                            │
│  /tenants/{id} → "Run All Now" → confirm modal:                           │
│    "This will trigger scans on N accounts. Confirm?"                      │
│    "Dry run" option shows count + next scan details without triggering    │
│                                                                            │
│    POST /api/v1/tenants/{tenant_id}/scan-all                              │
│    {dry_run: false, scope_override: {...}}                                 │
│    Backend:                                                                │
│      Fetch all enabled schedules for tenant                               │
│      Trigger up to MAX_CONCURRENT_SCANS=10 immediately                    │
│      Queue remainder with 30s stagger                                     │
│      Return {triggered: N, queued: M, scan_run_ids: [...]}                │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 5 — Scheduler Auto-Fire (Background Process)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  onboarding engine pod — asyncio background task (starts at FastAPI       │
│  startup event, runs in-process with API server)                           │
│                                                                            │
│  Every SCHEDULER_INTERVAL_SECONDS (default: 60s):                         │
│                                                                            │
│  ① Poll:                                                                   │
│       SELECT s.*, ca.provider, ca.credential_type, ca.credential_ref      │
│       FROM schedules s JOIN cloud_accounts ca USING (account_id)          │
│       WHERE s.enabled = true AND s.next_run_at <= NOW()                   │
│                                                                            │
│  ② For each due schedule (up to MAX_CONCURRENT_SCANS=10):                 │
│       a. INSERT scan_runs (status=pending, trigger_type='scheduled')      │
│       b. POST to Argo Server:                                              │
│            http://argo-server.argo.svc.cluster.local:2746/               │
│              api/v1/workflows/{ns}/submit                                 │
│          params: scan-run-id, tenant-id, account-id,                      │
│                  provider, credential-type, credential-ref,               │
│                  include-services, include-regions                         │
│       c. UPDATE scan_runs SET status='running'                            │
│       d. UPDATE cloud_accounts SET last_scan_at=NOW()                     │
│       e. Recalculate schedules.next_run_at via croniter                   │
│       f. INCREMENT schedules.run_count                                    │
│                                                                            │
│  ③ Concurrency guard:                                                      │
│       Running scans >= MAX_CONCURRENT_SCANS → skip tick                  │
│       Due schedule stays at next_run_at <= NOW(), fires next tick         │
│                                                                            │
│  ④ Startup stale-scan cleanup:                                             │
│       UPDATE scan_runs SET status='failed', error_details={...}           │
│       WHERE status='running' AND started_at < NOW() - 4 hours            │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 6 — Cron Presets (UI Quick-Pick)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  ┌───────────────────────────┬──────────────────┬───────────────────────┐ │
│  │ Label                     │ Cron Expression  │ Example Next Run      │ │
│  ├───────────────────────────┼──────────────────┼───────────────────────┤ │
│  │ Every 6 hours             │ 0 */6 * * *      │ Today 18:00 UTC       │ │
│  │ Every 12 hours            │ 0 */12 * * *     │ Today 20:00 UTC       │ │
│  │ Daily at 2 AM             │ 0 2 * * *        │ Tomorrow 02:00 UTC    │ │
│  │ Weekly (Sunday 2 AM)      │ 0 2 * * 0        │ Sun 02:00 UTC         │ │
│  │ Monthly (1st day 2 AM)    │ 0 2 1 * *        │ Jun 1 02:00 UTC       │ │
│  │ Custom                    │ [free input]     │ Calculated live       │ │
│  └───────────────────────────┴──────────────────┴───────────────────────┘ │
│                                                                            │
│  Timezone selector: UTC default + user local timezone option              │
│  "Next 3 run times" preview updates live as user types cron expression   │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 7 — Credential Re-validation + Rotation

```
┌───────────────────────────────────────────────────────────────────────────┐
│  TRIGGER: user rotates IAM key / secret expires                            │
│                                                                            │
│  Account card shows badge:                                                 │
│    credential_validation_status = 'expired' | 'invalid'                  │
│    "Last validated: 45 days ago"                                          │
│    "Scheduled scans PAUSED — update credentials to resume"                │
│                                                                            │
│  Option A: Update + re-validate credentials                               │
│    POST /api/v1/cloud-accounts/{account_id}/credentials                   │
│    (full re-validate + re-store — same as initial submission)             │
│                                                                            │
│  Option B: Test existing stored credentials (no change)                   │
│    POST /api/v1/cloud-accounts/{account_id}/validate-credentials          │
│    Re-reads from Secrets Manager, re-runs API validation calls            │
│    Returns {valid, missing_permissions: [...]}                             │
│                                                                            │
│  PERIODIC HEALTH-CHECK (gap — needs build):                                │
│    Weekly Celery task per account                                         │
│    If STS/cloud API call fails → set credential_validation_status='expired'
│    → pause schedule (enabled=false)                                       │
│    → email notification_emails                                            │
│    → show badge in UI: "Credentials need attention"                       │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 8 — Scheduling by Account Type

### Cloud CSP (AWS / Azure / GCP / OCI / AliCloud / K8s)

```
Standard flow — Flows 1-7 above apply fully.
Scheduler controls everything via schedules table.
Scope: regions + services + engines.
```

### SecOps (Git Repositories / IaC)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  account_type = 'secops'                                                   │
│                                                                            │
│  Schedule Option A — Cron (same schedules table):                          │
│    engines_requested = ['secops']                                          │
│    include_services = ['iac', 'sast', 'sca']  ← scan type filters        │
│    Triggers secops engine via Argo pipeline                                │
│                                                                            │
│  Schedule Option B — Webhook on push (gap — needs build):                  │
│    GitHub/GitLab webhook → POST /api/v1/cloud-accounts/{id}/webhook       │
│    Payload: {branch, commit_sha, pusher}                                  │
│    → immediate scan of changed branches                                   │
│    → trigger_type = 'webhook'                                             │
│    Use case: PR-gate scanning (fail PR if new SAST issues found)         │
│                                                                            │
│  Credential: PAT / SSH key / GitHub App installation                      │
│  Validation: attempt to list refs on repo                                 │
└───────────────────────────────────────────────────────────────────────────┘
```

### Vulnerability / Database / Middleware (Agent-Based)

```
┌───────────────────────────────────────────────────────────────────────────┐
│  account_type = 'vulnerability' | 'database' | 'middleware'               │
│  AGENT controls the scan execution — not the Argo pipeline directly        │
│                                                                            │
│  Agent heartbeat loop:                                                     │
│    Every N minutes → POST /api/v1/agents/heartbeat                        │
│    Payload: {registration_id, agent_version, hostname, os, last_scan_at} │
│    Response: {run_now: bool, scan_config: {...}}                           │
│                                                                            │
│  Schedule Option A — Platform-configured (gap — needs build):              │
│    Admin creates schedule on account (same schedules table)               │
│    Onboarding engine sets run_now=true in heartbeat response              │
│    at next_run_at time                                                     │
│    Agent reads → starts scan → posts results back                         │
│                                                                            │
│  Schedule Option B — Agent-local (current default):                        │
│    Agent has its own cron config file                                     │
│    Platform passively receives results                                    │
│                                                                            │
│  Run Now for agents (gap — needs build):                                   │
│    POST /api/v1/cloud-accounts/{id}/signal-scan                           │
│    Sets agent_registrations.scan_requested = true                         │
│    Next heartbeat → agent reads flag → starts scan immediately            │
│                                                                            │
│  Credential validation: not applicable                                     │
│    Platform validates agent registration via PKCE bootstrap only          │
│    account_onboarding_status = 'deployed' once first heartbeat received   │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 9 — Scan Progress Monitoring

```
┌───────────────────────────────────────────────────────────────────────────┐
│  /scans/{scan_run_id}/progress                                             │
│                                                                            │
│  Data source: scan_runs.engine_statuses JSONB (updated by each engine     │
│  via POST /scan-runs/{id}/engine-status endpoint)                         │
│                                                                            │
│  {                                                                         │
│    "discovery":  {"status": "completed", "findings": 1204, "duration": 45}│
│    "inventory":  {"status": "running",   "findings": 0,    "duration": 12}│
│    "check":      {"status": "pending",   "findings": 0,    "duration": 0} │
│    "threat":     {"status": "pending",   ...}                             │
│    "compliance": {"status": "pending",   ...}                             │
│    "iam":        {"status": "pending",   ...}                             │
│    "datasec":    {"status": "pending",   ...}                             │
│  }                                                                         │
│                                                                            │
│  UI:                                                                       │
│    Progress bar per engine (pending=grey, running=blue, done=green)       │
│    Finding count per engine (updates live via polling or SSE)             │
│    Overall elapsed time                                                   │
│    On complete → "View Findings" → /dashboard                             │
│    On failure  → "Retry" + error message from error_details JSONB        │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Flow 10 — Scan History + Re-run

```
┌───────────────────────────────────────────────────────────────────────────┐
│  /tenants/{id}/accounts/{account_id}/scans                                 │
│  GET /api/v1/scan-runs/?account_id={id}&limit=20                          │
│                                                                            │
│  Table columns:                                                            │
│    Date | Trigger (scheduled/manual/api) | Scope | Status | Duration      │
│    Engines Run | Findings (new/changed/total) | Actions                   │
│                                                                            │
│  Row actions:                                                              │
│    "View Findings"  → /scans/{id}/findings (all findings for that run)    │
│    "Re-run"         → run-now with same scope as that scan_run            │
│    "Compare"        → diff view against previous scan run                 │
│    "Download"       → export scan results as CSV/JSON                     │
│                                                                            │
│  scan_runs.trigger_type values:                                           │
│    'scheduled' — auto-fired by SchedulerService cron                     │
│    'manual'    — triggered by Run Now button                              │
│    'api'       — CI/CD pipeline or external API call                      │
│    'webhook'   — (future) push event from SecOps Git webhook              │
└───────────────────────────────────────────────────────────────────────────┘
```

---

## Full State Machine — Account Lifecycle

```
           POST /cloud-accounts/
                    │
                    ▼
          ┌──────────────────┐
          │     CREATED      │
          │ onboarding=pending│
          │ cred_valid=pending│
          └──────────────────┘
                    │
         POST /credentials
                    │
          ┌─────────▼────────┐        ┌──────────────────┐
          │   VALIDATING     │─FAIL──►│  INVALID CREDS   │
          │  (CSP API calls) │        │ cred_valid=invalid│
          └─────────┬────────┘        └──────────┬───────┘
                  PASS                           │
                    │                 POST /credentials (retry)
          ┌─────────▼────────┐                   │
          │    DEPLOYED      │◄──────────────────┘
          │ cred_valid=valid  │
          │ creds in Secrets  │
          └─────────┬────────┘
                    │
         POST /schedules/ (optional)
                    │
          ┌─────────▼────────┐
          │    SCHEDULED     │
          │ has ≥1 schedule  │◄── PATCH /schedules/{id} (edit scope/cron)
          │ next_run_at set  │
          └─────────┬────────┘
               ┌────┤
               │    │
          RUN NOW  auto-fire (cron)
               │    │
          ┌────▼────▼────────┐
          │  SCAN RUNNING    │
          │ scan_run=running  │
          └─────────┬────────┘
               ┌────┤
               │    │
             FAIL  PASS
               │    │
  ┌────────────▼┐  ┌▼──────────────────┐
  │ SCAN FAILED │  │  SCAN COMPLETED   │
  │ retry?      │  │ findings written  │
  │             │  │ next_run computed │
  └─────────────┘  └───────────────────┘


  Credential expiry (periodic health-check — gap):
    DEPLOYED → credential_validation_status='expired'
               schedule paused (enabled=false)
               email alert sent
```

---

## State Machine — Agent Registration

```
  POST /tenants/{id}/agent-token  (PKCE: code_challenge sent, not code_verifier)
                    │
                    ▼
          ┌──────────────────┐
          │     PENDING      │ (15 min TTL)
          │ status=issued    │
          └──────────────────┘
            │             │
         TTL expires    agent calls POST /agents/bootstrap
            │           {registration_id, code_verifier}
            ▼                    │
       ┌─────────┐        check_password(code_verifier, stored_hash)
       │ EXPIRED │               │
       └─────────┘         FAIL─┘  → 401, no account created
                                │
                              PASS
                                ▼
                      ┌──────────────────┐
                      │     ACTIVE       │
                      │ cloud_account    │
                      │ auto-created     │
                      │ heartbeat begins │
                      └──────────────────┘
                                │
                     admin revoke / key rotation
                                ▼
                      ┌──────────────────┐
                      │    REVOKED       │
                      └──────────────────┘
```

---

## Gaps Summary — What Must Be Built

### Must-Have (Scheduling Sprint — P0/P1)

| # | Gap | Existing? | Priority |
|---|-----|-----------|----------|
| S-01 | RBAC `require_permission("scans:create")` on all schedule endpoints | ❌ Missing | P0 |
| S-02 | Ad-hoc scan `POST /cloud-accounts/{id}/scan` (no schedule needed) | ❌ Missing | P0 |
| S-03 | Apply `20260503_account_type_and_agent_registrations.sql` | ❌ Not applied | P0 |
| S-04 | `exclude_regions` on Schedule ORM + migration | ❌ Missing | P1 |
| S-05 | Bulk `POST /tenants/{id}/scan-all` with dry_run option | ❌ Missing | P1 |
| S-06 | Credential expiry health-check Celery task + pause schedule | ❌ Missing | P1 |
| S-07 | Agent scan-signal `POST /cloud-accounts/{id}/signal-scan` | ❌ Missing | P1 |
| S-08 | Permission gap reporting surfaced in UI (missing_permissions display) | 🔶 Backend has it, UI missing | P1 |

### Nice-to-Have (Future Sprint — P2)

| # | Gap |
|---|-----|
| S-09 | SecOps webhook trigger on Git push |
| S-10 | Estimated scan duration shown in schedule creation UI |
| S-11 | CI/CD API token for `trigger_type='api'` (non-session auth) |
| S-12 | Scan comparison / diff view between two scan_run_ids |
| S-13 | Scan scope presets saved per tenant ("our standard weekly" profile) |
| S-14 | Schedule pause window ("don't scan during deployment 22:00–23:00") |
| S-15 | Schedule clone (copy schedule from account A to account B) |

---

## Sprint Plan — Scheduling Work (Integrated into Auth & Onboarding Sprint)

```
Auth & Onboarding Sprint
├── Sprint A  (DB Foundation — cspm DB)
│     A1: Migrations 0011/0012/0013 (drop dead tables, add groups)
│     A2: provision_org_and_tenant() — signup + invite flows
│     A3: Async Celery tenant sync + dead-letter
│
├── Sprint B  (Auth Security Fixes — BLOCK-01 to BLOCK-12)
│     B1: Signup enumeration + rate limit + CAPTCHA
│     B2: Google OAuth hd validation
│     B3: TenantViewSet DRF auth + export + IDP rate limit
│     B4: org_admin boundary (customer_id) + remove developer bypass
│
├── Sprint C  (Onboarding Engine + Scheduling)
│     C1: Apply 20260503 migration (account_type + agent_registrations)  ← S-03
│     C2: RBAC on schedule endpoints                                     ← S-01
│     C3: Ad-hoc scan endpoint                                           ← S-02
│     C4: exclude_regions on Schedule model                              ← S-04
│     C5: Bulk scan-all endpoint                                         ← S-05
│     C6: Credential expiry health-check task                            ← S-06
│     C7: Agent scan-signal endpoint                                     ← S-07
│     C8: BLOCK-05 onboarding engine auth middleware
│     C9: BLOCK-06 CloudAccountUpdate Pydantic allow-list
│     C10: PKCE agent bootstrap endpoint
│
└── Sprint D  (Frontend — Wizard + Scheduling UI)
      D1: Tenant-type selector in onboarding wizard
      D2: Credential form branching (by account_type)
      D3: Schedule creation modal (cron presets + scope + engine picker)
      D4: Account card: next run, last run, Run Now, disable toggle
      D5: Ad-hoc scan modal (scope picker, no schedule required)
      D6: Bulk "Run All Now" button + dry-run confirm
      D7: Scan progress page (per-engine bars, live updates)
      D8: Scan history table (re-run + compare links)
      D9: Credential validation result + missing permissions display
      D10: Agent install flow UI (vuln/db/middleware)
      D11: User/group assignment UI (tenant + account level)
      D12: Org/tenant switcher component
```
