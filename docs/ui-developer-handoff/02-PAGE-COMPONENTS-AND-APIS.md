# CSPM Platform — Page Components & API Mapping

## API Base
```
NLB: http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
All routes go through: /gateway/...
```

---

## 1. DASHBOARD (Landing Page)

### Layout
```
┌─────────────────────────────────────────────────────────────┐
│  [Tenant Selector ▾]    [Account Selector ▾]    [Refresh]   │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Total    │ │ Critical │ │ High     │ │ Assets   │       │
│  │ Threats  │ │ Threats  │ │ Threats  │ │ Count    │       │
│  │  247     │ │   12     │ │   89     │ │  3,121   │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                             │
│  ┌────────────────────────┐ ┌──────────────────────────┐    │
│  │  Compliance Score      │ │  Threats by Region       │    │
│  │  [Donut Chart]         │ │  [World Map / Bar Chart] │    │
│  │  HIPAA: 78%            │ │                          │    │
│  │  PCI-DSS: 85%          │ │                          │    │
│  │  SOC2: 72%             │ │                          │    │
│  └────────────────────────┘ └──────────────────────────┘    │
│                                                             │
│  ┌────────────────────────┐ ┌──────────────────────────┐    │
│  │  Recent Scans          │ │  Top Threats (by Risk)   │    │
│  │  [Table: 5 rows]       │ │  [Table: 5 rows]        │    │
│  └────────────────────────┘ └──────────────────────────┘    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Threat Trend (last 30 days)  [Line Chart]           │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Components → APIs

| Component | API Endpoint | Method | Key Params |
|-----------|-------------|--------|------------|
| Tenant Selector | `GET /gateway/api/v1/onboarding/tenants` | GET | — |
| Account Selector | `GET /gateway/api/v1/onboarding/accounts` | GET | `tenant_id` |
| Total Threats KPI | `GET /gateway/api/v1/threat/analytics/distribution` | GET | `tenant_id`, `scan_run_id` |
| Assets Count KPI | `GET /gateway/api/v1/inventory/runs/latest/summary` | GET | `tenant_id` |
| Compliance Scores | `GET /gateway/api/v1/compliance/dashboard` | GET | `tenant_id` |
| Threats by Region | `GET /gateway/api/v1/threat/map/geographic` | GET | `tenant_id`, `scan_run_id` |
| Recent Scans | `GET /gateway/api/v1/threat/reports` | GET | `tenant_id`, `limit=5` |
| Top Threats | `GET /gateway/api/v1/threat/analysis/prioritized` | GET | `tenant_id`, `top_n=5` |
| Threat Trend | `GET /gateway/api/v1/threat/analytics/trend` | GET | `tenant_id`, `days=30` |

---

## 2. ONBOARDING

### 2a. Tenants Page
**Route**: `/onboarding/tenants`

```
┌─────────────────────────────────────────────────────────────┐
│  Tenants                                    [+ New Tenant]  │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Name        │ ID          │ Accounts │ Created       │   │
│  │─────────────┼─────────────┼──────────┼───────────────│   │
│  │ Acme Corp   │ tnt_acme    │ 3        │ 2026-01-15    │   │
│  │ Test Tenant │ tnt_local.. │ 1        │ 2026-02-01    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Request | Response |
|-----------|-----|--------|---------|----------|
| Tenant List | `/gateway/api/v1/onboarding/tenants` | GET | — | `{tenants: [{tenant_id, tenant_name, description, created_at}]}` |
| Create Tenant (modal) | `/gateway/api/v1/onboarding/tenants` | POST | `{tenant_name, description}` | `{tenant_id, tenant_name, ...}` |

### 2b. Accounts Page
**Route**: `/onboarding/accounts`

```
┌─────────────────────────────────────────────────────────────┐
│  Accounts  [Tenant: ▾]  [Provider: ▾]    [+ Onboard New]   │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Name    │ Provider│ Account # │ Status │ Last Scan   │   │
│  │─────────┼─────────┼───────────┼────────┼─────────────│   │
│  │ Prod-AWS│ aws     │ 12345678  │ active │ 2h ago      │   │
│  │ Dev-GCP │ gcp     │ proj-dev  │ active │ 1d ago      │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  [Click row → Account Detail panel]                         │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Account Health                                       │   │
│  │  Credentials: ✓ Valid    Last Validated: 2h ago      │   │
│  │  Total Scans: 47   Success Rate: 95.7%               │   │
│  │  [Re-validate]  [Delete Account]                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**3-step onboarding flow:**

| Step | Component | API | Method | Request Body | Response |
|------|-----------|-----|--------|--------------|----------|
| — | Account List | `/onboarding/api/v1/cloud-accounts` | GET | `?tenant_id=...&provider=...&status=...` | `{accounts:[...], count:N}` |
| 1 | Register Account | `/onboarding/api/v1/cloud-accounts` | POST | `{account_id, tenant_id, account_name, provider, regions:[]}` | created account object |
| 2 | Store & Validate Credentials | `/onboarding/api/v1/accounts/{id}/credentials` | POST | `{credential_type, credentials:{...}}` — see per-CSP shapes below | `{status:"stored", account_id}` or `400` |
| 3 | Activate + Schedule | `/onboarding/api/v1/cloud-accounts/{id}/validate` | POST | `{cron_expression, include_regions:[], engines_requested:[]}` | full updated account |
| — | Account Status | `/onboarding/api/v1/cloud-accounts/{id}/status` | GET | — | `{account_status, onboarding_status, credential_validation_status, schedule_enabled, ...}` |
| — | Re-validate Credentials | `/onboarding/api/v1/cloud-accounts/{id}/validate-credentials` | POST | — (no body) | `{success, status, message, validated_at}` |
| — | Update Config | `/onboarding/api/v1/cloud-accounts/{id}` | PATCH | any subset of account fields | updated account |
| — | Delete Account | `/onboarding/api/v1/cloud-accounts/{id}` | DELETE | — | `{message}` |
| — | Remove Credentials | `/onboarding/api/v1/accounts/{id}/credentials` | DELETE | — | `{status:"deleted"}` |

**Credential body shapes per CSP (Step 2):**

| CSP | `credential_type` | `credentials` object fields |
|-----|-------------------|-----------------------------|
| AWS Access Key | `aws_access_key` | `aws_access_key_id`, `aws_secret_access_key` |
| AWS IAM Role | `aws_iam_role` | `role_arn`, `external_id`, `account_number` |
| Azure | `azure_service_principal` | `client_id`, `client_secret`, `tenant_id`, `subscription_id` |
| GCP | `gcp_service_account` | `service_account_json` (full JSON object) |
| IBM | `ibm_api_key` | `api_key` |
| OCI | `oci_user_principal` | `user_ocid`, `tenancy_ocid`, `fingerprint`, `private_key` (PEM string), `region` |
| AliCloud | `alicloud_access_key` | `access_key_id`, `access_key_secret` |

> Credentials are validated **live** before storage. A `400` with `{message, errors:[]}` means the CSP rejected them.
> On success, `cloud_accounts.credential_validation_status` is set to `"valid"` automatically.

### 2c. Schedules Page
**Route**: `/onboarding/schedules`

```
┌─────────────────────────────────────────────────────────────┐
│  Scan Schedules                            [+ New Schedule] │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Name       │ Account │ Type │ Next Run  │ Status     │   │
│  │────────────┼─────────┼──────┼───────────┼────────────│   │
│  │ Daily Prod │ Prod-AWS│ cron │ in 4h     │ active     │   │
│  │ Weekly Dev │ Dev-GCP │ cron │ in 3d     │ active     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  [Click row → Execution History]                            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Execution History for "Daily Prod"                   │   │
│  │ Run #47 │ 2026-02-09 08:00 │ completed │ 12m 34s     │   │
│  │ Run #46 │ 2026-02-08 08:00 │ completed │ 11m 56s     │   │
│  │ [Trigger Now]  [Edit]  [Delete]                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Request | Response |
|-----------|-----|--------|---------|----------|
| Schedule List | `/gateway/api/v1/schedules` | GET | `?tenant_id=...` | `{schedules: [...]}` |
| Create Schedule | `/gateway/api/v1/schedules` | POST | `{account_id, tenant_id, name, schedule_type, cron_expression, ...}` | `{schedule_id, next_run_at}` |
| Execution History | `/gateway/api/v1/schedules/{id}/executions` | GET | — | `{executions: [...]}` |
| Trigger Now | `/gateway/api/v1/schedules/{id}/trigger` | POST | — | `{execution_id, status}` |
| Schedule Stats | `/gateway/api/v1/schedules/{id}/statistics` | GET | — | `{total_runs, success_rate, avg_duration}` |
| Edit Schedule | `/gateway/api/v1/schedules/{id}` | PUT | `{name?, cron_expression?, ...}` | `{status}` |
| Delete Schedule | `/gateway/api/v1/schedules/{id}` | DELETE | — | `{status}` |

---

## 3. SCANS (Orchestration)

### 3a. Run Scan
**Route**: `/scans/run`

```
┌─────────────────────────────────────────────────────────────┐
│  Run New Scan                                               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Tenant:    [▾ Select Tenant    ]                           │
│  Provider:  [▾ aws / azure / gcp]                           │
│  Account:   [▾ Select Account   ]                           │
│                                                             │
│           [ Start Full Scan ]                               │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Pipeline Progress                                   │   │
│  │                                                      │   │
│  │  Discovery  ████████████████████ 100%  ✓ 3,121 found│   │
│  │  Check      ████████████░░░░░░░  60%   running...   │   │
│  │  Inventory  ░░░░░░░░░░░░░░░░░░░   0%   pending     │   │
│  │  Threat     ░░░░░░░░░░░░░░░░░░░   0%   pending     │   │
│  │  Compliance ░░░░░░░░░░░░░░░░░░░   0%   pending     │   │
│  │  IAM        ░░░░░░░░░░░░░░░░░░░   0%   pending     │   │
│  │  DataSec    ░░░░░░░░░░░░░░░░░░░   0%   pending     │   │
│  │                                                      │   │
│  │  Orchestration ID: 27047875-910e-4267-bd4e-5fc...    │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Request | Response |
|-----------|-----|--------|---------|----------|
| Start Scan | `/gateway/gateway/orchestrate` | POST | `{customer_id, tenant_id, provider, hierarchy_id}` | `{orchestration_id, status, engines: {...}}` |
| Poll Discovery | `/gateway/api/v1/discovery/{id}/status` | GET | — | `{status, progress}` |
| Poll Check | `/gateway/api/v1/check/{id}/status` | GET | — | `{status, progress}` |
| Poll Threat | `/gateway/api/v1/threat/jobs/{id}` | GET | — | `{status, result}` |

### 3b. Scan History
**Route**: `/scans/history`

| Component | API | Method | Request | Response |
|-----------|-----|--------|---------|----------|
| Scan List | `/gateway/api/v1/threat/reports` | GET | `?tenant_id=...&limit=50` | `{reports: [{scan_run_id, tenant_id, status, created_at}]}` |
| Discovery Scans | `/gateway/api/v1/discoveries` | GET | `?tenant_id=...` | `{scans: [...]}` |
| Check Scans | `/gateway/api/v1/checks` | GET | `?tenant_id=...` | `{scans: [...]}` |

---

## 4. INVENTORY

### 4a. Assets List
**Route**: `/inventory/assets`

```
┌─────────────────────────────────────────────────────────────┐
│  Asset Inventory   [Provider ▾] [Region ▾] [Type ▾] [Search]│
├─────────────────────────────────────────────────────────────┤
│  Total: 3,121 assets    ┌──────────────────────────────┐    │
│                          │ By Type:                     │    │
│                          │  EC2: 45  S3: 23  RDS: 12   │    │
│                          │  Lambda: 67  IAM: 312  ...  │    │
│                          └──────────────────────────────┘    │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Resource UID        │ Type     │ Region    │ Account │   │
│  │─────────────────────┼──────────┼───────────┼─────────│   │
│  │ arn:aws:ec2:...     │ Instance │ us-east-1 │ 12345.. │   │
│  │ arn:aws:s3:::prod   │ Bucket   │ global    │ 12345.. │   │
│  │ ... (paginated)                                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Asset List (paginated) | `/gateway/api/v1/inventory/assets` | GET | `tenant_id, provider, region, resource_type, account_id, limit, offset` |
| Summary Stats | `/gateway/api/v1/inventory/runs/latest/summary` | GET | `tenant_id` |

### 4b. Asset Detail
**Route**: `/inventory/assets/:resource_uid`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Asset Detail | `/gateway/api/v1/inventory/assets/{uid}` | GET | `tenant_id` |
| Relationships | `/gateway/api/v1/inventory/assets/{uid}/relationships` | GET | `tenant_id, depth, direction` |
| Drift History | `/gateway/api/v1/inventory/assets/{uid}/drift` | GET | `tenant_id, limit` |
| Threats for Asset | `/gateway/api/v1/threat/resources/{uid}/threats` | GET | `tenant_id` |
| Compliance for Asset | `/gateway/api/v1/compliance/resource/{uid}/compliance` | GET | `tenant_id` |

### 4c. Graph View
**Route**: `/inventory/graph`

```
┌─────────────────────────────────────────────────────────────┐
│  Relationship Graph    [Resource ▾] [Depth: 2] [Apply]      │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │                                                      │   │
│  │          [VPC] ─── [Subnet] ─── [EC2]               │   │
│  │            │                      │                  │   │
│  │          [IGW]               [SecurityGroup]         │   │
│  │                                   │                  │   │
│  │                              [ELB] ─── [TG]         │   │
│  │                                                      │   │
│  │  (Force-directed / hierarchical graph visualization) │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Graph Data | `/gateway/api/v1/inventory/graph` | GET | `tenant_id, resource_uid, depth, limit` |

### 4d. Drift
**Route**: `/inventory/drift`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Drift Summary | `/gateway/api/v1/inventory/drift` | GET | `tenant_id, baseline_scan, compare_scan, change_type` |
| Scan Selector | `/gateway/api/v1/inventory/scans` | GET | `tenant_id` |

---

## 5. THREATS

### 5a. Threat Overview
**Route**: `/threats`

```
┌─────────────────────────────────────────────────────────────┐
│  Threat Overview                                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Critical │ │ High     │ │ Medium   │ │ Low      │       │
│  │   12     │ │   89     │ │  134     │ │   22     │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                             │
│  ┌────────────────────────┐ ┌──────────────────────────┐    │
│  │ By Service             │ │ By Account               │    │
│  │ [Horizontal Bar Chart] │ │ [Horizontal Bar Chart]   │    │
│  └────────────────────────┘ └──────────────────────────┘    │
│                                                             │
│  ┌────────────────────────┐ ┌──────────────────────────┐    │
│  │ Threat Patterns        │ │ Correlation Matrix       │    │
│  │ [Table]                │ │ [Heatmap]                │    │
│  └────────────────────────┘ └──────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Distribution KPIs | `/gateway/api/v1/threat/analytics/distribution` | GET | `tenant_id, scan_run_id` |
| By Service | `/gateway/api/v1/threat/map/service` | GET | `tenant_id, scan_run_id` |
| By Account | `/gateway/api/v1/threat/map/account` | GET | `tenant_id, scan_run_id` |
| Patterns | `/gateway/api/v1/threat/analytics/patterns` | GET | `tenant_id, scan_run_id` |
| Correlation | `/gateway/api/v1/threat/analytics/correlation` | GET | `tenant_id, scan_run_id` |

### 5b. Threat List
**Route**: `/threats/list`

```
┌─────────────────────────────────────────────────────────────┐
│  Threats  [Severity ▾] [Category ▾] [Status ▾] [Search]    │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │ ID     │ Title          │ Severity│ Resource │ Status│   │
│  │────────┼────────────────┼─────────┼──────────┼───────│   │
│  │ THR-01 │ Public S3      │ CRIT    │ s3://... │ open  │   │
│  │ THR-02 │ Unencrypted RDS│ HIGH    │ rds://...│ open  │   │
│  │ ... (paginated, sortable)                            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Threat List | `/gateway/api/v1/threat/threats` | GET | `tenant_id, scan_run_id, severity, category, status, limit, offset` |
| Prioritized View | `/gateway/api/v1/threat/analysis/prioritized` | GET | `tenant_id, top_n` |

### 5c. Threat Detail
**Route**: `/threats/:threat_id`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Threat Detail | `/gateway/api/v1/threat/threats/{id}` | GET | `tenant_id` |
| Root Cause Findings | `/gateway/api/v1/threat/{id}/misconfig-findings` | GET | `tenant_id` |
| Affected Assets | `/gateway/api/v1/threat/{id}/assets` | GET | `tenant_id` |
| Remediation Steps | `/gateway/api/v1/threat/{id}/remediation` | GET | `tenant_id` |
| Blast Radius | `/gateway/api/v1/graph/blast-radius/{resource_uid}` | GET | `tenant_id, max_hops` |
| Analysis Detail | `/gateway/api/v1/threat/analysis/{detection_id}` | GET | `tenant_id` |
| Update Status | `/gateway/api/v1/threat/{id}` | PATCH | `{status, assignee, notes}` |

### 5d. Attack Paths
**Route**: `/threats/attack-paths`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Attack Paths | `/gateway/api/v1/graph/attack-paths` | GET | `tenant_id, max_hops, min_severity` |
| Internet Exposed | `/gateway/api/v1/graph/internet-exposed` | GET | `tenant_id` |
| Toxic Combinations | `/gateway/api/v1/graph/toxic-combinations` | GET | `tenant_id, min_threats` |

### 5e. Analytics
**Route**: `/threats/analytics`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Trend Chart | `/gateway/api/v1/threat/analytics/trend` | GET | `tenant_id, days, severity` |
| Distribution | `/gateway/api/v1/threat/analytics/distribution` | GET | `tenant_id, scan_run_id` |
| Patterns | `/gateway/api/v1/threat/analytics/patterns` | GET | `tenant_id, limit` |
| Correlation | `/gateway/api/v1/threat/analytics/correlation` | GET | `tenant_id, scan_run_id` |

### 5f. Threat Hunting
**Route**: `/threats/hunting`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Predefined Hunts | `/gateway/api/v1/hunt/predefined` | GET | — |
| Custom Queries | `/gateway/api/v1/hunt/queries` | GET | `tenant_id` |
| Execute Hunt | `/gateway/api/v1/hunt/execute` | POST | `{tenant_id, hunt_id or predefined_id or cypher}` |
| Hunt Results | `/gateway/api/v1/hunt/results` | GET | `tenant_id, hunt_id, limit` |
| Save Query | `/gateway/api/v1/hunt/queries` | POST | `{tenant_id, query_name, query_text, hunt_type}` |

### 5g. Threat Intelligence
**Route**: `/threats/intel`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Intel Feed | `/gateway/api/v1/intel` | GET | `tenant_id, intel_type, severity, source, limit` |
| Add Intel | `/gateway/api/v1/intel/feed` | POST | `{tenant_id, source, intel_type, severity, threat_data}` |
| Correlate | `/gateway/api/v1/intel/correlate` | GET | `tenant_id` |

### 5h. MITRE ATT&CK Matrix
**Route**: `/threats/mitre`

Visual heat map showing which MITRE ATT&CK tactics and techniques have active findings. This is the single most-used view by threat analysts in enterprise CSPM platforms — it shows _where in the kill chain_ the cloud environment is exposed.

```
┌────────────────────────────────────────────────────────────────────┐
│  MITRE ATT&CK Coverage     [Account ▾]  [Scan ▾]  [Severity ▾]   │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  TACTIC         │ Init.Access │ Execution │ Persist. │ Priv.Esc   │
│─────────────────┼─────────────┼───────────┼──────────┼────────────│
│  T1530 Cloud Stor│  ████ 14   │           │          │            │
│  T1190 Pub.Facing│  ██ 6      │           │          │            │
│  T1078 Valid Acct│             │           │  ███ 9   │  ██ 4     │
│  T1548 Abuse Elev│             │           │          │  ██████22 │
│  T1552 Unsecure  │             │           │  ████ 11 │            │
│  T1580 Cloud Infra│            │  ██ 5     │          │            │
│                                                                    │
│  TACTIC         │ Cred.Access │ Discovery │ Lat.Move │ Impact     │
│─────────────────┼─────────────┼───────────┼──────────┼────────────│
│  T1552 Unsecure  │  ████ 11   │           │          │            │
│  T1087 Account   │             │  ████ 12  │          │            │
│  T1567 Exfil     │             │           │          │  ██ 3     │
│                                                                    │
│  Color: ░ 0  ▒ 1–3  ▓ 4–9  █ 10+                                 │
│  [Click any cell → filtered Threat List for that technique]        │
└────────────────────────────────────────────────────────────────────┘
```

> **Security Expert Note**: Focus remediation on T1548 (Privilege Escalation, 22 findings) and T1530/T1190 (Initial Access, 20 total). These are your highest-risk kill-chain entry points.

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Technique Breakdown | `/gateway/api/v1/threat/analytics/patterns` | GET | `tenant_id, scan_run_id, limit=50` |
| Filter by Technique | `/gateway/api/v1/threat/threats` | GET | `tenant_id, scan_run_id, category={mitre_technique}` |
| Severity Distribution | `/gateway/api/v1/threat/analytics/distribution` | GET | `tenant_id, scan_run_id` |

### 5i. Internet Exposure & Toxic Combinations
**Route**: `/threats/exposure`

Dedicated attack surface view for the two highest-risk posture signals: resources directly reachable from the internet, and dangerous coinciding misconfigurations.

```
┌────────────────────────────────────────────────────────────────────┐
│  Attack Surface                                                    │
├──────────────────────────────┬─────────────────────────────────────┤
│  Internet-Exposed Resources  │  Toxic Combinations                │
│                              │                                    │
│  ┌────────────────────────┐  │  ┌─────────────────────────────┐  │
│  │ 23 resources exposed   │  │  │ ⚠ 8 toxic combos found     │  │
│  │ to internet            │  │  │                             │  │
│  │                        │  │  │ Public + Unencrypted (4)    │  │
│  │  EC2 Instances:  11    │  │  │  └─ S3: 3  RDS: 1         │  │
│  │  S3 Buckets:      6    │  │  │                             │  │
│  │  RDS Endpoints:   3    │  │  │ No-MFA + Admin Role (3)     │  │
│  │  ELB/APIs:        3    │  │  │  └─ IAM Users: 3          │  │
│  │                        │  │  │                             │  │
│  │  [Click → Threat List] │  │  │ Public + No Logging (1)     │  │
│  └────────────────────────┘  │  └─────────────────────────────┘  │
│                              │                                    │
│  [View all exposed →]        │  [View all combos →]               │
└──────────────────────────────┴─────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Internet-Exposed Resources | `/gateway/api/v1/graph/internet-exposed` | GET | `tenant_id` |
| Toxic Combinations | `/gateway/api/v1/graph/toxic-combinations` | GET | `tenant_id, min_threats` |
| Attack Paths | `/gateway/api/v1/graph/attack-paths` | GET | `tenant_id, max_hops, min_severity` |
| Blast Radius (per resource) | `/gateway/api/v1/graph/blast-radius/{resource_uid}` | GET | `tenant_id, max_hops` |

---

## 6. COMPLIANCE

### 6a. Compliance Dashboard
**Route**: `/compliance`

```
┌─────────────────────────────────────────────────────────────┐
│  Compliance Dashboard                                       │
├─────────────────────────────────────────────────────────────┤
│  Overall Score: 76%        Frameworks: 5                    │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ HIPAA    │ │ PCI-DSS  │ │ SOC 2    │ │ CIS      │       │
│  │  78%     │ │  85%     │ │  72%     │ │  81%     │       │
│  │ [Gauge]  │ │ [Gauge]  │ │ [Gauge]  │ │ [Gauge]  │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Framework     │ Controls│ Passing│ Failing│ Score    │   │
│  │───────────────┼─────────┼────────┼────────┼──────────│   │
│  │ HIPAA         │ 45      │ 35     │ 10     │ 78%     │   │
│  │ PCI-DSS       │ 52      │ 44     │ 8      │ 85%     │   │
│  │ SOC 2         │ 61      │ 44     │ 17     │ 72%     │   │
│  │ CIS AWS       │ 98      │ 79     │ 19     │ 81%     │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                             │
│  [Generate Report ▾]  [Download PDF]  [Download Excel]      │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Dashboard Summary | `/gateway/api/v1/compliance/dashboard` | GET | `tenant_id, scan_id` |
| Framework List | `/gateway/api/v1/compliance/frameworks` | GET | `csp` |
| Generate Report | `/gateway/api/v1/compliance/generate/from-check-db` | POST | `{tenant_id, scan_id, csp, frameworks}` |
| Download PDF | `/gateway/api/v1/compliance/report/{id}/download/pdf` | GET | — |
| Download Excel | `/gateway/api/v1/compliance/report/{id}/download/excel` | GET | — |
| Trend | `/gateway/api/v1/compliance/trends` | GET | `csp, framework, days` |

### 6b. Framework Detail
**Route**: `/compliance/framework/:framework`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Framework Detail | `/gateway/api/v1/compliance/framework-detail/{fw}` | GET | `tenant_id, scan_id` |
| Controls Grouped | `/gateway/api/v1/compliance/framework/{fw}/controls/grouped` | GET | `scan_id, csp` |
| Resources Grouped | `/gateway/api/v1/compliance/framework/{fw}/resources/grouped` | GET | `scan_id, csp` |
| Search Controls | `/gateway/api/v1/compliance/controls/search` | GET | `query, framework, csp` |

### 6c. Control Detail
**Route**: `/compliance/framework/:framework/control/:control_id`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Control Detail | `/gateway/api/v1/compliance/control-detail/{fw}/{ctrl}` | GET | `tenant_id, scan_id` |
| Affected Resources | (included in control-detail response) | — | — |

### 6d. Reports
**Route**: `/compliance/reports`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Report List | `/gateway/api/v1/compliance/reports` | GET | `tenant_id, csp, limit, offset` |
| Report Detail | `/gateway/api/v1/compliance/report/{id}` | GET | — |
| Delete Report | `/gateway/api/v1/compliance/reports/{id}` | DELETE | — |

---

## 7. IAM SECURITY

> **CSPM Expert Context**: The IAM engine evaluates **6 security modules** across 825 findings from your AWS account. IAM misconfigurations are the #1 initial access vector in cloud breaches. Every page below maps to a specific `module=` filter on the findings endpoint.
>
> Modules: `least_privilege` · `policy_analysis` · `mfa` · `role_management` · `password_policy` · `access_control`

### 7a. IAM Overview
**Route**: `/iam`

Executive posture scorecard showing the risk signal from each of the 6 IAM modules, plus per-account risk scores.

```
┌────────────────────────────────────────────────────────────────────┐
│  IAM Security Posture    [Account ▾]  [Scan ▾]  [Run IAM Scan]    │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │
│  │ Total      │ │ Critical   │ │ High       │ │ IAM Score  │      │
│  │ Findings   │ │   18       │ │   312      │ │   42/100   │      │
│  │   825      │ │            │ │            │ │ (POOR)     │      │
│  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │
│                                                                    │
│  Module Scorecard                                                  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Module            │ Findings │ Critical │ Risk Level │ Trend │  │
│  │───────────────────┼──────────┼──────────┼────────────┼───────│  │
│  │ Least Privilege   │  312     │    5     │ ████ HIGH  │  ↑   │  │
│  │ Policy Analysis   │  198     │    8     │ ████ HIGH  │  →   │  │
│  │ MFA               │   87     │    3     │ ███ MEDIUM │  ↓   │  │
│  │ Role Management   │  142     │    2     │ ███ MEDIUM │  →   │  │
│  │ Password Policy   │   24     │    0     │ ██ LOW     │  ↓   │  │
│  │ Access Control    │   62     │    0     │ ██ LOW     │  →   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  [Least Privilege →]  [Policy Analysis →]  [MFA →]  [Roles →]     │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Module List & Counts | `/iam/api/v1/iam-security/modules` | GET | — |
| All Findings (summary) | `/iam/api/v1/iam-security/findings` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| Per-Account Posture | `/iam/api/v1/iam-security/accounts/{account_id}` | GET | `csp=aws&scan_id=latest` |
| Trigger Scan | `/iam/api/v1/iam-security/scan` | POST | `{csp, scan_id, tenant_id}` |

---

### 7b. Least Privilege & Policy Analysis
**Route**: `/iam/least-privilege`

The two most critical IAM modules. `least_privilege` finds entities that have more permissions than they use. `policy_analysis` finds structurally risky policies (wildcards, `*` on actions/resources, admin access).

```
┌────────────────────────────────────────────────────────────────────┐
│  Least Privilege & Policy Risk   [Severity ▾] [Service ▾]        │
├──────────────────────────────────┬─────────────────────────────────┤
│  Overprivileged Entities (312)   │  Policy Risk Signals (198)     │
│                                  │                                │
│  [Search role/user name...]      │  [Search policy name...]       │
│                                  │                                │
│  ┌────────────────────────────┐  │  ┌─────────────────────────┐  │
│  │ Entity      │Excess │ Sev  │  │  │ Signal        │Count    │  │
│  │─────────────┼───────┼──────│  │  │───────────────┼─────────│  │
│  │ LambdaExecR │ s3:*  │ HIGH │  │  │ Action *      │  89     │  │
│  │ EC2InstanceP│iam:*  │ CRIT │  │  │ Resource *    │  67     │  │
│  │ DevOpsRole  │ ec2:* │ HIGH │  │  │ Admin access  │  24     │  │
│  │ BackupLambda│ rds:* │ MED  │  │  │ Cross-account │  18     │  │
│  │ ... (312 more)             │  │  └─────────────────────────┘  │
│  └────────────────────────────┘  │                                │
│                                  │  [Click row → Rule Detail]    │
│  [Click row → Resource Detail]   │                                │
└──────────────────────────────────┴─────────────────────────────────┘
```

> **Fix Priority**: Start with `iam:*` and `s3:*` on compute roles — these allow privilege escalation and data exfiltration respectively.

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Least Privilege Findings | `/iam/api/v1/iam-security/findings` | GET | `module=least_privilege&csp=aws&scan_id=latest&tenant_id=T` |
| Policy Analysis Findings | `/iam/api/v1/iam-security/findings` | GET | `module=policy_analysis&csp=aws&scan_id=latest&tenant_id=T` |
| Rule Detail | `/iam/api/v1/iam-security/rules/{rule_id}` | GET | — |
| Resource IAM Context | `/iam/api/v1/iam-security/resources/{resource_uid}` | GET | `csp=aws&scan_id=latest` |
| Filter by Service | `/iam/api/v1/iam-security/services/{service}` | GET | `csp=aws&scan_id=latest` |

---

### 7c. MFA & Credential Health
**Route**: `/iam/mfa`

MFA adoption rate and stale/exposed credential detection. The two password-related modules in one view: `mfa` (multi-factor enforcement) and `password_policy` (account-level policy strength).

```
┌────────────────────────────────────────────────────────────────────┐
│  MFA & Credential Health                                          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────┐  ┌──────────────────────────────┐   │
│  │  MFA Adoption Rate       │  │  Password Policy Score       │   │
│  │                          │  │                              │   │
│  │  [Donut Chart]           │  │  Min Length:     ✓  12 chars │   │
│  │  ████████░░  72%         │  │  Complexity:     ✓  Required │   │
│  │                          │  │  Max Age:        ✗  Not set  │   │
│  │  MFA On:  21 users       │  │  Reuse Prev:     ✓  24 prev  │   │
│  │  MFA Off:  8 users       │  │  Account Score:  68/100      │   │
│  └──────────────────────────┘  └──────────────────────────────┘   │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  Findings Table: MFA & Password Policy                       │  │
│  │                                                              │  │
│  │  Finding                    │ Severity │ Resource    │ Status│  │
│  │  ─────────────────────────  │ ──────── │ ──────────  │ ──── │  │
│  │  Root account no MFA        │ CRITICAL │ account     │ open  │  │
│  │  Console user no MFA: dev1  │ HIGH     │ iam/user    │ open  │  │
│  │  Access key age > 90 days   │ HIGH     │ iam/user    │ open  │  │
│  │  Password policy: no expiry │ MEDIUM   │ account     │ open  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

> **Critical**: Root account without MFA is a CRITICAL finding — highest priority fix regardless of other scores.

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| MFA Findings | `/iam/api/v1/iam-security/findings` | GET | `module=mfa&csp=aws&scan_id=latest&tenant_id=T` |
| Password Policy Findings | `/iam/api/v1/iam-security/findings` | GET | `module=password_policy&csp=aws&scan_id=latest&tenant_id=T` |
| Rule Detail | `/iam/api/v1/iam-security/rules/{rule_id}` | GET | — |

---

### 7d. Role & Access Management
**Route**: `/iam/roles`

IAM role hygiene and access control effectiveness. `role_management` covers unused roles, overly trusted cross-account trust relationships, and permissive assume-role policies. `access_control` covers SCPs, permission boundaries, and resource-based policy exposure.

```
┌────────────────────────────────────────────────────────────────────┐
│  Role & Access Management    [Account ▾]  [Service ▾]            │
├──────────────────────────────────┬─────────────────────────────────┤
│  Role Hygiene (142 findings)     │  Access Control (62 findings)  │
│                                  │                                │
│  ┌────────────────────────────┐  │  ┌─────────────────────────┐  │
│  │ Issue           │ Count    │  │  │ Issue          │Count   │  │
│  │─────────────────┼──────────│  │  │────────────────┼────────│  │
│  │ Unused roles    │  47      │  │  │ No SCP on OU   │  12    │  │
│  │ Cross-acct trust│  23      │  │  │ No perm bound  │  31    │  │
│  │ Wildcard trust  │   8      │  │  │ Public policy  │  11    │  │
│  │ Stale roles     │  64      │  │  │ No resource tag│   8    │  │
│  └────────────────────────────┘  │  └─────────────────────────┘  │
│                                  │                                │
│  Role Trust Graph                │                                │
│  ┌────────────────────────────┐  │                                │
│  │  [AccountA] ──→ [RoleX]   │  │                                │
│  │       └──→ [RoleY] ──→ [R]│  │  [Click any row for detail]   │
│  └────────────────────────────┘  │                                │
└──────────────────────────────────┴─────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Role Management Findings | `/iam/api/v1/iam-security/findings` | GET | `module=role_management&csp=aws&scan_id=latest&tenant_id=T` |
| Access Control Findings | `/iam/api/v1/iam-security/findings` | GET | `module=access_control&csp=aws&scan_id=latest&tenant_id=T` |
| Per-Account IAM Posture | `/iam/api/v1/iam-security/accounts/{account_id}` | GET | `csp=aws&scan_id=latest` |
| Rule Pattern Reference | `/iam/api/v1/iam-security/rule-ids` | GET | — |

---

### 7e. Per-Resource IAM Findings
**Route**: `/iam/resource/:resource_uid`

Accessed from the Inventory Asset Detail page via deep link. Shows all IAM findings associated with a specific cloud resource.

```
┌────────────────────────────────────────────────────────────────────┐
│  IAM Findings for: arn:aws:iam::588989875114:role/EC2-Prod-Role   │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Rule                     │ Module          │ Severity │Status │  │
│  │  ─────────────────────── │ ──────────────  │ ──────── │ ──── │  │
│  │  ec2:* allows all actions│ least_privilege │ HIGH     │ open  │  │
│  │  No permission boundary  │ access_control  │ MEDIUM   │ open  │  │
│  │  Role unused 90+ days    │ role_management │ LOW      │ open  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  [← Back to Inventory]  [View Full IAM Posture →]                 │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Resource IAM Findings | `/iam/api/v1/iam-security/resources/{resource_uid}` | GET | `csp=aws&scan_id=latest` |
| Service IAM Posture | `/iam/api/v1/iam-security/services/{service}` | GET | `csp=aws&scan_id=latest` |

---

## 8. DATA SECURITY

> **CSPM Expert Context**: The DataSec engine analyses 21 data stores across S3, RDS, DynamoDB and other storage services. It performs 4 types of analysis (classification, lineage, residency, activity) and maps findings to GDPR, HIPAA, and PCI-DSS. Data exposure is the #1 consequence of cloud misconfiguration — these pages tell you _what data is at risk and why_.

### 8a. Data Risk Overview
**Route**: `/datasec`

Executive summary across all data security sub-modules. Designed for a CISO-level "data risk at a glance" view.

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Security Overview     [Account ▾]  [Scan ▾]                │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────┐  │
│  │ Data     │ │ Sensitive│ │ Exposed  │ │Unencrypt.│ │Residcy │  │
│  │ Stores   │ │ Stores   │ │ Publicly │ │ At Rest  │ │Violatn │  │
│  │   21     │ │    9     │ │    4     │ │    6     │ │   3    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └────────┘  │
│                                                                    │
│  ┌────────────────────────────┐  ┌──────────────────────────────┐  │
│  │  Data Risk by Service      │  │  Compliance Coverage         │  │
│  │  [Treemap]                 │  │  GDPR:  ████████░░  82%      │  │
│  │  S3 (12 stores, 4 exposed) │  │  HIPAA: ██████░░░░  61%      │  │
│  │  RDS (6 stores, 2 issues)  │  │  PCI:   █████████░  90%      │  │
│  │  DynamoDB (3 stores)       │  │                              │  │
│  └────────────────────────────┘  └──────────────────────────────┘  │
│                                                                    │
│  [Data Catalog →]  [Classification →]  [Residency →]  [Activity→] │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Data Stores (catalog summary) | `/datasec/api/v1/data-security/catalog` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| Classification Summary | `/datasec/api/v1/data-security/classification` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| Data Compliance Status | `/datasec/api/v1/data-security/compliance` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| All DataSec Findings | `/datasec/api/v1/data-security/findings` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| Module List | `/datasec/api/v1/data-security/modules` | GET | — |

---

### 8b. Data Catalog
**Route**: `/datasec/catalog`

Full inventory of all data stores discovered, with sensitivity level, encryption status, access exposure, and region.

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Catalog (21 Stores)   [Service ▾] [Region ▾] [Sensitivity▾]│
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Store                  │Service│Region  │Sensitivity│Access  │  │
│  │────────────────────────┼───────┼────────┼───────────┼────────│  │
│  │ prod-data-lake         │ S3    │us-east-1│ 🔴 HIGH  │ Public │  │
│  │ customer-pii-backup    │ S3    │ap-south-1│🔴 HIGH  │Private │  │
│  │ analytics-staging      │ S3    │us-east-1│ 🟡 MED  │Private │  │
│  │ prod-db-main           │ RDS   │ap-south-1│🔴 HIGH  │Private │  │
│  │ orders-dynamo          │DynamoDB│us-east-1│🟡 MED  │Private │  │
│  │ logs-archive           │ S3    │us-east-1│ 🟢 LOW  │Private │  │
│  │ ... (15 more stores)   │       │        │           │        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  [Click row → Protection & Governance Detail]                     │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Data Store List | `/datasec/api/v1/data-security/catalog` | GET | `csp=aws&scan_id=latest&account_id=A&service=s3&region=R` |
| Protection Detail | `/datasec/api/v1/data-security/protection/{resource_id}` | GET | `csp=aws&scan_id=latest` |
| Access Governance | `/datasec/api/v1/data-security/governance/{resource_id}` | GET | `csp=aws&scan_id=latest` |
| Per-Service Summary | `/datasec/api/v1/data-security/services/{service}` | GET | `csp=aws&scan_id=latest` |
| Per-Account Summary | `/datasec/api/v1/data-security/accounts/{account_id}` | GET | `csp=aws&scan_id=latest` |

---

### 8c. Data Classification
**Route**: `/datasec/classification`

Which data stores contain PII, PHI, or PCI data? This view drives GDPR/HIPAA reporting — security teams use it to prioritize which stores need the strongest controls.

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Classification (Sensitive Data Detection)   [Account ▾]    │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐              │
│  │ PII Stores   │ │ PHI Stores   │ │ PCI Stores   │              │
│  │    6         │ │    2         │ │    3         │              │
│  │ (personal    │ │ (health      │ │ (payment     │              │
│  │  identifiers)│ │  records)    │ │  card data)  │              │
│  └──────────────┘ └──────────────┘ └──────────────┘              │
│                                                                    │
│  Classification Heat Map (stores × data type)                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Store               │ PII │ PHI │ PCI │ Encrypted │ At Risk  │  │
│  │─────────────────────┼─────┼─────┼─────┼───────────┼──────── │  │
│  │ prod-data-lake      │  ✓  │     │  ✓  │     ✗     │ 🔴 YES  │  │
│  │ customer-pii-backup │  ✓  │  ✓  │     │     ✓     │ 🟡 NO   │  │
│  │ prod-db-main        │  ✓  │     │  ✓  │     ✓     │ 🟢 NO   │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  [Click row → Protection Detail for that store]                   │
└────────────────────────────────────────────────────────────────────┘
```

> **GDPR Note**: Any PII store that is publicly accessible or unencrypted is a GDPR Article 32 violation. Remediate `prod-data-lake` first.

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Classification Results | `/datasec/api/v1/data-security/classification` | GET | `csp=aws&scan_id=latest&tenant_id=T&account_id=A` |
| Findings for Data Type | `/datasec/api/v1/data-security/findings` | GET | `module=data_classification&csp=aws&scan_id=latest` |
| Protection Status | `/datasec/api/v1/data-security/protection/{resource_id}` | GET | `csp=aws&scan_id=latest` |
| Rule Detail | `/datasec/api/v1/data-security/rules/{rule_id}` | GET | — |

---

### 8d. Data Residency & Compliance
**Route**: `/datasec/residency`

Where is your data physically stored, and does it comply with geographic data sovereignty requirements? Critical for GDPR (EU data must stay in EU), India DPDP (Indian data must stay in India), and other regulations.

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Residency     [Allowed Regions: ap-south-1, eu-west-1 ▾]   │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  [World Map — dots at each AWS region, colored by compliance]     │
│                                                                    │
│  ● ap-south-1  (Mumbai)    — 8 stores  ✓ Allowed                 │
│  ● us-east-1   (N.Virginia)— 11 stores ⚠ VIOLATION (3 PII stores)│
│  ● eu-west-2   (London)    — 2 stores  ✓ Allowed                 │
│  ● ap-southeast-1 (Singapore)— 1 store ⚠ VIOLATION (1 PII store) │
│                                                                    │
│  Violations                                                        │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Store               │ Region       │ Data Type │ Framework  │  │
│  │─────────────────────┼──────────────┼───────────┼────────────│  │
│  │ customer-pii-backup │ us-east-1    │ PII       │ GDPR Art.44│  │
│  │ analytics-staging   │ us-east-1    │ PII       │ GDPR Art.44│  │
│  │ logs-pii            │ ap-southeast-1│ PII      │ IN-DPDP    │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  Framework Compliance Status                                       │
│  GDPR:  2 violations   HIPAA: 0 violations   PCI: 1 violation     │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Residency Violations | `/datasec/api/v1/data-security/residency` | GET | `csp=aws&scan_id=latest&tenant_id=T&allowed_regions=ap-south-1,eu-west-1` |
| Data Compliance Status | `/datasec/api/v1/data-security/compliance` | GET | `csp=aws&scan_id=latest&tenant_id=T&framework=GDPR` |
| Findings (residency module) | `/datasec/api/v1/data-security/findings` | GET | `module=data_residency&csp=aws&scan_id=latest` |

---

### 8e. Data Lineage
**Route**: `/datasec/lineage`

Flow diagram showing how data moves between services — from ingestion through storage to consumers. Used to understand blast radius: "if this bucket is compromised, what downstream systems are affected?"

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Lineage     [Source ▾]  [Depth: 3]  [Apply]                │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │                                                             │  │
│  │  [Kinesis] ──→ [S3: prod-data-lake] ──→ [Glue ETL]        │  │
│  │                        │                     │             │  │
│  │                        │              [Athena Queries]     │  │
│  │                        │                     │             │  │
│  │                   [Lambda]            [QuickSight]        │  │
│  │                        │                                   │  │
│  │                   [DynamoDB]                               │  │
│  │                                                             │  │
│  │  (Force-directed graph, click node = show findings)        │  │
│  └─────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  ⚠ prod-data-lake has PII data — 4 downstream consumers          │
└────────────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Lineage Graph Data | `/datasec/api/v1/data-security/lineage` | GET | `csp=aws&scan_id=latest&tenant_id=T` |
| Protection per Node | `/datasec/api/v1/data-security/protection/{resource_id}` | GET | `csp=aws&scan_id=latest` |
| Governance per Node | `/datasec/api/v1/data-security/governance/{resource_id}` | GET | `csp=aws&scan_id=latest` |

---

### 8f. Data Activity & Anomalies
**Route**: `/datasec/activity`

Time-series access patterns for data stores over the past N days, with anomaly detection. Unusual spikes in read/list operations can indicate data exfiltration in progress.

```
┌────────────────────────────────────────────────────────────────────┐
│  Data Activity Monitor     [Days Back: 30 ▾]  [Store ▾]          │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Access Operations (last 30 days)                                 │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │  [Line chart: GET/LIST/PUT ops per day, annotated anomalies] │  │
│  │  300 ─                                ⚠ spike               │  │
│  │  200 ─       ────────────────────────/──────────────────     │  │
│  │  100 ─ ────/                                                  │  │
│  │    0 ─ Feb 4  Feb 10  Feb 16  Feb 22  Feb 28  Mar 6         │  │
│  └──────────────────────────────────────────────────────────────┘  │
│                                                                    │
│  Anomalies Detected                                                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Store          │ Date     │ Op Type│ Baseline │ Actual │ △   │  │
│  │────────────────┼──────────┼────────┼──────────┼────────┼──── │  │
│  │ prod-data-lake │ Mar 4    │ GET    │  50/day  │ 289/day│ 5x  │  │
│  │ analytics-stg  │ Feb 28   │ LIST   │  10/day  │  87/day│ 8x  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

> **Security Analyst Note**: A 5× spike in GET operations on a PII bucket is a potential data exfiltration indicator. Cross-reference with CloudTrail logs for the IP address and user identity.

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Activity Time-Series | `/datasec/api/v1/data-security/activity` | GET | `csp=aws&scan_id=latest&days_back=30` |
| Findings (activity module) | `/datasec/api/v1/data-security/findings` | GET | `module=data_activity&csp=aws&scan_id=latest` |
| Per-Store Activity | `/datasec/api/v1/data-security/accounts/{account_id}` | GET | `csp=aws&scan_id=latest` |

---

## 9. CODE SECURITY (SecOps)

### 9a. Run Code Scan
**Route**: `/secops/scan`

```
┌─────────────────────────────────────────────────────────────┐
│  Code Security Scanner                                      │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Repository URL:  [https://github.com/org/repo.git      ]  │
│  Branch:          [main                                  ]  │
│  Tenant:          [▾ Select Tenant                       ]  │
│  Languages:       [▾ All / Select specific               ]  │
│                                                             │
│           [ Start Scan ]                                    │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Status: completed ✓                                 │   │
│  │  Scan ID: f6b3aea2-9e1d-4536-beef-c09fbc6e133c      │   │
│  │  Files Scanned: 10  |  Findings: 212  |  Errors: 205│   │
│  │  Languages: ruby, docker, javascript                 │   │
│  │                                                      │   │
│  │  [View Findings →]                                   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Request | Response |
|-----------|-----|--------|---------|----------|
| Start Scan | `/secops/api/v1/secops/scan` | POST | `{tenant_id, repo_url, branch, languages}` | `{secops_scan_id, status, summary, findings_count}` |
| Poll Status | `/secops/api/v1/secops/scan/{id}/status` | GET | — | `{status, summary}` |

### 9b. Scan Results
**Route**: `/secops/results/:scan_id`

```
┌─────────────────────────────────────────────────────────────┐
│  Scan: juice-shop   ID: f6b3aea2...                         │
│  [Severity ▾] [Language ▾] [Search rule/file]               │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │ Critical │ │ High     │ │ Medium   │ │ Low      │       │
│  │    0     │ │  201     │ │    0     │ │   11     │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ File Path           │ Rule ID           │Sev │ Line  │   │
│  │─────────────────────┼───────────────────┼────┼───────│   │
│  │ Dockerfile          │ pulling_image_..  │HIGH│ 1     │   │
│  │ Dockerfile          │ allowing_shell_.. │HIGH│ 5     │   │
│  │ .eslintrc.js        │ web_sql_databases │HIGH│ 6     │   │
│  │ ... (paginated, sortable)                            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Findings | `/secops/api/v1/secops/scan/{id}/findings` | GET | `severity, language` |
| Scan List | `/secops/api/v1/secops/scans` | GET | `tenant_id, limit` |

### 9c. Rule Library
**Route**: `/secops/rules`

| Component | API | Method | Params |
|-----------|-----|--------|--------|
| Rule Stats | `/secops/api/v1/secops/rules/stats` | GET | — |
| Sync Rules | `/secops/api/v1/secops/rules/sync` | POST | — |

---

## 10. SETTINGS

### 10a. Platform Health
**Route**: `/settings/health`

```
┌─────────────────────────────────────────────────────────────┐
│  Platform Health                                            │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Engine          │ Status  │ Port │ Latency │ Version │   │
│  │─────────────────┼─────────┼──────┼─────────┼─────────│   │
│  │ API Gateway     │ ✓ UP    │ 8000 │ 12ms    │ 1.0.0   │   │
│  │ Discovery       │ ✓ UP    │ 8001 │ 15ms    │ 1.0.0   │   │
│  │ Check           │ ✓ UP    │ 8002 │ 18ms    │ 1.0.0   │   │
│  │ Threat          │ ✓ UP    │ 8020 │ 22ms    │ 1.0.0   │   │
│  │ IAM             │ ✓ UP    │ 8003 │ 14ms    │ 1.0.0   │   │
│  │ Data Security   │ ✓ UP    │ 8004 │ 16ms    │ 1.0.0   │   │
│  │ Inventory       │ ✓ UP    │ 8022 │ 20ms    │ 1.0.0   │   │
│  │ Compliance      │ ✓ UP    │ 8010 │ 19ms    │ 1.0.0   │   │
│  │ SecOps          │ ✓ UP    │ 8009 │ 11ms    │ 3.0.0   │   │
│  │ Onboarding      │ ✓ UP    │ 8008 │ 13ms    │ 1.0.0   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

| Component | API | Method |
|-----------|-----|--------|
| Gateway Health | `/gateway/gateway/health` | GET |
| All Services | `/gateway/gateway/services` | GET |
