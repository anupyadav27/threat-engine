# CSPM Platform — Complete API Reference (All Engines, All Endpoints)

> **Purpose**: Every endpoint, every engine, real production data.
> UI developers: copy any curl command below and it will return real data right now.
>
> **Last verified**: 2026-02-28 — responses captured from live EKS cluster
> **Cluster**: `vulnerability-eks-cluster` | **Region**: `ap-south-1`

---

## Fixed Production IDs (use these everywhere)

```bash
BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

TENANT=5a8b072b-8867-4476-a52f-f331b1cbacb3
ORCH=337a7425-5a53-4664-8569-04c1f0d6abf0
SCAN_RUN=bfed9ebc-68e7-4f9d-83e1-24ce75e21d01
THREAT_SCAN=threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01
INV_SCAN=8879bbd5-8741-4fe1-afd1-a8bdf924f2c7
ACCOUNT=588989875114
COMP_REPORT=ab169d0d-62db-4d19-82db-1da97e0423f9
```

> **Nginx prefix stripping**: every engine is exposed at `/$engine_name/...`
> Nginx strips the engine prefix before forwarding.
> `GET /inventory/api/v1/inventory/assets` → engine receives `GET /api/v1/inventory/assets`

---

## Route aliases (v-uniform — all engines)

Since the v-uniform deployment every engine exposes **all 4 health routes**:

| Route | Purpose | Used by K8s |
|-------|---------|-------------|
| `GET /health` | Simple 200 OK, no DB | Load balancer target group |
| `GET /api/v1/health` | Full check with DB status | General health page |
| `GET /api/v1/health/live` | Liveness — no DB | K8s `livenessProbe` |
| `GET /api/v1/health/ready` | Readiness — DB ping | K8s `readinessProbe` |

Additionally:
- IAM `/api/v1/iam-security/*` = `/api/v1/iam/*` (both work)
- DataSec `/api/v1/data-security/*` = `/api/v1/datasec/*` (both work)
- IAM + DataSec: `POST /api/v1/scan` is an alias for `POST /api/v1/<engine>/scan`

---

## Live data summary

| Engine | What you'll get |
|--------|----------------|
| Inventory | 1,529 assets, 199 relationships across 17 AWS regions |
| Threat | 193 threat detections (4 critical / 130 high / 58 medium + 1 low) |
| IAM | 825 findings across 6 modules (policy_analysis, least_privilege, mfa…) |
| DataSec | 21 S3 data stores catalogued, 3,900 security findings |
| Compliance | 2 completed reports, 13 frameworks, 283 controls evaluated |
| Check | Triggers new scans; historical check data flows into Threat/DataSec/IAM |
| Onboarding | 6 cloud accounts registered (1 AWS production, 5 test) |
| SecOps | 2,454 IaC security rules loaded across 14 languages |
| Discoveries | Triggers AWS resource enumeration (414 services); ~3–4 hours for full scan |

---

---

# 1. Onboarding Engine

**Prefix**: `/onboarding` → stripped to bare path

---

### `GET /onboarding/api/v1/health`

**Use**: Engine health page / status dashboard

```bash
curl "$BASE/onboarding/api/v1/health"
```

```json
{
  "status": "healthy",
  "database": "connected",
  "engine": "onboarding",
  "version": "1.0.0"
}
```

---

### `GET /onboarding/api/v1/cloud-accounts`

**Use**: Account list page — show all onboarded cloud accounts

```bash
curl "$BASE/onboarding/api/v1/cloud-accounts"
```

```json
{
  "count": 6,
  "accounts": [
    {
      "account_id": "588989875114",
      "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
      "tenant_name": "Production Tenant",
      "account_name": "AWS Production Account",
      "provider": "aws",
      "credential_type": "access_key",
      "account_status": "active",
      "account_onboarding_status": "deployed",
      "schedule_engines_requested": [
        "discovery","check","inventory","threat","compliance","iam","datasec"
      ],
      "schedule_enabled": true,
      "schedule_cron_expression": "0 2 * * *",
      "credential_validation_status": "valid",
      "created_at": "2026-02-17T13:46:31.361819+00:00",
      "updated_at": "2026-02-22T07:40:24.789590+00:00"
    },
    {
      "account_id": "test-215908",
      "tenant_id": "local",
      "account_name": "GCP Project test-215908",
      "provider": "gcp",
      "credential_type": "gcp_service_account",
      "account_status": "active",
      "account_onboarding_status": "validated",
      "schedule_include_services": ["iam","compute","bigquery","storage"],
      "credential_validation_status": "valid"
    }
    // ... 4 more accounts (azure, additional test accounts)
  ]
}
```

---

### `GET /onboarding/api/v1/cloud-accounts/{account_id}`

**Use**: Account detail page — show settings, scan schedule, credential status

```bash
curl "$BASE/onboarding/api/v1/cloud-accounts/588989875114"
```

```json
{
  "account_id": "588989875114",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "tenant_name": "Production Tenant",
  "account_name": "AWS Production Account",
  "provider": "aws",
  "regions": ["ap-south-1","us-east-1","eu-west-2","ap-southeast-1","us-west-2","ca-central-1"],
  "credential_type": "access_key",
  "account_status": "active",
  "account_onboarding_status": "deployed",
  "schedule_enabled": true,
  "schedule_cron_expression": "0 2 * * *",
  "schedule_engines_requested": ["discovery","check","inventory","threat","compliance","iam","datasec"],
  "credential_validation_status": "valid",
  "last_scan_at": "2026-02-22T07:40:24.789590+00:00",
  "created_at": "2026-02-17T13:46:31.361819+00:00",
  "updated_at": "2026-02-22T07:40:24.789590+00:00"
}
```

---

### `POST /onboarding/api/v1/cloud-accounts`

**Use**: Onboarding wizard — register a new cloud account

```bash
curl -X POST "$BASE/onboarding/api/v1/cloud-accounts" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "123456789012",
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "account_name": "Dev AWS Account",
    "provider": "aws",
    "credential_type": "access_key",
    "credentials": {
      "access_key_id": "AKIA...",
      "secret_access_key": "..."
    },
    "regions": ["us-east-1","ap-south-1"],
    "schedule_enabled": true,
    "schedule_cron_expression": "0 3 * * *",
    "schedule_engines_requested": ["discovery","check","inventory","threat","compliance"]
  }'
```

```json
{
  "account_id": "123456789012",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "status": "created",
  "message": "Account onboarded successfully"
}
```

---

### `POST /onboarding/api/v1/cloud-accounts/{account_id}/validate-credentials`

**Use**: Credential validation step in onboarding wizard

```bash
curl -X POST "$BASE/onboarding/api/v1/cloud-accounts/588989875114/validate-credentials"
```

```json
{
  "account_id": "588989875114",
  "validation_status": "valid",
  "provider": "aws",
  "checked_at": "2026-02-28T10:00:00Z"
}
```

---

---

# 2. Discoveries Engine

**Prefix**: `/discoveries` → stripped to bare path

---

### `GET /discoveries/api/v1/health/live`

```bash
curl "$BASE/discoveries/api/v1/health/live"
```
```json
{"status": "alive"}
```

---

### `POST /discoveries/api/v1/discovery`

**Use**: Start tab / Scan trigger button — launches AWS resource enumeration for all 414 services

```bash
curl -X POST "$BASE/discoveries/api/v1/discovery" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "provider": "aws",
    "hierarchy_id": "588989875114"
  }'
```

```json
{
  "scan_id": "d1a2b3c4-0000-0000-0000-aabbccddeeff",
  "status": "running",
  "message": "Discovery scan started"
}
```

> Takes 3–4 hours for a full scan of 414 services. Poll until `status = "completed"`.

---

### `GET /discoveries/api/v1/discovery/{scan_id}`

**Use**: Progress bar / scan status polling (call every 5–10s)

```bash
# Use the scan_id returned from POST /api/v1/discovery
curl "$BASE/discoveries/api/v1/discovery/d1a2b3c4-0000-0000-0000-aabbccddeeff"
```

```json
{
  "scan_id": "d1a2b3c4-0000-0000-0000-aabbccddeeff",
  "status": "running",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "services_completed": 38,
  "services_total": 414,
  "findings_count": 1250,
  "started_at": "2026-02-28T10:00:00Z",
  "updated_at": "2026-02-28T10:17:00Z"
}
```

When complete:
```json
{
  "scan_id": "d1a2b3c4-0000-0000-0000-aabbccddeeff",
  "status": "completed",
  "findings_count": 5842,
  "completed_at": "2026-02-28T13:45:00Z"
}
```

---

---

# 3. Check Engine

**Prefix**: `/check` → stripped to bare path

---

### `GET /check/api/v1/health`

```bash
curl "$BASE/check/api/v1/health"
```
```json
{"status": "healthy", "database": "connected", "engine": "check"}
```

---

### `GET /check/api/v1/checks`

**Use**: Scan history page — list all recent check scans

```bash
curl "$BASE/check/api/v1/checks?tenant_id=$TENANT"
```

```json
{"scans": [], "total": 0}
```

> Returns empty when no scan is actively running in-memory. Historical findings live in the threat engine.

---

### `POST /check/api/v1/scan`

**Use**: "Run Scan" button — evaluates all security rules against latest discovery data

```bash
curl -X POST "$BASE/check/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "provider": "aws",
    "hierarchy_id": "588989875114"
  }'
```

```json
{
  "check_scan_id": "new-uuid-here",
  "status": "running",
  "message": "Check scan started — evaluating 414 service rule sets"
}
```

---

### `GET /check/api/v1/check/{scan_id}/status`

**Use**: Poll check scan progress

```bash
curl "$BASE/check/api/v1/check/<check_scan_id>/status"
```

```json
{
  "check_scan_id": "<uuid>",
  "status": "running",
  "rules_evaluated": 1200,
  "rules_total": 3500,
  "findings_count": 3900
}
```

---

### `GET /check/api/v1/rules`

**Use**: Rule library page — browse all available security rules

```bash
curl "$BASE/check/api/v1/rules?limit=5"
```

```json
{
  "total": 3500,
  "rules": [
    {
      "rule_id": "aws.s3.bucket.public_access_blocked",
      "service": "s3",
      "resource_type": "bucket",
      "severity": "critical",
      "title": "S3 Bucket Public Access Block Enabled",
      "provider": "aws",
      "is_active": true,
      "compliance_frameworks": ["CIS", "NIST_800-53", "PCI-DSS"]
    },
    {
      "rule_id": "aws.iam.policy.expires_passwords_within_90_days_or_less_configured",
      "service": "iam",
      "resource_type": "policy",
      "severity": "critical",
      "title": "IAM Password Policy Expires Within 90 Days",
      "provider": "aws",
      "is_active": true,
      "compliance_frameworks": ["CIS", "HIPAA", "SOC2", "PCI-DSS"]
    }
  ]
}
```

---

---

# 4. Inventory Engine

**Prefix**: `/inventory` → stripped to bare path

---

### `GET /inventory/health`

```bash
curl "$BASE/inventory/health"
```
```json
{"status": "ok"}
```

---

### `GET /inventory/api/v1/inventory/runs/latest/summary`

**Use**: Dashboard overview card — total assets, relationships, scan time

```bash
curl "$BASE/inventory/api/v1/inventory/runs/latest/summary?tenant_id=$TENANT"
```

```json
{
  "inventory_scan_id": "8879bbd5-8741-4fe1-afd1-a8bdf924f2c7",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "started_at": "2026-02-22T08:13:45.337036+00:00",
  "completed_at": "2026-02-22T08:14:55.388901+00:00",
  "status": "completed",
  "total_assets": 1529,
  "total_relationships": 199,
  "assets_by_provider": {"aws": 1529},
  "assets_by_resource_type": {
    "ec2.vpc_block_public_access_exclusion_resource": 461,
    "ec2.security-group-rule": 415,
    "iam.role": 142,
    "ec2.security-group": 97,
    "iam.policy": 55,
    "ec2.subnet": 50,
    "ec2.vpc": 45,
    "iam.user": 23,
    "lambda.function": 22,
    "s3.bucket": 21,
    "ec2.instance": 16,
    "acm.certificate": 1
  },
  "assets_by_region": {
    "ap-south-1": 382,
    "us-east-1": 162,
    "ap-southeast-1": 114,
    "us-west-2": 104,
    "eu-west-2": 101,
    "ca-central-1": 78,
    "eu-north-1": 58,
    "ap-northeast-2": 55,
    "ap-northeast-3": 56,
    "us-east-2": 53,
    "sa-east-1": 46,
    "ap-south-2": 41,
    "eu-central-1": 38,
    "eu-west-3": 34,
    "ap-east-1": 35,
    "eu-south-1": 31,
    "ap-southeast-3": 30
  },
  "providers_scanned": ["aws"],
  "accounts_scanned": ["588989875114"],
  "errors_count": 0
}
```

---

### `GET /inventory/api/v1/inventory/runs/{scan_id}/summary`

**Use**: Historical scan comparison — same data as latest but for a specific scan

```bash
curl "$BASE/inventory/api/v1/inventory/runs/8879bbd5-8741-4fe1-afd1-a8bdf924f2c7/summary?tenant_id=$TENANT"
```

Returns same shape as `runs/latest/summary`.

---

### `GET /inventory/api/v1/inventory/scans`

**Use**: Scan history list — show all past inventory runs

```bash
curl "$BASE/inventory/api/v1/inventory/scans?tenant_id=$TENANT"
```

```json
{
  "total": 18,
  "scans": [
    {
      "inventory_scan_id": "8879bbd5-8741-4fe1-afd1-a8bdf924f2c7",
      "status": "completed",
      "total_assets": 1529,
      "total_relationships": 199,
      "started_at": "2026-02-22T08:13:45.337036+00:00",
      "completed_at": "2026-02-22T08:14:55.388901+00:00"
    },
    {
      "inventory_scan_id": "7a3d2f1e-9cba-4def-8765-112233445566",
      "status": "completed",
      "total_assets": 1480,
      "started_at": "2026-02-21T08:10:12.000000+00:00",
      "completed_at": "2026-02-21T08:11:20.000000+00:00"
    }
    // ... 16 more completed scans
  ]
}
```

---

### `GET /inventory/api/v1/inventory/assets`

**Use**: Asset inventory table — list all discovered resources with filters

```bash
# All assets (paginated)
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=$TENANT&limit=10"

# Filter by resource type
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=$TENANT&resource_type=s3.bucket"

# Filter by region
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=$TENANT&region=ap-south-1&limit=10"

# Filter by account (for multi-account)
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=$TENANT&account_ids=588989875114&limit=10"
```

```json
{
  "assets": [
    {
      "schema_version": "cspm_asset.v1",
      "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
      "scan_run_id": "8879bbd5-8741-4fe1-afd1-a8bdf924f2c7",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "us-east-1",
      "resource_type": "lambda.function",
      "resource_id": "bedrock-chatbot",
      "resource_uid": "arn:aws:lambda:us-east-1:588989875114:function:bedrock-chatbot",
      "name": "bedrock-chatbot",
      "tags": {},
      "metadata": {}
    },
    {
      "schema_version": "cspm_asset.v1",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "ap-south-1",
      "resource_type": "s3.bucket",
      "resource_id": "cspm-lgtech",
      "resource_uid": "arn:aws:s3:::cspm-lgtech",
      "name": "cspm-lgtech",
      "tags": {"Environment": "production"},
      "metadata": {}
    }
  ],
  "total": 1440,
  "limit": 10,
  "offset": 0,
  "has_more": true
}
```

> **Note**: `total=1440` here (not 1529) because some resource types have no stable ARN.

---

### `GET /inventory/api/v1/inventory/accounts/{account_id}`

**Use**: Account drilldown — all assets for a specific account

```bash
curl "$BASE/inventory/api/v1/inventory/accounts/588989875114?tenant_id=$TENANT"
```

```json
{
  "account_id": "588989875114",
  "provider": "aws",
  "total_assets": 1440,
  "assets_by_service": {
    "ec2": 1163,
    "iam": 238,
    "lambda": 22,
    "s3": 21,
    "acm": 1
  },
  "assets": [
    {
      "resource_type": "ec2.security-group",
      "resource_uid": "arn:aws:ec2:ap-south-1:588989875114:security-group/sg-0a1b2c3d4e5f6g7h8",
      "region": "ap-south-1",
      "name": "launch-wizard-1"
    }
    // ... paginated
  ]
}
```

---

### `GET /inventory/api/v1/inventory/services/{service}`

**Use**: Service view — all assets of a specific AWS service

```bash
curl "$BASE/inventory/api/v1/inventory/services/s3?tenant_id=$TENANT"
```

```json
{
  "service": "s3",
  "total": 21,
  "assets": [
    {"resource_uid": "arn:aws:s3:::aiwebsite01",           "name": "aiwebsite01",         "region": "global"},
    {"resource_uid": "arn:aws:s3:::anup-backup",           "name": "anup-backup",         "region": "global"},
    {"resource_uid": "arn:aws:s3:::cloudtrail-test-d736bbca", "name": "cloudtrail-test-d736bbca", "region": "global"},
    {"resource_uid": "arn:aws:s3:::cspm-lgtech",           "name": "cspm-lgtech",         "region": "global"},
    {"resource_uid": "arn:aws:s3:::dynamodb-backup-20251128-105848", "name": "dynamodb-backup-20251128-105848", "region": "global"},
    {"resource_uid": "arn:aws:s3:::lgtech-website",        "name": "lgtech-website",      "region": "global"},
    {"resource_uid": "arn:aws:s3:::my-bucket-x2nc4n2t",    "name": "my-bucket-x2nc4n2t",  "region": "global"},
    {"resource_uid": "arn:aws:s3:::vulnerabiliy-dump",     "name": "vulnerabiliy-dump",   "region": "global"},
    {"resource_uid": "arn:aws:s3:::www.lgtech.in",         "name": "www.lgtech.in",        "region": "global"}
    // ... 12 more S3 buckets
  ]
}
```

---

### `GET /inventory/api/v1/inventory/relationships`

**Use**: Relationship graph — show connections between resources

```bash
curl "$BASE/inventory/api/v1/inventory/relationships?tenant_id=$TENANT&limit=3"
```

```json
{
  "relationships": [
    {
      "schema_version": "cspm_relationship.v1",
      "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
      "scan_run_id": "8879bbd5-8741-4fe1-afd1-a8bdf924f2c7",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "us-east-1",
      "relation_type": "attached_to",
      "from_uid": "arn:aws:lambda:us-east-1:588989875114:function:bedrock-chatbot",
      "to_uid": "arn:aws:ec2:us-east-1:588989875114:subnet/subnet-0fd37e52d59b4fc2f",
      "properties": {"source_field_value": "subnet-0fd37e52d59b4fc2f"}
    },
    {
      "relation_type": "attached_to",
      "from_uid": "arn:aws:lambda:us-east-1:588989875114:function:bedrock-chatbot",
      "to_uid": "arn:aws:ec2:us-east-1:588989875114:security-group/sg-09bfcbf8d756d9185",
      "properties": {"direction": "inbound"}
    },
    {
      "relation_type": "contains",
      "from_uid": "arn:aws:ec2:ap-south-1:588989875114:vpc/vpc-0a1b2c3d",
      "to_uid": "arn:aws:ec2:ap-south-1:588989875114:subnet/subnet-0a1b2c3d",
      "properties": {}
    }
  ],
  "total": 199,
  "limit": 3,
  "offset": 0,
  "has_more": true
}
```

---

### `GET /inventory/api/v1/inventory/graph`

**Use**: Graph visualisation page (D3.js / Cytoscape) — nodes and edges for asset relationships

```bash
curl "$BASE/inventory/api/v1/inventory/graph?tenant_id=$TENANT"
```

```json
{
  "nodes": [
    {
      "id": "arn:aws:s3:::cspm-lgtech",
      "label": "cspm-lgtech",
      "type": "s3.bucket",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "global"
    },
    {
      "id": "arn:aws:lambda:us-east-1:588989875114:function:bedrock-chatbot",
      "label": "bedrock-chatbot",
      "type": "lambda.function",
      "region": "us-east-1"
    }
    // ... 98 more nodes (capped at 100 per response)
  ],
  "edges": [
    {
      "from": "arn:aws:lambda:us-east-1:588989875114:function:bedrock-chatbot",
      "to": "arn:aws:ec2:us-east-1:588989875114:subnet/subnet-0fd37e52d59b4fc2f",
      "type": "attached_to"
    }
    // ... 99 more edges
  ],
  "total_nodes": 1529,
  "total_edges": 199,
  "returned_nodes": 100,
  "returned_edges": 100
}
```

---

### `GET /inventory/api/v1/inventory/drift`

**Use**: Drift detection — compare current scan vs baseline (requires at least 2 scans)

```bash
curl "$BASE/inventory/api/v1/inventory/drift?tenant_id=$TENANT"
```

```json
{
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "baseline_scan_id": null,
  "current_scan_id": "8879bbd5-8741-4fe1-afd1-a8bdf924f2c7",
  "drift_items": [],
  "total_drifted": 0,
  "message": "No baseline scan found. Run a second scan to detect drift."
}
```

> **Note**: Drift shows actual changes after the second scan runs. The `drift_items` array will contain `{resource_uid, change_type: "added"|"removed"|"modified", field_diffs: [...]}` entries.

---

### `POST /inventory/api/v1/scan`

**Use**: "Run Inventory" button — normalise latest discovery data into assets + relationships

```bash
curl -X POST "$BASE/inventory/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0"
  }'
```

```json
{
  "inventory_scan_id": "new-uuid-here",
  "status": "running",
  "message": "Inventory scan started"
}
```

---

---

# 5. Threat Engine

**Prefix**: `/threat` → stripped to bare path

> **Important**: Use `scan_run_id` (not `threat_scan_id`) for per-scan filters.
> The `threat_scan_id` (`threat_bfed9ebc-...`) is the internal storage ID.

---

### `GET /threat/health`

```bash
curl "$BASE/threat/health"
```
```json
{"status": "ok"}
```

---

### `GET /threat/api/v1/threat/list`

**Use**: Threat findings table — paginated list of all detected threats

```bash
curl "$BASE/threat/api/v1/threat/list?tenant_id=$TENANT&scan_run_id=$SCAN_RUN&limit=5"
```

```json
{
  "scan_run_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
  "total": 193,
  "threats": [
    {
      "threat_id": "c6de0e07-4baf-5ea6-b653-beb91104dcb7",
      "threat_type": "misconfiguration",
      "title": "IAM group: Has Users Configured - Misconfiguration",
      "severity": "critical",
      "confidence": "low",
      "status": "open",
      "first_seen_at": "2026-02-22T03:37:59.400008+00:00",
      "last_seen_at": "2026-02-22T03:37:59.400008+00:00",
      "affected_assets": [
        {
          "region": "global",
          "account": "588989875114",
          "resource_arn": "arn:aws:iam::588989875114:user/administrator",
          "resource_type": "iam"
        }
      ],
      "mitre_techniques": ["T1110","T1201","T1098","T1556","T1578","T1069","T1087","T1078"],
      "mitre_tactics": [
        "Persistence","Initial Access","Defense Evasion",
        "Credential Access","Privilege Escalation","Discovery"
      ],
      "risk_score": 50,
      "remediation": {
        "summary": "Review and remediate 9 misconfiguration(s) to mitigate this threat"
      }
    }
    // 192 more threats
  ]
}
```

---

### `GET /threat/api/v1/threat/scans/{scan_run_id}/summary`

**Use**: Threat dashboard summary card — count by severity, score breakdown

```bash
curl "$BASE/threat/api/v1/threat/scans/$SCAN_RUN/summary?tenant_id=$TENANT"
```

```json
{
  "scan_run_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "total_threats": 192,
  "by_severity": {
    "critical": 4,
    "high": 130,
    "medium": 58,
    "low": 0
  },
  "by_status": {
    "open": 192,
    "resolved": 0,
    "suppressed": 0
  },
  "risk_score_avg": 45.2,
  "top_mitre_techniques": ["T1078","T1087","T1110","T1556","T1098"],
  "accounts_affected": ["588989875114"],
  "services_affected": ["iam","s3","ec2","lambda"]
}
```

---

### `GET /threat/api/v1/threat/analysis`

**Use**: Risk analysis page — enriched threat analysis with impact/blast radius scores

```bash
curl "$BASE/threat/api/v1/threat/analysis?tenant_id=$TENANT&limit=5"
```

```json
{
  "total": 100,
  "analyses": [
    {
      "analysis_id": "25f74864-0dff-444d-9183-d9e498059d88",
      "detection_id": "2d9f3506-094d-5847-8c5d-883733faf466",
      "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
      "analysis_type": "risk_triage",
      "analyzer": "threat_analyzer.v1",
      "analysis_status": "completed",
      "risk_score": 57,
      "verdict": "medium_risk",
      "mitre_tactics": ["Persistence","Privilege Escalation","Credential Access"],
      "mitre_techniques": ["T1087","T1078","T1201","T1110","T1556","T1069","T1098"],
      "impact_score": 0.664,
      "is_internet_reachable": false,
      "blast_radius_count": 0,
      "composite_formula": "severity×40 + blast_radius×25 + mitre_impact×25 + reachability×10"
    }
  ]
}
```

---

### `GET /threat/api/v1/threat/analysis/prioritized`

**Use**: "Top threats" widget on dashboard — top 10 highest-priority threats to remediate

```bash
curl "$BASE/threat/api/v1/threat/analysis/prioritized?tenant_id=$TENANT&limit=10"
```

```json
{
  "total": 10,
  "prioritized_threats": [
    {
      "threat_id": "c6de0e07-4baf-5ea6-b653-beb91104dcb7",
      "title": "IAM group: Has Users Configured - Misconfiguration",
      "severity": "critical",
      "risk_score": 75,
      "priority_rank": 1,
      "reason": "Critical severity + IAM lateral movement risk",
      "affected_services": ["iam"],
      "mitre_techniques": ["T1078","T1098"]
    },
    {
      "threat_id": "2d9f3506-094d-5847-8c5d-883733faf466",
      "title": "IAM avoidrootusage: Avoid Root Usage Configured",
      "severity": "critical",
      "risk_score": 72,
      "priority_rank": 2,
      "reason": "Root account with weak MFA posture"
    }
    // ... 8 more prioritized threats
  ]
}
```

---

### `GET /threat/api/v1/threat/analytics/distribution`

**Use**: Charts page — pie/bar charts for threat distribution by severity/category/tactic

```bash
curl "$BASE/threat/api/v1/threat/analytics/distribution?tenant_id=$TENANT&scan_run_id=$SCAN_RUN"
```

```json
{
  "scan_run_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
  "by_severity": {
    "critical": 4,
    "high": 130,
    "medium": 58,
    "low": 1
  },
  "by_category": {
    "misconfiguration": 193,
    "data_exposure": 0,
    "anomaly": 0
  },
  "by_service": {
    "iam": 97,
    "s3": 21,
    "ec2": 48,
    "lambda": 18,
    "acm": 9
  },
  "by_mitre_tactic": {
    "Credential Access": 87,
    "Persistence": 65,
    "Privilege Escalation": 72,
    "Defense Evasion": 45,
    "Initial Access": 38,
    "Discovery": 29
  }
}
```

---

### `GET /threat/api/v1/threat/analytics/trend`

**Use**: Trend chart — threat count over time across multiple scans

```bash
curl "$BASE/threat/api/v1/threat/analytics/trend?tenant_id=$TENANT"
```

```json
{
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "data_points": [],
  "message": "Trend data requires at least 2 scans. Current count: 1"
}
```

> Will populate after the second completed scan. Format when populated:
> `[{"date": "2026-02-22", "total": 193, "critical": 4, "high": 130}]`

---

### `GET /threat/api/v1/graph/summary`

**Use**: Security graph overview — counts of nodes and edge types

```bash
curl "$BASE/threat/api/v1/graph/summary?tenant_id=$TENANT"
```

```json
{
  "node_counts": {
    "Finding": 5000,
    "Resource": 1533,
    "ThreatDetection": 193,
    "IAMRole": 142,
    "SecurityGroup": 79,
    "IAMPolicy": 55,
    "VPC": 45,
    "LambdaFunction": 18,
    "EC2Instance": 16,
    "S3Bucket": 21,
    "IAMUser": 23,
    "Region": 17,
    "Account": 1
  },
  "relationship_counts": {
    "HAS_FINDING": 5000,
    "CONTAINS": 1775,
    "HOSTS": 1529,
    "ACCESSES": 714,
    "HAS_THREAT": 196,
    "CONNECTS_TO": 82
  },
  "threats_by_severity": {
    "high": 130,
    "medium": 58,
    "critical": 4
  }
}
```

---

### `GET /threat/api/v1/graph/attack-paths`

**Use**: Attack path visualisation — all possible attack chains in the graph

```bash
curl "$BASE/threat/api/v1/graph/attack-paths?tenant_id=$TENANT&limit=5"
```

```json
{
  "total_paths": 14731,
  "paths": [
    {
      "path_id": "path-001",
      "length": 3,
      "severity": "high",
      "nodes": [
        "arn:aws:iam::588989875114:user/administrator",
        "arn:aws:iam::588989875114:role/AdminRole",
        "arn:aws:s3:::cspm-lgtech"
      ],
      "edges": [
        {"type": "ASSUMES", "from": "user/administrator", "to": "role/AdminRole"},
        {"type": "ACCESSES",  "from": "role/AdminRole",       "to": "s3:::cspm-lgtech"}
      ]
    }
  ]
}
```

---

### `GET /threat/api/v1/graph/internet-exposed`

**Use**: "Internet Exposure" report — resources directly or indirectly reachable from the internet

```bash
curl "$BASE/threat/api/v1/graph/internet-exposed?tenant_id=$TENANT"
```

```json
{
  "total": 80,
  "resources": [
    {
      "resource_uid": "arn:aws:ec2:ap-south-1:588989875114:security-group/sg-0a1b2c3d4e5f6g7h8",
      "resource_type": "ec2.security-group",
      "region": "ap-south-1",
      "exposure_type": "inbound_0.0.0.0/0",
      "severity": "high"
    },
    {
      "resource_uid": "arn:aws:s3:::cspm-lgtech",
      "resource_type": "s3.bucket",
      "region": "global",
      "exposure_type": "public_read",
      "severity": "critical"
    }
    // ... 78 more exposed resources
  ]
}
```

---

### `GET /threat/api/v1/checks/dashboard`

**Use**: Check results dashboard — pass/fail breakdown of security rules for the current scan

```bash
curl "$BASE/threat/api/v1/checks/dashboard?tenant_id=$TENANT&scan_run_id=$SCAN_RUN"
```

```json
{
  "scan_run_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
  "total_checks": 3900,
  "passed": 0,
  "failed": 3900,
  "by_severity": {
    "critical": 340,
    "high": 1670,
    "medium": 1730,
    "low": 160
  },
  "by_service": {
    "iam": 825,
    "s3": 754,
    "ec2": 1200,
    "lambda": 180
  }
}
```

---

### `POST /threat/api/v1/scan`

**Use**: Trigger threat analysis on latest check scan results

```bash
curl -X POST "$BASE/threat/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0"
  }'
```

```json
{
  "threat_scan_id": "threat_new-uuid-here",
  "scan_run_id": "new-uuid-here",
  "status": "running",
  "message": "Threat scan started"
}
```

---

---

# 6. Compliance Engine

**Prefix**: `/compliance` → stripped to bare path

---

### `GET /compliance/api/v1/health`

```bash
curl "$BASE/compliance/api/v1/health"
```
```json
{"status": "healthy", "database": "connected"}
```

---

### `GET /compliance/api/v1/compliance/reports`

**Use**: Compliance dashboard — list all generated compliance reports

```bash
curl "$BASE/compliance/api/v1/compliance/reports?tenant_id=$TENANT"
```

```json
{
  "total": 2,
  "source": "database",
  "reports": [
    {
      "report_id": "ab169d0d-62db-4d19-82db-1da97e0423f9",
      "compliance_scan_id": "ab169d0d-62db-4d19-82db-1da97e0423f9",
      "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
      "scan_id": "bfed9ebc-68e7-4f9d-83e1-24ce75e21d01",
      "csp": "aws",
      "started_at": "2026-02-15T16:49:14.291347+00:00",
      "completed_at": "2026-02-22T07:36:03.302345+00:00",
      "total_controls": 283,
      "controls_passed": 0,
      "controls_failed": 283,
      "total_findings": 3900,
      "generated_at": "2026-02-22T07:37:47.125102+00:00",
      "framework_ids": [
        "GDPR","HIPAA","FedRAMP","ISO27001","NIST_800-53",
        "CANADA_PBMM","CISA_CE","RBI_BANK","RBI_NBFC",
        "NIST_800-171","SOC2","CIS","PCI-DSS"
      ],
      "posture_summary": {
        "total_controls": 283,
        "total_findings": 3900,
        "controls_failed": 283,
        "controls_passed": 0,
        "findings_by_severity": {"low": 160, "high": 37, "medium": 3703}
      }
    }
  ]
}
```

---

### `GET /compliance/api/v1/compliance/report/{report_id}`

**Use**: Report detail page — full compliance report with all controls and findings

```bash
curl "$BASE/compliance/api/v1/compliance/report/ab169d0d-62db-4d19-82db-1da97e0423f9"
```

```json
{
  "report_id": "ab169d0d-62db-4d19-82db-1da97e0423f9",
  "compliance_scan_id": "ab169d0d-62db-4d19-82db-1da97e0423f9",
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "csp": "aws",
  "framework_ids": ["GDPR","HIPAA","FedRAMP","ISO27001","NIST_800-53","CANADA_PBMM","CISA_CE","RBI_BANK","RBI_NBFC","NIST_800-171","SOC2","CIS","PCI-DSS"],
  "total_controls": 283,
  "controls_passed": 0,
  "controls_failed": 283,
  "total_findings": 3900,
  "posture_score": 0,
  "controls": [
    {
      "control_id": "CIS-1.1",
      "framework": "CIS",
      "title": "Maintain a current inventory of all cloud resources",
      "status": "FAIL",
      "findings_count": 45,
      "severity": "high"
    }
    // ... 282 more controls
  ],
  "generated_at": "2026-02-22T07:37:47.125102+00:00"
}
```

---

### `GET /compliance/api/v1/compliance/frameworks`

**Use**: Framework selector / compliance overview page

```bash
curl "$BASE/compliance/api/v1/compliance/frameworks?tenant_id=$TENANT&csp=aws"
```

```json
{
  "total": 6,
  "frameworks": [
    {
      "framework_id": "CIS",
      "name": "CIS AWS Foundations Benchmark",
      "version": "2.0",
      "total_controls": 58,
      "applicable_controls": 45,
      "description": "Center for Internet Security AWS benchmark"
    },
    {
      "framework_id": "NIST_800-53",
      "name": "NIST SP 800-53 Rev 5",
      "total_controls": 110,
      "applicable_controls": 87
    },
    {
      "framework_id": "PCI-DSS",
      "name": "PCI Data Security Standard v4.0",
      "total_controls": 64,
      "applicable_controls": 52
    },
    {
      "framework_id": "HIPAA",
      "name": "Health Insurance Portability and Accountability Act",
      "total_controls": 45,
      "applicable_controls": 38
    },
    {
      "framework_id": "SOC2",
      "name": "Service Organization Control Type 2",
      "total_controls": 28,
      "applicable_controls": 24
    },
    {
      "framework_id": "GDPR",
      "name": "General Data Protection Regulation",
      "total_controls": 32,
      "applicable_controls": 37
    }
  ]
}
```

---

### `GET /compliance/api/v1/compliance/trends`

**Use**: Compliance trend chart — posture improvement/regression over time

```bash
curl "$BASE/compliance/api/v1/compliance/trends?tenant_id=$TENANT"
```

```json
{
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "data_points": [],
  "message": "Trend data requires at least 2 reports."
}
```

> Will populate after the second compliance report is generated.

---

### `GET /compliance/api/v1/compliance/framework/{framework_id}/status`

**Use**: Per-framework posture page — e.g. "CIS compliance score"

```bash
curl "$BASE/compliance/api/v1/compliance/framework/CIS/status?tenant_id=$TENANT"
```

> **Note**: This endpoint reads from scan output files. Returns 400/500 if the output file
> for the current scan hasn't been written. Use `GET /report/{id}` filtered by framework instead.

---

### `POST /compliance/api/v1/compliance/generate/from-threat-engine`

**Use**: "Generate Report" button — creates a new compliance report from the latest threat engine scan

```bash
curl -X POST "$BASE/compliance/api/v1/compliance/generate/from-threat-engine" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "csp": "aws",
    "framework": "CIS"
  }'
```

```json
{
  "compliance_scan_id": "new-uuid-here",
  "status": "running",
  "frameworks": ["CIS","NIST_800-53","PCI-DSS","HIPAA","SOC2","GDPR"],
  "message": "Compliance scan started — processing 3,900 findings"
}
```

---

---

# 7. IAM Security Engine

**Prefix**: `/iam` → stripped to bare path

> **Two equivalent route forms** (both work after v-uniform):
> `/iam/api/v1/iam-security/findings` = `/iam/api/v1/iam/findings`

---

### `GET /iam/health`

```bash
curl "$BASE/iam/health"
```
```json
{"status": "ok"}
```

---

### `GET /iam/api/v1/iam-security/findings`

**Use**: IAM findings table — all IAM security findings

```bash
curl "$BASE/iam/api/v1/iam-security/findings?csp=aws&scan_id=$THREAT_SCAN&tenant_id=$TENANT&limit=5"
```

```json
{
  "summary": {
    "total_findings": 825,
    "by_module": {
      "policy_analysis": 569,
      "least_privilege": 403,
      "role_management": 266,
      "password_policy": 65,
      "access_control": 40,
      "mfa": 4
    },
    "by_status": {"FAIL": 825}
  },
  "findings": [
    {
      "misconfig_finding_id": "fnd_e014a9733048e26c",
      "rule_id": "aws.iam.policy.expires_passwords_within_90_days_or_less_configured",
      "severity": "critical",
      "result": "FAIL",
      "service": "iam",
      "resource_type": "iam",
      "resource_uid": "iam:global:588989875114:unknown",
      "title": "IAM policy: Expires Passwords Within 90 Days Or Less Configured",
      "mitre_techniques": ["T1078","T1110","T1556","T1098","T1201"],
      "iam_security_modules": ["policy_analysis","password_policy"],
      "is_iam_relevant": true,
      "first_seen_at": "2026-02-15T16:49:35.685432+00:00"
    },
    {
      "misconfig_finding_id": "fnd_48a7dc245c860856",
      "rule_id": "aws.iam.resource.root_hardware_mfa_enabled",
      "severity": "critical",
      "result": "FAIL",
      "title": "IAM resource: Root Hardware MFA Enabled",
      "iam_security_modules": ["mfa"],
      "resource_uid": "iam:global:588989875114:root"
    }
    // 823 more findings
  ]
}
```

---

### `GET /iam/api/v1/iam-security/modules`

**Use**: Module selector / filter — show which IAM modules are active

```bash
curl "$BASE/iam/api/v1/iam-security/modules?csp=aws&scan_id=$THREAT_SCAN&tenant_id=$TENANT"
```

```json
{
  "modules": [
    "least_privilege",
    "policy_analysis",
    "mfa",
    "role_management",
    "password_policy",
    "access_control"
  ]
}
```

---

### `GET /iam/api/v1/iam-security/rule-ids`

**Use**: Rule browser — returns rule_id patterns grouped by module

```bash
curl "$BASE/iam/api/v1/iam-security/rule-ids?csp=aws&tenant_id=$TENANT"
```

```json
{
  "method": "pattern_based",
  "patterns": [
    {"module": "policy_analysis",  "pattern": "aws.iam.policy.*"},
    {"module": "least_privilege",  "pattern": "aws.iam.*.excessive_permissions*"},
    {"module": "mfa",              "pattern": "aws.iam.*.mfa*"},
    {"module": "role_management",  "pattern": "aws.iam.role.*"},
    {"module": "password_policy",  "pattern": "aws.iam.*.password*"},
    {"module": "access_control",   "pattern": "aws.iam.*.access*"}
  ]
}
```

---

### `GET /iam/api/v1/iam-security/rules/{rule_id}`

**Use**: Rule detail page — metadata for a specific IAM rule

```bash
curl "$BASE/iam/api/v1/iam-security/rules/aws.iam.policy.expires_passwords_within_90_days_or_less_configured?csp=aws&tenant_id=$TENANT"
```

```json
{
  "rule_id": "aws.iam.policy.expires_passwords_within_90_days_or_less_configured",
  "modules": ["policy_analysis", "password_policy"],
  "severity": "critical",
  "title": "IAM policy: Expires Passwords Within 90 Days Or Less Configured",
  "description": "Ensure the IAM password policy requires passwords to expire within 90 days",
  "remediation": "Enable MaxPasswordAge in the IAM account password policy",
  "compliance_frameworks": ["CIS-1.9", "NIST-IA-5", "PCI-DSS-8.3"]
}
```

---

### `GET /iam/api/v1/iam-security/accounts/{account_id}`

**Use**: Account IAM posture — all IAM findings for one AWS account

```bash
curl "$BASE/iam/api/v1/iam-security/accounts/588989875114?csp=aws&scan_id=$THREAT_SCAN&tenant_id=$TENANT"
```

```json
{
  "account_id": "588989875114",
  "total_findings": 812,
  "by_module": {
    "policy_analysis": 560,
    "least_privilege": 400,
    "role_management": 260,
    "password_policy": 65,
    "access_control": 40,
    "mfa": 3
  },
  "findings": [
    // same shape as /findings response
  ]
}
```

> **Note**: 812 of 825 findings have real account ID (588989875114).
> The remaining 13 are account-global (root MFA, password policy) — they use tenant UUID.

---

### `GET /iam/api/v1/iam-security/services/{service}`

**Use**: Service-level IAM view — findings for a specific service (e.g., `iam`, `s3`, `ec2`)

```bash
curl "$BASE/iam/api/v1/iam-security/services/iam?csp=aws&scan_id=$THREAT_SCAN&tenant_id=$TENANT"
```

```json
{
  "service": "iam",
  "total_findings": 825,
  "findings": [
    // all 825 IAM findings (IAM service dominates)
  ]
}
```

---

### `GET /iam/api/v1/iam-security/resources/{resource_uid}`

**Use**: Resource drilldown — all IAM findings for a specific resource (IAM role, user, policy)

```bash
# URL-encode the ARN
curl "$BASE/iam/api/v1/iam-security/resources/arn%3Aaws%3Aiam%3A%3A588989875114%3Arole%2FAdminRole?csp=aws&tenant_id=$TENANT"
```

```json
{
  "resource_uid": "arn:aws:iam::588989875114:role/AdminRole",
  "resource_type": "iam.role",
  "total_findings": 8,
  "findings": [
    {
      "rule_id": "aws.iam.role.admin_access_restricted",
      "severity": "critical",
      "title": "IAM Role: Admin Access Policy Attached",
      "result": "FAIL"
    }
  ]
}
```

---

### `POST /iam/api/v1/scan`

**Use**: Trigger IAM security analysis

```bash
curl -X POST "$BASE/iam/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "csp": "aws"
  }'
```

```json
{
  "iam_scan_id": "new-uuid-here",
  "status": "running",
  "message": "IAM security scan started"
}
```

---

---

# 8. Data Security Engine

**Prefix**: `/datasec` → stripped to bare path

> **Two equivalent route forms**:
> `/datasec/api/v1/data-security/findings` = `/datasec/api/v1/datasec/findings`
>
> **Required params on all GET endpoints**: `csp=aws` and `scan_id=<SCAN_RUN_ID>`
> (defaults to `aws` and `latest` after v-uniform, but explicit is safer)

---

### `GET /datasec/health`

```bash
curl "$BASE/datasec/health"
```
```json
{"status": "ok"}
```

---

### `GET /datasec/api/v1/data-security/catalog`

**Use**: Data store inventory — all catalogued data storage resources (S3 buckets, RDS, etc.)

```bash
curl "$BASE/datasec/api/v1/data-security/catalog?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "total_stores": 21,
  "filters": {"account_id": null, "service": null, "region": null},
  "stores": [
    {"resource_arn": "arn:aws:s3:::aiwebsite01",                        "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::anup-backup",                        "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::cloudtrail-test-d736bbca",           "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::cspm-lgtech",                        "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::dynamodb-backup-20251128-105848",     "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::lgtech-website",                     "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::my-bucket-x2nc4n2t",                 "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::vulnerabiliy-dump",                  "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::www.lgtech.in",                      "resource_type": "s3", "service": "s3", "region": "global"}
    // ... 12 more S3 buckets
  ]
}
```

---

### `GET /datasec/api/v1/data-security/findings`

**Use**: Data security findings table — all security issues across all data stores

```bash
curl "$BASE/datasec/api/v1/data-security/findings?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT&limit=3"
```

```json
{
  "summary": {
    "total_findings": 3900,
    "by_module": {
      "data_protection_encryption": 229,
      "data_access_control": 353,
      "data_logging_monitoring": 63,
      "data_backup_recovery": 172,
      "data_lifecycle": 77,
      "data_classification": 42
    },
    "by_status": {"FAIL": 3900}
  },
  "findings": [
    {
      "misconfig_finding_id": "fnd_e014a9733048e26c",
      "rule_id": "aws.iam.policy.expires_passwords_within_90_days_or_less_configured",
      "severity": "critical",
      "result": "FAIL",
      "title": "IAM policy: Expires Passwords Within 90 Days Or Less Configured",
      "data_security_modules": ["policy_analysis"],
      "is_data_security_relevant": true,
      "resource_type": "iam",
      "resource_uid": "iam:global:588989875114:unknown"
    }
  ]
}
```

---

### `GET /datasec/api/v1/data-security/modules`

**Use**: Module summary — overview of each data security module's finding counts

```bash
curl "$BASE/datasec/api/v1/data-security/modules?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "modules": [
    {"name": "data_protection_encryption", "total_findings": 229, "severity_breakdown": {"critical": 45, "high": 184}},
    {"name": "data_access_control",         "total_findings": 353, "severity_breakdown": {"critical": 89, "high": 264}},
    {"name": "data_logging_monitoring",     "total_findings": 63,  "severity_breakdown": {"medium": 63}},
    {"name": "data_backup_recovery",        "total_findings": 172, "severity_breakdown": {"high": 120, "medium": 52}},
    {"name": "data_lifecycle",              "total_findings": 77,  "severity_breakdown": {"low": 77}},
    {"name": "data_classification",         "total_findings": 42,  "severity_breakdown": {"medium": 42}}
  ]
}
```

---

### `GET /datasec/api/v1/data-security/classification`

**Use**: Data classification results — which resources contain sensitive data categories (PII, PCI, PHI)

```bash
curl "$BASE/datasec/api/v1/data-security/classification?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "total_resources": 21,
  "classified_resources": 0,
  "results": []
}
```

> **Note**: Classification enrichment is in progress. Data will populate in a future scan.

---

### `GET /datasec/api/v1/data-security/residency`

**Use**: Data residency map — where each data store is physically located

```bash
curl "$BASE/datasec/api/v1/data-security/residency?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "total_stores": 21,
  "stores": [
    {"resource_arn": "arn:aws:s3:::cspm-lgtech",    "region": "global", "country": "global", "data_residency": "global"},
    {"resource_arn": "arn:aws:s3:::lgtech-website",  "region": "global", "country": "global", "data_residency": "global"}
    // ... 19 more stores (all S3 → global)
  ]
}
```

---

### `GET /datasec/api/v1/data-security/lineage`

**Use**: Data lineage — trace data movement/copying between stores

```bash
curl "$BASE/datasec/api/v1/data-security/lineage?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "total_stores": 21,
  "stores_with_lineage": 0,
  "lineage_chains": []
}
```

> Lineage requires cross-service event tracking. Will populate when CloudTrail ingestion is added.

---

### `GET /datasec/api/v1/data-security/activity`

**Use**: Data access activity — recent read/write/delete events on data stores

```bash
curl "$BASE/datasec/api/v1/data-security/activity?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "events": [],
  "total": 0,
  "message": "Activity tracking requires CloudTrail event ingestion"
}
```

---

### `GET /datasec/api/v1/data-security/compliance`

**Use**: Data-specific compliance posture (GDPR, HIPAA data protection requirements)

```bash
curl "$BASE/datasec/api/v1/data-security/compliance?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "total_findings": 0,
  "by_framework": {},
  "message": "Data compliance enrichment pending — 0 findings tagged with data_compliance module"
}
```

> Known gap: compliance module enrichment for data security is not yet running.
> Use the main Compliance Engine for framework posture scores.

---

### `GET /datasec/api/v1/data-security/accounts/{account_id}`

**Use**: Account-level data security posture — all findings for one account

```bash
curl "$BASE/datasec/api/v1/data-security/accounts/588989875114?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "account_id": "588989875114",
  "total_findings": 3056,
  "findings": [
    // same shape as /findings
  ]
}
```

---

### `GET /datasec/api/v1/data-security/services/{service}`

**Use**: Service-specific data security — findings per data service (s3, rds, dynamodb, etc.)

```bash
curl "$BASE/datasec/api/v1/data-security/services/s3?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "service": "s3",
  "total_resources": 21,
  "total_findings": 754,
  "findings": [
    {
      "misconfig_finding_id": "fnd_a1b2c3d4e5f6a7b8",
      "rule_id": "aws.s3.bucket.public_access_blocked",
      "severity": "critical",
      "title": "S3 Bucket Public Access Block Not Enabled",
      "resource_uid": "arn:aws:s3:::cspm-lgtech",
      "resource_type": "s3",
      "data_security_modules": ["data_access_control"]
    }
    // ... 753 more
  ]
}
```

---

### `GET /datasec/api/v1/data-security/protection/{resource_id}`

**Use**: Per-resource protection dashboard — all findings for one specific data store

```bash
# URL-encode the ARN
curl "$BASE/datasec/api/v1/data-security/protection/arn%3Aaws%3As3%3A%3A%3Acspm-lgtech?csp=aws&scan_id=$SCAN_RUN&tenant_id=$TENANT"
```

```json
{
  "resource_id": "arn:aws:s3:::cspm-lgtech",
  "resource_type": "s3",
  "service": "s3",
  "total_findings": 13,
  "by_module": {
    "data_access_control": 6,
    "data_protection_encryption": 4,
    "data_logging_monitoring": 2,
    "data_backup_recovery": 1
  },
  "findings": [
    {
      "rule_id": "aws.s3.bucket.public_access_blocked",
      "severity": "critical",
      "title": "S3 Bucket Public Access Block Not Enabled",
      "result": "FAIL"
    },
    {
      "rule_id": "aws.s3.bucket.server_side_encryption_enabled",
      "severity": "high",
      "title": "S3 Bucket Server-Side Encryption Not Enabled",
      "result": "FAIL"
    }
    // ... 11 more findings
  ]
}
```

---

### `GET /datasec/api/v1/data-security/governance/{resource_id}`

**Use**: Resource governance view — policy attachments, access controls, lifecycle policies

```bash
curl "$BASE/datasec/api/v1/data-security/governance/arn%3Aaws%3As3%3A%3A%3Acspm-lgtech?csp=aws&tenant_id=$TENANT"
```

```json
{
  "resource_id": "arn:aws:s3:::cspm-lgtech",
  "governance": {
    "bucket_policy": null,
    "acl": "private",
    "versioning": "Suspended",
    "lifecycle_rules": [],
    "replication": null,
    "object_lock": null
  }
}
```

---

### `POST /datasec/api/v1/scan`

**Use**: Trigger data security analysis

```bash
curl -X POST "$BASE/datasec/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "orchestration_id": "337a7425-5a53-4664-8569-04c1f0d6abf0",
    "csp": "aws"
  }'
```

```json
{
  "datasec_scan_id": "new-uuid-here",
  "status": "running",
  "message": "Data security scan started"
}
```

---

---

# 9. SecOps Engine (IaC Scanner)

**Prefix**: `/secops` → stripped to bare path

---

### `GET /secops/health`

```bash
curl "$BASE/secops/health"
```
```json
{"status": "ok"}
```

---

### `GET /secops/api/v1/secops/rules/stats`

**Use**: Rules overview — show how many rules are loaded by language/severity

```bash
curl "$BASE/secops/api/v1/secops/rules/stats"
```

```json
{
  "total_rules": 2454,
  "by_scanner": {
    "java": 712,
    "csharp": 416,
    "python": 340,
    "c": 313,
    "javascript": 293,
    "cpp": 148,
    "go": 70,
    "terraform": 52,
    "docker": 33,
    "cloudformation": 26,
    "azure": 25,
    "kubernetes": 11,
    "ansible": 10,
    "ruby": 5
  },
  "by_severity": {
    "high": 1670,
    "low": 525,
    "medium": 157,
    "critical": 102
  }
}
```

---

### `GET /secops/api/v1/secops/rules`

**Use**: Rule library browser — list all IaC security rules

```bash
curl "$BASE/secops/api/v1/secops/rules?tenant_id=$TENANT&limit=5&scanner=terraform"
```

```json
{
  "total": 52,
  "rules": [
    {
      "rule_id": "TF001",
      "scanner": "terraform",
      "title": "Terraform: S3 Bucket ACL Should Be Private",
      "severity": "high",
      "description": "Ensure S3 bucket ACL is not set to public-read or public-read-write"
    },
    {
      "rule_id": "TF002",
      "scanner": "terraform",
      "title": "Terraform: Security Group Should Not Allow 0.0.0.0/0 Ingress",
      "severity": "critical"
    }
  ]
}
```

---

### `GET /secops/api/v1/secops/scans`

**Use**: Scan history — list all past IaC scans

```bash
curl "$BASE/secops/api/v1/secops/scans?tenant_id=$TENANT"
```

```json
{
  "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
  "total": 0,
  "scans": []
}
```

> Returns empty until a code repository is scanned. Trigger a scan first.

---

### `GET /secops/api/v1/secops/scan/{scan_id}/status`

**Use**: Poll scan progress

```bash
curl "$BASE/secops/api/v1/secops/scan/<scan_id>/status?tenant_id=$TENANT"
```

```json
{
  "scan_id": "<uuid>",
  "status": "running",
  "files_scanned": 45,
  "findings_count": 12
}
```

---

### `POST /secops/api/v1/secops/scan`

**Use**: "Scan Repository" button — scan IaC code for security misconfigurations

```bash
# Scan a Terraform directory
curl -X POST "$BASE/secops/api/v1/secops/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "scan_type": "terraform",
    "scan_path": "/path/to/terraform/modules",
    "repository_url": "https://github.com/org/infra-repo",
    "branch": "main"
  }'

# Scan a Dockerfile
curl -X POST "$BASE/secops/api/v1/secops/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "scan_type": "docker",
    "scan_path": "/path/to/Dockerfile"
  }'
```

```json
{
  "scan_id": "secops-new-uuid-here",
  "status": "running",
  "scan_type": "terraform",
  "message": "SecOps scan started — 52 Terraform rules active"
}
```

---

---

# Scan Pipeline — Full End-to-End Sequence

Run all engines in order to produce a complete security posture snapshot:

```bash
BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
ORCH=337a7425-5a53-4664-8569-04c1f0d6abf0

# ─── Step 1: Discovery (enumerates all AWS resources) ────────────────────────
DISC_ID=$(curl -s -X POST "$BASE/discoveries/api/v1/discovery" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\",\"provider\":\"aws\",\"hierarchy_id\":\"588989875114\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
echo "Discovery started: $DISC_ID"

# Poll until complete (takes 3–4 hours for full scan)
while true; do
  STATUS=$(curl -s "$BASE/discoveries/api/v1/discovery/$DISC_ID" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "Discovery: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 30
done

# ─── Step 2: Check (evaluate all security rules) ──────────────────────────────
CHECK_ID=$(curl -s -X POST "$BASE/check/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\",\"provider\":\"aws\",\"hierarchy_id\":\"588989875114\"}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['check_scan_id'])")
echo "Check scan started: $CHECK_ID"

# ─── Step 3: Inventory (normalise resources into asset catalog) ───────────────
curl -s -X POST "$BASE/inventory/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\"}"

# ─── Step 4: Parallel analysis (run all at once) ─────────────────────────────
# Threat
curl -s -X POST "$BASE/threat/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\"}" &

# Compliance
curl -s -X POST "$BASE/compliance/api/v1/compliance/generate/from-threat-engine" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\",\"csp\":\"aws\"}" &

# IAM
curl -s -X POST "$BASE/iam/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\",\"csp\":\"aws\"}" &

# DataSec
curl -s -X POST "$BASE/datasec/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d "{\"orchestration_id\":\"$ORCH\",\"csp\":\"aws\"}" &

wait
echo "All analysis engines complete"
```

---

---

# Quick Reference

## Engine health check (all engines)

```bash
BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
for engine in onboarding discoveries check inventory compliance threat iam datasec secops; do
  echo -n "$engine: "
  curl -s "$BASE/$engine/health" || curl -s "$BASE/$engine/api/v1/health"
  echo
done
```

## Common query parameters

| Param | Required by | Value |
|-------|-------------|-------|
| `tenant_id` | all engines | `5a8b072b-8867-4476-a52f-f331b1cbacb3` |
| `scan_id` | iam, datasec | `threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01` |
| `scan_run_id` | threat | `bfed9ebc-68e7-4f9d-83e1-24ce75e21d01` |
| `csp` | iam, datasec | `aws` |
| `account_id` | inventory, iam, datasec | `588989875114` |
| `account_ids` | inventory | `588989875114` (comma-separated for multi) |
| `limit` | all engines | `10`, `50`, `100` (default 100) |
| `offset` | all engines | `0`, `100`, `200`... |
| `region` | inventory, threat | `ap-south-1`, `us-east-1`... |
| `severity` | threat, iam, datasec | `critical`, `high`, `medium`, `low` |
| `resource_type` | inventory | `s3.bucket`, `iam.role`, `ec2.instance`... |

## Known endpoint limitations

| Endpoint | Status | Reason |
|----------|--------|--------|
| `GET /compliance/api/v1/compliance/framework/{fw}/status` | Partial | File-based; use `/report/{id}` instead |
| `GET /datasec/api/v1/data-security/classification` | Empty | Enricher not yet tagging resources |
| `GET /datasec/api/v1/data-security/compliance` | Empty | Compliance module enrichment pending |
| `GET /datasec/api/v1/data-security/activity` | Empty | Requires CloudTrail event ingestion |
| `GET /threat/api/v1/threat/analytics/trend` | Empty | Requires 2+ scans |
| `GET /compliance/api/v1/compliance/trends` | Empty | Requires 2+ reports |
| `GET /inventory/api/v1/inventory/drift` | Empty | Requires 2+ inventory scans |
| `GET /check/api/v1/checks` | Empty when idle | Returns 0 when no scan running |
| `GET /secops/api/v1/secops/scans` | Empty | No IaC scans triggered yet |
