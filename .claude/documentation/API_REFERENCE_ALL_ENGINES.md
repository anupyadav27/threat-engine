# Threat Engine — Complete API Reference (All Engines)

> **Last tested:** 2026-02-28
> **ELB:** `http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com`
> **Cluster:** `vulnerability-eks-cluster` | **Region:** `ap-south-1` | **Account:** `588989875114`
> **Live tenant with data:** `test-tenant` | **Live inventory scan:** `aa9c7896-bf57-4d7c-9df3-23b293c0d64c`
>
> All sample requests and responses on this page use **real data from live tests** unless explicitly marked `[example]`.
> See `docs/API_UNIFORMITY.md` for the full inconsistency analysis and migration plan.

---

## Quick Reference — All Engines

| Engine | ELB Path Prefix | ClusterIP | Container Port | Health Path |
|--------|----------------|-----------|----------------|-------------|
| api-gateway | `/gateway/` | 10.100.209.181 | 8080 | `/gateway/health` |
| engine-onboarding | `/onboarding/` | 10.100.138.231 | 8010 | `/api/v1/health` |
| engine-discoveries | `/discoveries/` | 10.100.188.200 | 8001 | `/health` |
| engine-check | `/check/` | 10.100.43.124 | 8002 | `/api/v1/health` |
| engine-inventory | `/inventory/` | 10.100.246.103 | 8022 | `/health` |
| engine-compliance | `/compliance/` | 10.100.48.135 | 8000 | `/api/v1/health` |
| engine-threat | `/threat/` | 10.100.60.108 | 8020 | `/health` |
| engine-iam | `/iam/` | 10.100.170.233 | 8001 | `/health` |
| engine-datasec | `/datasec/` | 10.100.155.216 | 8003 | `/health` |
| engine-secops | `/secops/` | 10.100.192.50 | 8005 | `/health` |
| engine-rule | _(no ingress)_ | 10.100.88.168 | 8011 | `/api/v1/health` |

**All ClusterIP services expose port 80** (mapped to the container port above).

---

## Access URL Patterns

### External — UI / API clients

```
http://<ELB>/<engine-prefix><engine-path>
```

Examples:
```
GET http://<ELB>/onboarding/api/v1/health
GET http://<ELB>/inventory/api/v1/inventory/assets?tenant_id=test-tenant
POST http://<ELB>/discoveries/api/v1/discovery
```

### Internal — engine-to-engine calls (same namespace)

```
http://<service-name>:80<engine-path>
# e.g.
http://engine-inventory:80/api/v1/inventory/assets
```

---

## Common Patterns

### Universal Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `tenant_id` | string | Required on almost all query endpoints. Isolates data per tenant. |
| `account_id` | string | Filter by a single cloud account (e.g. `588989875114`) |
| `account_ids` | string | Comma-separated list for multi-account queries |
| `limit` | integer | Page size (default varies per engine, usually 100) |
| `offset` | integer | Pagination offset (0-based) |
| `provider` | string | Cloud provider: `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm` |

### Pagination Response Shape

All paginated endpoints return:
```json
{
  "items_key": [...],
  "total": 274,
  "limit": 10,
  "offset": 0,
  "has_more": true
}
```

### Scan Pipeline Identifiers

| Identifier | Set by | Read by |
|------------|--------|---------|
| `orchestration_id` | Onboarding (scan_orchestration table) | All engines |
| `discovery_scan_id` | Discoveries engine | Check, Inventory |
| `check_scan_id` | Check engine | Compliance, Threat, IAM, DataSec |
| `inventory_scan_id` | Inventory engine | Frontend queries |
| `compliance_scan_id` | Compliance engine | Frontend queries |
| `threat_scan_id` | Threat engine | Frontend queries |

---

## API INCONSISTENCIES WARNING

The following differences exist across engines. Frontend code must handle these case-by-case.
See `docs/API_UNIFORMITY.md` for the full analysis and migration plan.

### 1. Health endpoint paths differ

| Pattern | Engines |
|---------|---------|
| `/api/v1/health` | onboarding, check, compliance, rule |
| `/health` | discoveries, inventory, threat, iam, datasec, secops |

Some engines additionally expose `/api/v1/health/live` and `/api/v1/health/ready` (discoveries, iam, datasec).

### 2. IAM and DataSec require `csp` and `scan_id` as mandatory query params

Engines: `engine-iam`, `engine-datasec`

These two engines require `csp` (e.g. `aws`) and `scan_id` (or use the literal string `latest`) on all
finding/query endpoints. Other engines do not require this.

```
# REQUIRED for IAM/DataSec:
GET /iam/api/v1/iam-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest
GET /datasec/api/v1/data-security/modules?tenant_id=test-tenant&csp=aws&scan_id=latest
```

### 3. Threat engine requires `scan_run_id` on some endpoints but not others

Some threat endpoints require `scan_run_id`, others do not. See the Threat Engine section for the full list.

```
# DOES NOT require scan_run_id:
GET /threat/api/v1/threat/analytics/correlation?tenant_id=test-tenant
GET /threat/api/v1/checks/dashboard?tenant_id=test-tenant

# REQUIRES scan_run_id:
GET /threat/api/v1/threat/summary?tenant_id=test-tenant&scan_run_id=<id>
GET /threat/api/v1/threat/analytics/distribution?tenant_id=test-tenant&scan_run_id=<id>
```

### 4. Inventory engine has two scan trigger routes

The legacy `/api/v1/scan` and the recommended pipeline route `/api/v1/inventory/scan/discovery`.
Use the pipeline route for all new integrations.

### 5. SecOps engine has legacy routes without `/api/v1/` prefix

`POST /scan` and `GET /results/{project_name}` are legacy. Use `/api/v1/secops/...` routes.

---

## 1. Engine Onboarding

**Purpose:** Multi-cloud account registration, credential management, and scan scheduling.
Manages the `cloud_accounts` table and writes to `scan_orchestration`.

**Supported providers:** `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`

**External:** `http://<ELB>/onboarding/...`
**Internal:** `http://engine-onboarding:80/...`
**Database:** `threat_engine_onboarding`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/api/v1/health` | Health + DB status | — |
| GET | `/api/v1/health/live` | K8s liveness (no DB) | — |
| GET | `/api/v1/health/ready` | K8s readiness (DB ping) | — |
| POST | `/api/v1/cloud-accounts` | Step 1 — Register account record | body |
| GET | `/api/v1/cloud-accounts` | List cloud accounts | optional: `tenant_id`, `provider`, `status` |
| GET | `/api/v1/cloud-accounts/{account_id}` | Get account details | `account_id` |
| PATCH | `/api/v1/cloud-accounts/{account_id}` | Update account config | `account_id` |
| DELETE | `/api/v1/cloud-accounts/{account_id}` | Soft-delete account | `account_id` |
| POST | `/api/v1/accounts/{account_id}/credentials` | Step 2 — Store & validate credentials | `account_id`, body |
| GET | `/api/v1/accounts/{account_id}/credentials/validate` | Re-validate stored credentials | `account_id` |
| DELETE | `/api/v1/accounts/{account_id}/credentials` | Remove credentials from Secrets Manager | `account_id` |
| GET | `/api/v1/cloud-accounts/{account_id}/status` | Lightweight status summary | `account_id` |
| POST | `/api/v1/cloud-accounts/{account_id}/validate-credentials` | Re-validate (returns full detail) | `account_id` |
| POST | `/api/v1/cloud-accounts/{account_id}/validate` | Step 3 — Set schedule + activate | `account_id`, body |

### Health Check

**Request:**
```
GET http://<ELB>/onboarding/api/v1/health
```

**Response (200):**
```json
{
  "status": "healthy",
  "database": "connected",
  "database_details": {
    "status": "connected",
    "database": "threat_engine_onboarding",
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "version": "PostgreSQL 15.12 on x86_64-pc-linux-gnu",
    "using": "local_database_config"
  },
  "secrets_manager": "disconnected (optional)",
  "version": "1.0.0",
  "service": "onboarding"
}
```

### List Cloud Accounts

**Request:**
```
GET http://<ELB>/onboarding/api/v1/cloud-accounts
```

**Response (200):**
```json
{
  "accounts": [
    {
      "account_id": "test-215908",
      "customer_id": "local-test",
      "customer_email": "test@local.dev",
      "tenant_id": "local",
      "tenant_name": "Local Test",
      "account_name": "GCP Project test-215908",
      "account_number": "test-215908",
      "provider": "gcp",
      "credential_type": "gcp_service_account",
      "credential_ref": "threat-engine/account/test-215908",
      "account_status": "active",
      "account_onboarding_status": "validated",
      "schedule_cron_expression": "0 * * * *",
      "schedule_timezone": "UTC",
      "schedule_include_services": ["iam", "compute", "bigquery", "storage"],
      "schedule_include_regions": [],
      "schedule_engines_requested": ["discovery"],
      "schedule_enabled": true,
      "schedule_status": "active",
      "schedule_next_run_at": "2026-02-22T08:00:00+00:00",
      "schedule_run_count": 0,
      "credential_validation_status": "valid",
      "credential_validation_message": "Service account validated successfully",
      "credential_validated_at": "2026-02-22T07:40:24.756253+00:00",
      "credential_validation_errors": [],
      "created_at": "2026-02-17T13:46:31.361819+00:00",
      "updated_at": "2026-02-22T07:40:24.789590+00:00"
    }
  ]
}
```

### Get Single Account

**Request:**
```
GET http://<ELB>/onboarding/api/v1/cloud-accounts/588989875114
```

**Response (200):**
```json
{
  "account_id": "588989875114",
  "customer_id": "test-customer-002",
  "customer_email": "anup@example.com",
  "tenant_id": "test-tenant-002",
  "tenant_name": "Production Tenant",
  "account_name": "AWS Production Account",
  "provider": "aws",
  "credential_type": "access_key",
  "credential_ref": "threat-engine/account/588989875114",
  "account_status": "pending",
  "account_onboarding_status": "deployed",
  "schedule_engines_requested": ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"],
  "schedule_enabled": true,
  "schedule_status": "active"
}
```

### 3-Step Onboarding Flow

#### Step 1 — Register Account

**Request:**
```
POST http://<ELB>/onboarding/api/v1/cloud-accounts
Content-Type: application/json
```

```json
{
  "account_id": "123456789012",
  "tenant_id": "my-tenant",
  "tenant_name": "My Org",
  "customer_id": "cust-001",
  "customer_email": "admin@example.com",
  "account_name": "AWS Dev Account",
  "provider": "aws",
  "regions": ["ap-south-1", "us-east-1"]
}
```

**Response (201):** Returns created account object with `account_status: "pending"`.

---

#### Step 2 — Store & Validate Credentials

**Request:**
```
POST http://<ELB>/onboarding/api/v1/accounts/{account_id}/credentials
Content-Type: application/json
```

Credentials are validated live against the CSP API **before** being stored in Secrets Manager.
Returns `400` if invalid. Returns `200 {"status":"stored"}` on success.

**Per-CSP request bodies:**

| CSP | `credential_type` | Required fields in `credentials` |
|-----|-------------------|-----------------------------------|
| AWS Access Key | `aws_access_key` | `aws_access_key_id`, `aws_secret_access_key` |
| AWS IAM Role | `aws_iam_role` | `role_arn`, `external_id`, `account_number` |
| Azure | `azure_service_principal` | `client_id`, `client_secret`, `tenant_id`, `subscription_id` |
| GCP | `gcp_service_account` | `service_account_json` (full JSON object or string) |
| IBM | `ibm_api_key` | `api_key` |
| OCI | `oci_user_principal` | `user_ocid`, `tenancy_ocid`, `fingerprint`, `private_key` (PEM), `region` |
| AliCloud | `alicloud_access_key` | `access_key_id`, `access_key_secret` |

**Example — AWS Access Key:**
```json
{
  "credential_type": "aws_access_key",
  "credentials": {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}
```

**Example — Azure Service Principal:**
```json
{
  "credential_type": "azure_service_principal",
  "credentials": {
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "your-client-secret",
    "tenant_id": "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy",
    "subscription_id": "zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
  }
}
```

**Example — GCP Service Account:**
```json
{
  "credential_type": "gcp_service_account",
  "credentials": {
    "service_account_json": {
      "type": "service_account",
      "project_id": "my-gcp-project",
      "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
      "client_email": "scanner@my-gcp-project.iam.gserviceaccount.com"
    }
  }
}
```

**Example — IBM API Key:**
```json
{
  "credential_type": "ibm_api_key",
  "credentials": { "api_key": "your-ibm-cloud-api-key" }
}
```

**Example — OCI User Principal:**
```json
{
  "credential_type": "oci_user_principal",
  "credentials": {
    "user_ocid": "ocid1.user.oc1..aaaaaaaa...",
    "tenancy_ocid": "ocid1.tenancy.oc1..aaaaaaaa...",
    "fingerprint": "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...",
    "region": "us-ashburn-1"
  }
}
```

**Example — AliCloud Access Key:**
```json
{
  "credential_type": "alicloud_access_key",
  "credentials": {
    "access_key_id": "LTAI5tExampleKey",
    "access_key_secret": "ExampleSecret"
  }
}
```

**Success response (200):**
```json
{ "status": "stored", "account_id": "123456789012" }
```

**Error response (400):**
```json
{
  "detail": {
    "message": "AWS Error (InvalidClientTokenId): The security token included in the request is invalid.",
    "errors": ["..."]
  }
}
```

After success, `cloud_accounts` is updated:
- `credential_validation_status` → `"valid"`
- `account_onboarding_status` → `"deployed"`
- `account_number` populated from CSP identity response
- `credential_ref` → `"threat-engine/account/<account_id>"`

---

#### Step 3 — Set Schedule + Activate

**Request:**
```
POST http://<ELB>/onboarding/api/v1/cloud-accounts/{account_id}/validate
Content-Type: application/json
```

```json
{
  "cron_expression": "0 2 * * *",
  "include_regions": ["ap-south-1", "us-east-1"],
  "engines_requested": ["discovery", "check", "inventory", "threat", "compliance", "iam", "datasec"]
}
```

**Response (200):** Returns full updated account with `account_status: "active"`, `account_onboarding_status: "validated"`, and `schedule_next_run_at` calculated.

---

### Notes

- `account_id` = cloud provider identifier (AWS account number, GCP project ID, Azure subscription ID, etc.).
- Credentials stored at Secrets Manager path: `threat-engine/account/<account_id>`.
- `schedule_engines_requested` controls which pipeline stages run on the cron.
- `POST /validate-credentials` (no body) re-runs validation against live CSP API using stored credentials.

---

## 2. Engine Discoveries

**Purpose:** Enumerate cloud resources across 40+ AWS services and write raw findings to the discoveries DB.

**Supported providers:** `aws` (primary), multi-cloud in progress

**External:** `http://<ELB>/discoveries/...`
**Internal:** `http://engine-discoveries:80/...`
**Database:** `discoveries`
**Current image:** `yadavanup84/engine-discoveries:v5-final`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Liveness check | — |
| GET | `/api/v1/health/live` | Kubernetes liveness probe | — |
| GET | `/api/v1/health/ready` | Kubernetes readiness probe | — |
| GET | `/metrics` | Prometheus metrics | — |
| POST | `/api/v1/discovery` | Trigger a cloud discovery scan | body (see below) |
| GET | `/api/v1/discovery/{scan_id}` | Get discovery scan status | `scan_id` |

### Health Check

**Request:**
```
GET http://<ELB>/discoveries/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### Trigger Discovery Scan

**Request:**
```
POST http://<ELB>/discoveries/api/v1/discovery
Content-Type: application/json
```

```json
{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "tenant_id": "test-tenant"
}
```

**Response (202 Accepted):**
```json
{
  "scan_id": "7e3c4d2a-bf91-4f2e-9abc-123456789abc",
  "status": "started",
  "message": "Discovery scan initiated for aws account 588989875114"
}
```

### Get Discovery Scan Status

**Request:**
```
GET http://<ELB>/discoveries/api/v1/discovery/7e3c4d2a-bf91-4f2e-9abc-123456789abc
```

**Response (200):** [example]
```json
{
  "scan_id": "7e3c4d2a-bf91-4f2e-9abc-123456789abc",
  "status": "completed",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "started_at": "2026-02-21T17:00:00.000Z",
  "completed_at": "2026-02-21T17:17:00.000Z",
  "services_scanned": 38,
  "findings_count": 1240
}
```

### Notes

- `hierarchy_id` is the cloud account identifier (AWS account number, GCP project ID, etc.).
- The scan writes a `discovery_scan_id` back to the `scan_orchestration` table when complete.
- Scan speed is approximately 2.2 services/minute (~3-4 hours for a full 414-service AWS scan).
- Performance is controlled by environment variables: `BOTO_READ_TIMEOUT=10`, `BOTO_MAX_ATTEMPTS=2`, `DB_POOL_MIN=5`, `DB_POOL_MAX=60`.

---

## 3. Engine Check

**Purpose:** Evaluate cloud resources against YAML rule definitions. Produces PASS/FAIL findings
stored in the `threat_engine_check` database.

**Supported providers:** `aws`

**External:** `http://<ELB>/check/...`
**Internal:** `http://engine-check:80/...`
**Database:** `threat_engine_check`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/api/v1/health` | Health check | — |
| GET | `/api/v1/metrics` | Prometheus metrics | — |
| GET | `/api/v1/providers` | List supported providers | — |
| POST | `/api/v1/scan` | Trigger compliance check scan | body (see below) |
| GET | `/api/v1/checks` | List check scans | `tenant_id` |
| GET | `/api/v1/check/{check_scan_id}/status` | Get scan status | `check_scan_id` |

### Health Check

**Request:**
```
GET http://<ELB>/check/api/v1/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### List Supported Providers

**Request:**
```
GET http://<ELB>/check/api/v1/providers
```

**Response (200):**
```json
{
  "providers": ["aws"]
}
```

### List Check Scans

**Request:**
```
GET http://<ELB>/check/api/v1/checks?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "scans": [],
  "total": 0
}
```

### Trigger Check Scan

**Request:**
```
POST http://<ELB>/check/api/v1/scan
Content-Type: application/json
```

```json
{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant"
}
```

**Response (202):** [example]
```json
{
  "check_scan_id": "9f2a1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "started",
  "message": "Check scan initiated"
}
```

### Get Scan Status

**Request:**
```
GET http://<ELB>/check/api/v1/check/9f2a1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c/status
```

**Response (200):** [example]
```json
{
  "check_scan_id": "9f2a1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "completed",
  "total_checks": 1840,
  "passed": 1200,
  "failed": 640,
  "pass_rate": 65.2
}
```

### Notes

- The check engine reads discovery findings from the `discoveries` DB and evaluates them against rules stored in `rule_discoveries`.
- The `orchestration_id` mode reads the `discovery_scan_id` from `scan_orchestration` automatically.
- Results are written to `check_findings` table in the `threat_engine_check` database.

---

## 4. Engine Inventory

**Purpose:** Normalize discovery findings into structured assets and relationships. Provides
asset graph queries, drift detection, and account/service summaries.

**Supported providers:** `aws`, `azure`, `gcp`, `oci`, `alicloud`, `ibm`

**External:** `http://<ELB>/inventory/...`
**Internal:** `http://engine-inventory:80/...`
**Database:** `threat_engine_inventory`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Health check | — |
| POST | `/api/v1/inventory/scan/discovery` | Trigger inventory scan (pipeline mode, recommended) | `tenant_id`, `orchestration_id` OR `discovery_scan_id` |
| POST | `/api/v1/inventory/scan/discovery/async` | Async inventory scan, returns `job_id` | same as above |
| POST | `/api/v1/inventory/scan/async` | Alternative async trigger | `tenant_id` |
| POST | `/api/v1/scan` | Legacy sync scan trigger | `tenant_id`, `scan_run_id` |
| GET | `/api/v1/inventory/jobs/{job_id}` | Poll async job status | `job_id` |
| GET | `/api/v1/inventory/scans` | List discovery scans | `tenant_id` |
| GET | `/api/v1/inventory/runs/latest/summary` | Latest scan summary | `tenant_id` |
| GET | `/api/v1/inventory/runs/{scan_run_id}/summary` | Specific scan summary | `tenant_id`, `scan_run_id` |
| GET | `/api/v1/inventory/assets` | Paginated asset list | `tenant_id` |
| GET | `/api/v1/inventory/assets/{resource_uid}` | Single asset by UID/ARN | `tenant_id` |
| GET | `/api/v1/inventory/assets/{resource_uid}/relationships` | Asset relationships | `tenant_id` |
| GET | `/api/v1/inventory/assets/{resource_uid}/drift` | Asset drift hint | `tenant_id` |
| GET | `/api/v1/inventory/relationships` | Paginated relationships | `tenant_id` |
| GET | `/api/v1/inventory/graph` | Asset graph (nodes + edges) | `tenant_id` |
| GET | `/api/v1/inventory/drift` | Drift between two scans | `tenant_id` |
| GET | `/api/v1/inventory/runs/{scan_run_id}/drift` | Scan-specific drift | `tenant_id` |
| GET | `/api/v1/inventory/accounts/{account_id}` | Account asset summary | `tenant_id` |
| GET | `/api/v1/inventory/services/{service}` | Service asset summary | `tenant_id` |

### Health Check

**Request:**
```
GET http://<ELB>/inventory/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### Latest Scan Summary

**Request:**
```
GET http://<ELB>/inventory/api/v1/inventory/runs/latest/summary?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "inventory_scan_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
  "tenant_id": "test-tenant",
  "started_at": "2026-02-21T17:22:30.920727+00:00",
  "completed_at": "2026-02-21T17:22:34.219011+00:00",
  "status": "completed",
  "total_assets": 275,
  "total_relationships": 1,
  "assets_by_provider": {
    "aws": 275
  },
  "assets_by_resource_type": {
    "amp.workspace": 3,
    "acm.certificate": 1,
    "bedrock.foundation-model": 190,
    "bedrock.inference-profile": 76,
    "bedrock.default-prompt-router": 5
  },
  "assets_by_region": {
    "us-east-1": 192,
    "ap-south-1": 83
  },
  "providers_scanned": ["aws"],
  "accounts_scanned": ["588989875114"],
  "regions_scanned": ["us-east-1", "ap-south-1"],
  "errors_count": 0
}
```

### List Assets (Paginated)

**Request:**
```
GET http://<ELB>/inventory/api/v1/inventory/assets?tenant_id=test-tenant&limit=2
```

**Optional filters:** `scan_run_id`, `provider`, `region`, `resource_type`, `account_id`, `account_ids`, `limit`, `offset`

**Response (200):**
```json
{
  "assets": [
    {
      "schema_version": "cspm_asset.v1",
      "tenant_id": "test-tenant",
      "scan_run_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "ap-south-1",
      "scope": "ap-south-1",
      "resource_type": "amp.workspace",
      "resource_id": "",
      "resource_uid": "arn:aws:aps:ap-south-1:588989875114:workspace/ws-00236cdc-b215-4369-bb6c-7f66c59b5b4b",
      "name": "ws-00236cdc-b215-4369-bb6c-7f66c59b5b4b",
      "tags": {},
      "metadata": {}
    },
    {
      "schema_version": "cspm_asset.v1",
      "tenant_id": "test-tenant",
      "scan_run_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "ap-south-1",
      "scope": "ap-south-1",
      "resource_type": "amp.workspace",
      "resource_id": "",
      "resource_uid": "arn:aws:aps:ap-south-1:588989875114:workspace/ws-4d579277-135d-463a-bab2-cd03512898b3",
      "name": "ws-4d579277-135d-463a-bab2-cd03512898b3",
      "tags": {},
      "metadata": {}
    }
  ],
  "total": 274,
  "limit": 2,
  "offset": 0,
  "has_more": true
}
```

### Get Single Asset

**Request:**

Note: `resource_uid` is a URL-encoded ARN (use `encodeURIComponent()` in JS).

```
GET http://<ELB>/inventory/api/v1/inventory/assets/arn%3Aaws%3Aaps%3Aap-south-1%3A588989875114%3Aworkspace%2Fws-00236cdc-b215-4369-bb6c-7f66c59b5b4b?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "schema_version": "cspm_asset.v1",
  "tenant_id": "test-tenant",
  "scan_run_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
  "provider": "aws",
  "account_id": "588989875114",
  "region": "ap-south-1",
  "scope": "ap-south-1",
  "resource_type": "amp.workspace",
  "resource_id": "",
  "resource_uid": "arn:aws:aps:ap-south-1:588989875114:workspace/ws-00236cdc-b215-4369-bb6c-7f66c59b5b4b",
  "name": "ws-00236cdc-b215-4369-bb6c-7f66c59b5b4b",
  "tags": {},
  "metadata": {}
}
```

### List Relationships

**Request:**
```
GET http://<ELB>/inventory/api/v1/inventory/relationships?tenant_id=test-tenant&limit=1
```

**Optional filters:** `scan_run_id`, `relation_type`, `from_uid`, `to_uid`, `limit`, `offset`

**Response (200):**
```json
{
  "relationships": [
    {
      "schema_version": "cspm_relationship.v1",
      "tenant_id": "test-tenant",
      "scan_run_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
      "provider": "aws",
      "account_id": "588989875114",
      "region": "us-east-1",
      "relation_type": "uses",
      "from_uid": "arn:aws:acm:us-east-1:588989875114:certificate/466bf8a6-a11e-46e8-be3f-22f5050ea1fc",
      "to_uid": "arn:aws:acm:us-east-1:588989875114:certificate/466bf8a6-a11e-46e8-be3f-22f5050ea1fc",
      "properties": {
        "source_field_value": "arn:aws:acm:us-east-1:588989875114:certificate/466bf8a6-a11e-46e8-be3f-22f5050ea1fc"
      }
    }
  ],
  "total": 1,
  "limit": 1,
  "offset": 0,
  "has_more": false
}
```

### Account Summary

**Request:**
```
GET http://<ELB>/inventory/api/v1/inventory/accounts/588989875114?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "account_id": "588989875114",
  "total_assets": 274,
  "by_service": {
    "amp": 3,
    "bedrock": 271
  },
  "by_region": {
    "ap-south-1": 83,
    "us-east-1": 191
  },
  "provider": "aws"
}
```

### Drift

**Request:**
```
GET http://<ELB>/inventory/api/v1/inventory/drift?tenant_id=test-tenant
```

**Optional params:** `baseline_scan`, `compare_scan`, `provider`, `resource_type`, `account_id`

**Response (200):**
```json
{
  "tenant_id": "test-tenant",
  "baseline_scan": null,
  "compare_scan": null,
  "summary": {
    "assets_added": 0,
    "assets_removed": 0,
    "assets_changed": 0,
    "relationships_added": 0,
    "relationships_removed": 0
  },
  "drift_records": [],
  "total": 0,
  "by_change_type": {},
  "by_provider": {},
  "details": {}
}
```

### Trigger Inventory Scan (Pipeline Mode)

**Request:**
```
POST http://<ELB>/inventory/api/v1/inventory/scan/discovery
Content-Type: application/json
```

```json
{
  "tenant_id": "test-tenant",
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Or pass `discovery_scan_id` directly instead of `orchestration_id`:
```json
{
  "tenant_id": "test-tenant",
  "discovery_scan_id": "7e3c4d2a-bf91-4f2e-9abc-123456789abc"
}
```

**Response (200):** [example]
```json
{
  "inventory_scan_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
  "status": "completed",
  "total_assets": 275,
  "total_relationships": 1
}
```

### Notes

- `resource_uid` is the globally unique identifier for an asset — typically the full ARN for AWS resources.
- URL-encode the ARN when using it as a path segment.
- The `scan_run_id` in asset responses equals the `inventory_scan_id`.
- Use `scan_run_id` filter on asset queries to pin results to a specific scan.

---

## 5. Engine Compliance

**Purpose:** Map check findings to compliance frameworks and generate compliance reports with
control-level pass/fail scores.

**Supported providers:** `aws`, `azure`, `gcp`

**Supported frameworks:** `cis_aws`, `nist_800_53`, `soc2`, `pci_dss`, `hipaa`, `gdpr`, `iso_27001`, `ccpa`, `aws_well_architected`, `fedramp`, `cmmc`, `swift_csp`, `singapore_mas_trm`

**External:** `http://<ELB>/compliance/...`
**Internal:** `http://engine-compliance:80/...`
**Database:** `compliance`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/api/v1/health` | Health check | — |
| POST | `/api/v1/scan` | Generic scan trigger | body |
| POST | `/api/v1/compliance/generate` | Generate report from orchestration | `orchestration_id` OR `scan_id`, `csp`, `frameworks` |
| POST | `/api/v1/compliance/generate/from-threat-engine` | Generate from threat engine data | body |
| POST | `/api/v1/compliance/generate/from-check-db` | Generate directly from check DB | `check_scan_id`, `csp` |
| POST | `/api/v1/compliance/generate/from-threat-db` | Generate from threat DB | body |
| POST | `/api/v1/compliance/generate/detailed` | Detailed report generation | body |
| POST | `/api/v1/compliance/mock/generate` | Generate mock report (no scan required) | body |
| GET | `/api/v1/compliance/reports` | List compliance reports | `tenant_id` |
| GET | `/api/v1/compliance/report/{report_id}` | Get report by ID | `report_id` |
| GET | `/api/v1/compliance/report/{report_id}/export` | Export report | `format` |
| GET | `/api/v1/compliance/report/{report_id}/download/pdf` | Download PDF | `report_id` |
| GET | `/api/v1/compliance/report/{report_id}/download/excel` | Download Excel | `report_id` |
| GET | `/api/v1/compliance/reports/{report_id}/status` | Report generation status | `report_id` |
| DELETE | `/api/v1/compliance/reports/{report_id}` | Delete report | `report_id` |
| GET | `/api/v1/compliance/frameworks` | List available frameworks | — |
| GET | `/api/v1/compliance/frameworks/all` | All frameworks with details | — |
| GET | `/api/v1/compliance/framework-detail/{framework}` | Framework definition | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/status` | Framework compliance status | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/detailed` | Detailed framework findings | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/structure` | Control tree structure | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/controls/grouped` | Controls grouped by domain | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/resources/grouped` | Resources grouped by control | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/control/{control_id}` | Specific control detail | `framework`, `control_id` |
| GET | `/api/v1/compliance/framework/{framework}/download/pdf` | Framework PDF download | `framework` |
| GET | `/api/v1/compliance/framework/{framework}/download/excel` | Framework Excel download | `framework` |
| GET | `/api/v1/compliance/control-detail/{framework}/{control_id}` | Control detail view | `framework`, `control_id` |
| GET | `/api/v1/compliance/controls/search` | Search controls | `q`, `framework` |
| GET | `/api/v1/compliance/resource/drilldown` | Resource-level drilldown | `resource_uid` |
| GET | `/api/v1/compliance/resource/{resource_uid}/compliance` | Resource compliance status | `resource_uid`, `framework` |
| GET | `/api/v1/compliance/dashboard` | Compliance dashboard summary | `tenant_id`, `csp` |
| GET | `/api/v1/compliance/trends` | Compliance score over time | `tenant_id`, `days`, `framework` |
| GET | `/api/v1/compliance/accounts/{account_id}` | Account compliance posture | `framework`, `csp` |

### Health Check

**Request:**
```
GET http://<ELB>/compliance/api/v1/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### List Compliance Reports

**Request:**
```
GET http://<ELB>/compliance/api/v1/compliance/reports?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "total": 0,
  "limit": 2,
  "offset": 0,
  "reports": [],
  "source": "database"
}
```

### Generate Mock Report (no scan required)

Useful for UI development and testing without a live check scan.

**Request:**
```
POST http://<ELB>/compliance/api/v1/compliance/mock/generate
Content-Type: application/json
```

```json
{
  "tenant_id": "test-tenant",
  "framework": "cis_aws",
  "account_id": "588989875114"
}
```

**Response (200):**
```json
{
  "status": "success",
  "scan_id": "mock-scan-20260228-042738",
  "mock_data": {
    "scan_id": "mock-scan-20260228-042738",
    "csp": "aws",
    "account_id": "123456789012",
    "scanned_at": "2026-02-28T04:27:38.575368Z",
    "results": [
      {
        "account_id": "123456789012",
        "region": "us-east-1",
        "service": "eks",
        "checks": [
          {
            "rule_id": "aws.kms.cmk.rotation_enabled",
            "result": "PASS",
            "severity": "low",
            "resource": {
              "type": "eks_test",
              "id": "test-eks-1",
              "arn": "arn:aws:eks:us-east-1:123456789012:test-eks-1"
            },
            "evidence": {"status": "pass"}
          }
        ]
      }
    ]
  }
}
```

### Generate Compliance Report from Check Findings

**Request:**
```
POST http://<ELB>/compliance/api/v1/compliance/generate/from-threat-engine
Content-Type: application/json
```

```json
{
  "tenant_id": "test-tenant",
  "account_id": "588989875114",
  "framework": "cis_aws",
  "csp": "aws",
  "scan_id": "9f2a1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c"
}
```

**Response (202):** [example]
```json
{
  "report_id": "rpt-20260228-cis-aws-123456",
  "status": "generating",
  "framework": "cis_aws",
  "tenant_id": "test-tenant",
  "estimated_completion_seconds": 30
}
```

### Notes

- Use `/mock/generate` during UI development to get realistic response shapes without a live scan.
- `framework` values must exactly match the identifiers listed above (e.g. `cis_aws` not `CIS AWS`).
- PDF and Excel downloads return binary content with appropriate `Content-Disposition` headers.

---

## 6. Engine Threat

**Purpose:** Detect threats, map to MITRE ATT&CK techniques, build attack chains, and provide
threat intelligence, hunt queries, and blast-radius analysis.

**Supported providers:** `aws`, `azure`, `gcp`

**External:** `http://<ELB>/threat/...`
**Internal:** `http://engine-threat:80/...`
**Database:** `threat`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Health check | — |
| POST | `/api/v1/scan` | Trigger threat analysis (sync) | body |
| POST | `/api/v1/threat/generate/async` | Trigger async threat generation | body |
| GET | `/api/v1/threat/jobs/{job_id}` | Poll async job status | `job_id` |
| GET | `/api/v1/threat/threats` | List all threats | `tenant_id` |
| GET | `/api/v1/threat/list` | Threat list (alternative) | `tenant_id` |
| GET | `/api/v1/threat/reports` | List threat reports | `tenant_id` |
| GET | `/api/v1/threat/reports/{scan_run_id}` | Threat report for scan | `scan_run_id` |
| GET | `/api/v1/threat/scans/{scan_run_id}/summary` | Scan summary | `scan_run_id` |
| GET | `/api/v1/threat/summary` | Threat summary | `tenant_id`, `scan_run_id` (required) |
| GET | `/api/v1/threat/analytics/distribution` | Severity/type distribution | `tenant_id`, `scan_run_id` (required) |
| GET | `/api/v1/threat/analytics/correlation` | Threat correlations | `tenant_id` |
| GET | `/api/v1/threat/analytics/patterns` | Attack patterns | `tenant_id` |
| GET | `/api/v1/threat/analytics/trend` | Threat trend over time | `tenant_id` |
| GET | `/api/v1/threat/map/account` | Threats by account | `tenant_id` |
| GET | `/api/v1/threat/map/service` | Threats by service | `tenant_id` |
| GET | `/api/v1/threat/map/geographic` | Threats by region | `tenant_id` |
| GET | `/api/v1/threat/drift` | Threat drift between scans | `tenant_id` |
| GET | `/api/v1/threat/remediation/queue` | Pending remediations | `tenant_id` |
| GET | `/api/v1/threat/analysis` | Threat analysis list | `tenant_id` |
| POST | `/api/v1/threat/analysis/run` | Run threat analysis | body |
| GET | `/api/v1/threat/analysis/prioritized` | Prioritized findings | `tenant_id` |
| GET | `/api/v1/threat/analysis/{detection_id}` | Single detection detail | `detection_id` |
| GET | `/api/v1/threat/{threat_id}/misconfig-findings` | Misconfig findings for threat | `threat_id` |
| GET | `/api/v1/threat/{threat_id}/remediation` | Remediation steps | `threat_id` |
| GET | `/api/v1/threat/{threat_id}/assets` | Affected assets | `threat_id` |
| GET | `/api/v1/graph/summary` | Graph node/edge counts | `tenant_id` |
| GET | `/api/v1/graph/attack-paths` | Attack path enumeration | `tenant_id` |
| GET | `/api/v1/graph/blast-radius/{resource_uid}` | Blast radius for resource | `resource_uid`, `tenant_id` |
| GET | `/api/v1/graph/internet-exposed` | Internet-exposed resources | `tenant_id` |
| GET | `/api/v1/graph/toxic-combinations` | Toxic permission combos | `tenant_id` |
| POST | `/api/v1/graph/build` | (Re)build threat graph | body |
| GET | `/api/v1/intel` | Threat intelligence feed | `tenant_id` |
| POST | `/api/v1/intel/feed` | Submit intel feed entry | body |
| POST | `/api/v1/intel/feed/batch` | Submit batch intel entries | body |
| POST | `/api/v1/hunt/execute` | Execute a threat hunt | body |
| GET | `/api/v1/hunt/predefined` | List predefined hunts | — |
| GET | `/api/v1/checks/dashboard` | Check findings dashboard | `tenant_id` |
| GET | `/api/v1/checks/scans` | Check scans list | `tenant_id` |
| GET | `/api/v1/checks/stats` | Check statistics | `tenant_id` |
| GET | `/api/v1/checks/findings/search` | Search check findings | `tenant_id`, `q` |
| GET | `/api/v1/discoveries/scans` | Discovery scans list | `tenant_id` |
| GET | `/api/v1/discoveries/dashboard` | Discovery dashboard | `tenant_id` |

### Health Check

**Request:**
```
GET http://<ELB>/threat/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### Check Findings Dashboard

**Request:**
```
GET http://<ELB>/threat/api/v1/checks/dashboard?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "total_checks": 0,
  "passed": 0,
  "failed": 0,
  "error": 0,
  "pass_rate": 0.0,
  "services_scanned": 0,
  "accounts_scanned": 1,
  "top_failing_services": [],
  "recent_scans": [],
  "last_scan_timestamp": null
}
```

### Graph Summary

**Request:**
```
GET http://<ELB>/threat/api/v1/graph/summary?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "node_counts": {},
  "relationship_counts": {},
  "resources_by_type": {},
  "threats_by_severity": {}
}
```

### Threat Analytics Correlation

Does NOT require `scan_run_id`.

**Request:**
```
GET http://<ELB>/threat/api/v1/threat/analytics/correlation?tenant_id=test-tenant
```

**Response (200):** [example]
```json
{
  "tenant_id": "test-tenant",
  "correlations": [],
  "total": 0
}
```

### Trigger Threat Scan

**Request:**
```
POST http://<ELB>/threat/api/v1/scan
Content-Type: application/json
```

```json
{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant"
}
```

**Response (202):** [example]
```json
{
  "threat_scan_id": "thr-20260228-abc123",
  "status": "started"
}
```

### Notes

- `scan_run_id` is REQUIRED for: `/api/v1/threat/summary`, `/api/v1/threat/analytics/distribution`.
- `scan_run_id` is NOT required for: `/api/v1/threat/analytics/correlation`, `/api/v1/checks/dashboard`, `/api/v1/graph/summary`.
- All graph endpoints return empty results until a threat scan has been completed.

---

## 7. Engine IAM

**Purpose:** IAM security posture analysis — detects overprivileged roles, missing MFA,
weak password policies, and access control misconfigurations. Uses 57 built-in rules.

**Supported providers:** `aws`, `azure`, `gcp`

**External:** `http://<ELB>/iam/...`
**Internal:** `http://engine-iam:80/...`
**Database:** `iam`

### WARNING: csp and scan_id are required on all query endpoints

Unlike other engines, IAM requires both `csp` (e.g. `aws`) and `scan_id` (or the literal `latest`) as query parameters on all finding/query endpoints.

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| POST | `/api/v1/iam-security/scan` | Trigger IAM scan | body |
| GET | `/api/v1/iam-security/findings` | IAM findings | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/iam-security/modules` | List IAM modules | — |
| GET | `/api/v1/iam-security/rule-ids` | Rule ID patterns | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/iam-security/rules/{rule_id}` | Rule definition | `rule_id` |
| GET | `/api/v1/iam-security/accounts/{account_id}` | Account IAM posture | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/iam-security/services/{service}` | Service IAM posture | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/iam-security/resources/{resource_uid}` | Resource IAM findings | `tenant_id`, `csp`, `scan_id` |

### Health Check

**Request:**
```
GET http://<ELB>/iam/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### List IAM Modules

**Request:**
```
GET http://<ELB>/iam/api/v1/iam-security/modules
```

**Response (200):**
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

### Get Rule ID Patterns

**Request:**
```
GET http://<ELB>/iam/api/v1/iam-security/rule-ids?tenant_id=test-tenant&csp=aws&scan_id=latest
```

**Response (200):**
```json
{
  "method": "rule_id_pattern_matching",
  "patterns": [
    "\\.iam\\.",
    "\\.iam_",
    "\\.mfa[._]",
    "\\.password[._]",
    "\\.root[._]",
    "\\.sso[._]",
    "\\.entraid\\.",
    "\\.aad\\.",
    "\\.managedidentity\\.",
    "\\.serviceprincipal\\.",
    "\\.rbac\\.",
    "\\.pim\\.",
    "\\.serviceaccount\\.",
    "\\.workloadidentity\\.",
    "\\.orgpolicy\\."
  ],
  "description": "IAM relevance is determined by matching rule_id against these patterns"
}
```

### Get IAM Findings

**Request:**
```
GET http://<ELB>/iam/api/v1/iam-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest
```

**Optional filters:** `account_id`, `hierarchy_id`, `service`, `module`, `status`, `resource_id`

**Response (200):**
```json
{
  "filters": {
    "account_id": null,
    "hierarchy_id": null,
    "service": null,
    "module": null,
    "status": null,
    "resource_id": null
  },
  "summary": {
    "total_findings": 0,
    "by_module": {},
    "by_status": {}
  },
  "findings": []
}
```

### Get Account IAM Posture

**Request:**
```
GET http://<ELB>/iam/api/v1/iam-security/accounts/588989875114?tenant_id=test-tenant&csp=aws&scan_id=latest
```

**Response (200):**
```json
{
  "account_id": "588989875114",
  "summary": {
    "account_id": "588989875114",
    "total_findings": 0,
    "findings_by_status": {},
    "findings_by_module": {},
    "findings_by_severity": {}
  },
  "findings": []
}
```

### Trigger IAM Scan

**Request:**
```
POST http://<ELB>/iam/api/v1/iam-security/scan
Content-Type: application/json
```

```json
{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant",
  "provider": "aws"
}
```

**Response (202):** [example]
```json
{
  "iam_scan_id": "iam-20260228-xyz789",
  "status": "started"
}
```

### Notes

- `scan_id=latest` resolves to the most recent completed check scan for the given tenant and CSP.
- `module` filter values must match one of the modules returned by `/api/v1/iam-security/modules`.
- 57 built-in rules covering: least privilege, MFA enforcement, password policy, role management, SSO, and access control.

---

## 8. Engine DataSec

**Purpose:** Data security posture analysis — detects unencrypted data stores, public access
misconfigurations, data classification gaps, and residency violations. Uses 62 built-in rules.

**Supported providers:** `aws`, `azure`, `gcp`

**External:** `http://<ELB>/datasec/...`
**Internal:** `http://engine-datasec:80/...`
**Database:** `datasec`

### WARNING: csp and scan_id are required on all query endpoints

Same as IAM engine — both `csp` and `scan_id` (or `latest`) are required on all finding/query endpoints.

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Health check | — |
| GET | `/api/v1/health/live` | Liveness probe | — |
| GET | `/api/v1/health/ready` | Readiness probe | — |
| POST | `/api/v1/data-security/scan` | Trigger DataSec scan | body |
| GET | `/api/v1/data-security/findings` | DataSec findings | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/modules` | List DataSec modules | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/modules/{module}/rules` | Rules for a module | `module` |
| GET | `/api/v1/data-security/rules/{rule_id}` | Rule definition | `rule_id` |
| GET | `/api/v1/data-security/catalog` | Data catalog (all data stores) | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/classification` | Data classification analysis | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/residency` | Data residency compliance | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/lineage` | Data lineage map | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/activity` | Data activity monitoring | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/compliance` | DataSec compliance summary | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/accounts/{account_id}` | Account data posture | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/services/{service}` | Service data posture | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/protection/{resource_id}` | Encryption/protection status | `tenant_id`, `csp`, `scan_id` |
| GET | `/api/v1/data-security/governance/{resource_id}` | Access governance for resource | `tenant_id`, `csp`, `scan_id` |

### Health Check

**Request:**
```
GET http://<ELB>/datasec/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### List DataSec Modules

**Request:**
```
GET http://<ELB>/datasec/api/v1/data-security/modules?tenant_id=test-tenant&csp=aws&scan_id=latest
```

**Response (200):**
```json
{
  "modules": [
    "data_protection_encryption",
    "data_access_governance",
    "data_activity_monitoring",
    "data_residency",
    "data_compliance",
    "data_classification"
  ]
}
```

### Trigger DataSec Scan

**Request:**
```
POST http://<ELB>/datasec/api/v1/data-security/scan
Content-Type: application/json
```

```json
{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant",
  "provider": "aws"
}
```

**Response (202):** [example]
```json
{
  "datasec_scan_id": "ds-20260228-abc456",
  "status": "started"
}
```

### Get Data Catalog

**Request:**
```
GET http://<ELB>/datasec/api/v1/data-security/catalog?tenant_id=test-tenant&csp=aws&scan_id=latest
```

**Optional filters:** `account_id`, `service`, `region`

**Response (200):** [example]
```json
{
  "catalog": [
    {
      "resource_uid": "arn:aws:s3:::my-sensitive-bucket",
      "service": "s3",
      "resource_type": "s3.bucket",
      "region": "ap-south-1",
      "classification": "sensitive",
      "encryption_at_rest": false,
      "public_access": true,
      "findings_count": 3
    }
  ],
  "total": 1
}
```

### Notes

- 62 built-in rules across: encryption at rest, encryption in transit, access control, data classification, data residency, lineage, and activity monitoring.
- `module` values for filtering: see modules list above.

---

## 9. Engine SecOps

**Purpose:** Static analysis security scanning of Infrastructure-as-Code (IaC) across 14 languages.
Scans Terraform, CloudFormation, Kubernetes manifests, Dockerfiles, and more.

**External:** `http://<ELB>/secops/...`
**Internal:** `http://engine-secops:80/...`
**Database:** `secops`

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/health` | Health check | — |
| POST | `/api/v1/secops/scan` | Trigger IaC scan | body |
| GET | `/api/v1/secops/scans` | List scans | `tenant_id` |
| GET | `/api/v1/secops/scan/{secops_scan_id}/status` | Scan status | `secops_scan_id` |
| GET | `/api/v1/secops/scan/{secops_scan_id}/findings` | Scan findings | `secops_scan_id` |
| GET | `/api/v1/secops/rules/stats` | Rule library statistics | — |
| POST | `/api/v1/secops/rules/sync` | Sync rules to DB | — |
| POST | `/scan` | Legacy: scan pre-staged project | `project_name` |
| GET | `/results/{project_name}` | Legacy: get scan results | `project_name` |

### Health Check

**Request:**
```
GET http://<ELB>/secops/health
```

**Response (200):**
```json
{"status": "healthy"}
```

### Rule Library Statistics

**Request:**
```
GET http://<ELB>/secops/api/v1/secops/rules/stats
```

**Response (200):**
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

### List Scans

**Request:**
```
GET http://<ELB>/secops/api/v1/secops/scans?tenant_id=test-tenant
```

**Response (200):**
```json
{
  "tenant_id": "test-tenant",
  "total": 0,
  "scans": []
}
```

### Trigger IaC Scan (S3 source)

**Request:**
```
POST http://<ELB>/secops/api/v1/secops/scan
Content-Type: application/json
```

```json
{
  "tenant_id": "test-tenant",
  "project_name": "my-terraform-project",
  "scan_type": "terraform",
  "source": "s3",
  "s3_bucket": "cspm-lgtech",
  "s3_key": "projects/my-terraform/",
  "severity_threshold": "medium"
}
```

**Response (202):** [example]
```json
{
  "secops_scan_id": "sops-20260228-xyz",
  "status": "started",
  "project_name": "my-terraform-project"
}
```

### Get Scan Findings

**Request:**
```
GET http://<ELB>/secops/api/v1/secops/scan/sops-20260228-xyz/findings
```

**Optional filters:** `severity`, `language`, `limit`

**Response (200):** [example]
```json
{
  "secops_scan_id": "sops-20260228-xyz",
  "findings": [
    {
      "rule_id": "terraform.aws_s3_bucket.public_access_block_missing",
      "severity": "high",
      "language": "terraform",
      "file": "main.tf",
      "line": 14,
      "message": "S3 bucket does not have public access block configured",
      "resource": "aws_s3_bucket.data"
    }
  ],
  "total": 1,
  "by_severity": {"high": 1}
}
```

### Supported Languages (14)

`terraform`, `cloudformation`, `kubernetes`, `dockerfile`, `ansible`, `arm_template`, `bicep`,
`pulumi`, `opentofu`, `cdk`, `azure_devops`, `github_actions`, `gitlab_ci`, `ruby`

### Notes

- Use the `/api/v1/secops/...` routes for all new integrations. The legacy `/scan` and `/results/` routes are deprecated.
- `scan_type` and `source` in the scan body control how the engine fetches and parses the code.
- `severity_threshold` filters findings below the specified level.

---

## 10. Engine Rule

**Purpose:** YAML rule management — create, validate, and search compliance rules.
Internal-only service (no ingress from ELB).

**Internal only:** `http://engine-rule:80/...`
**ClusterIP:** `10.100.88.168` (port 8011)
**Database:** Read-only from check engine's rule tables

### Routes

| Method | Path | Description | Required Params |
|--------|------|-------------|-----------------|
| GET | `/api/v1/health` | Health + provider status | — |
| GET | `/api/v1/providers` | List cloud providers | — |
| GET | `/api/v1/providers/status` | All providers loading status | — |
| GET | `/api/v1/providers/{provider}/status` | Specific provider status | `provider` |
| GET | `/api/v1/providers/{provider}/services` | Services for provider | `provider` |
| GET | `/api/v1/providers/{provider}/services/{service}/fields` | Available fields | `provider`, `service` |
| GET | `/api/v1/providers/{provider}/services/{service}/rules` | Rules for service | `provider`, `service` |
| POST | `/api/v1/rules/validate` | Validate a rule definition | body |
| POST | `/api/v1/rules/generate` | Generate YAML + metadata | body |
| GET | `/api/v1/rules/{rule_id}` | Get rule details | `rule_id` |
| PUT | `/api/v1/rules/{rule_id}` | Update rule | `rule_id` |
| DELETE | `/api/v1/rules/{rule_id}` | Delete rule | `rule_id` |
| GET | `/api/v1/rules/search` | Full-text rule search | `q` |
| GET | `/api/v1/rules/statistics` | Rule library stats | — |

---

## 11. API Gateway

**Purpose:** Central routing and service health aggregation. Also provides orchestration trigger
and CSP routing configuration.

**External:** `http://<ELB>/gateway/...`
**Internal:** `http://api-gateway:80/...`

### Routes

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | List all registered services |
| GET | `/gateway/health` | Gateway health |
| GET | `/gateway/services` | All services with status |
| POST | `/gateway/services/{name}/health-check` | Force health check on service |
| POST | `/gateway/orchestrate` | Trigger full pipeline orchestration |
| GET | `/gateway/configscan/csps` | List supported CSPs |
| GET | `/gateway/configscan/route-test` | Test CSP routing |

---

## Scan Pipeline Trigger Sequence

This is the complete sequence to run a full security scan for an AWS account.
All requests use the ELB base URL. Replace variables as shown.

```
ELB=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
TENANT=test-tenant
ACCOUNT=588989875114
```

### Step 1 — Ensure account is registered

```
GET $ELB/onboarding/api/v1/cloud-accounts/$ACCOUNT
```

If 404, register it first via `POST /onboarding/api/v1/cloud-accounts`.

### Step 2 — Create orchestration record and trigger discovery

```
POST $ELB/discoveries/api/v1/discovery
Content-Type: application/json

{
  "orchestration_id": "<new-uuid>",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "tenant_id": "test-tenant"
}
```

Save the returned `scan_id` as `DISCOVERY_SCAN_ID`.

Poll for completion:
```
GET $ELB/discoveries/api/v1/discovery/$DISCOVERY_SCAN_ID
```

Wait until `"status": "completed"`.

### Step 3 — Run check scan

```
POST $ELB/check/api/v1/scan
Content-Type: application/json

{
  "orchestration_id": "<same-uuid-from-step-2>",
  "tenant_id": "test-tenant"
}
```

Save the returned `check_scan_id`. Poll:
```
GET $ELB/check/api/v1/check/$CHECK_SCAN_ID/status
```

### Step 4 — Run inventory scan

```
POST $ELB/inventory/api/v1/inventory/scan/discovery
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "orchestration_id": "<same-uuid>"
}
```

### Step 5 — Run compliance report (can run in parallel with steps 6-8)

```
POST $ELB/compliance/api/v1/compliance/generate/from-threat-engine
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "account_id": "588989875114",
  "framework": "cis_aws",
  "csp": "aws",
  "scan_id": "<check_scan_id>"
}
```

### Step 6 — Run threat scan (parallel)

```
POST $ELB/threat/api/v1/scan
Content-Type: application/json

{
  "orchestration_id": "<same-uuid>",
  "tenant_id": "test-tenant"
}
```

### Step 7 — Run IAM scan (parallel)

```
POST $ELB/iam/api/v1/iam-security/scan
Content-Type: application/json

{
  "orchestration_id": "<same-uuid>",
  "tenant_id": "test-tenant",
  "provider": "aws"
}
```

### Step 8 — Run DataSec scan (parallel)

```
POST $ELB/datasec/api/v1/data-security/scan
Content-Type: application/json

{
  "orchestration_id": "<same-uuid>",
  "tenant_id": "test-tenant",
  "provider": "aws"
}
```

### Step 9 — Query results

```
# Inventory summary
GET $ELB/inventory/api/v1/inventory/runs/latest/summary?tenant_id=test-tenant

# Compliance report list
GET $ELB/compliance/api/v1/compliance/reports?tenant_id=test-tenant

# IAM findings
GET $ELB/iam/api/v1/iam-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest

# DataSec findings
GET $ELB/datasec/api/v1/data-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest

# Check findings dashboard
GET $ELB/threat/api/v1/checks/dashboard?tenant_id=test-tenant
```

---

## Health Check Curl Script

```bash
ELB=a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

echo "=== Onboarding ===" && curl -s http://$ELB/onboarding/api/v1/health | python3 -m json.tool
echo "=== Check ===" && curl -s http://$ELB/check/api/v1/health | python3 -m json.tool
echo "=== Compliance ===" && curl -s http://$ELB/compliance/api/v1/health | python3 -m json.tool
echo "=== Discoveries ===" && curl -s http://$ELB/discoveries/health | python3 -m json.tool
echo "=== Inventory ===" && curl -s http://$ELB/inventory/health | python3 -m json.tool
echo "=== Threat ===" && curl -s http://$ELB/threat/health | python3 -m json.tool
echo "=== IAM ===" && curl -s http://$ELB/iam/health | python3 -m json.tool
echo "=== DataSec ===" && curl -s http://$ELB/datasec/health | python3 -m json.tool
echo "=== SecOps ===" && curl -s http://$ELB/secops/health | python3 -m json.tool
```

---

## Database Quick Reference

| Engine | Database Name | RDS Host |
|--------|---------------|----------|
| onboarding | `threat_engine_onboarding` | `postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com` |
| discoveries | `discoveries` | same |
| check | `threat_engine_check` | same |
| inventory | `threat_engine_inventory` | same |
| compliance | `compliance` | same |
| threat | `threat` | same |
| iam | `iam` | same |
| datasec | `datasec` | same |
| secops | `secops` | same |

All databases use the same RDS instance on port 5432. Passwords are stored in the
`threat-engine-db-passwords` Kubernetes secret (sourced from AWS Secrets Manager at
`threat-engine/rds-credentials`).

---

*See also: `docs/API_UNIFORMITY.md` for full inconsistency analysis and migration plan.*
*See also: `docs/SCAN_PIPELINE.md` for the orchestration table schema and engine coordination details.*
*See also: `docs/api/` directory for per-engine detailed documentation.*
