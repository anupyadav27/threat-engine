# CSPM Platform — Sample API Requests & Responses

> Last updated: 2026-02-28 — All samples tested against live production cluster
> Live tenant with data: `test-tenant` | AWS account: `588989875114`

## Base URL
```
BASE = http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com
```

> **IMPORTANT**: The nginx ingress strips the path prefix before forwarding to the engine.
> UI calls: `GET /inventory/api/v1/inventory/assets?tenant_id=T`
> Engine receives: `GET /api/v1/inventory/assets?tenant_id=T`

---

## 1. ONBOARDING ENGINE

**Base path**: `/onboarding/api/v1/`
**Health**: `GET /onboarding/api/v1/health` → 200

### List Cloud Accounts
```http
GET /onboarding/api/v1/cloud-accounts
```
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
      "schedule_include_services": ["iam","compute","bigquery","storage"],
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

### Get Account Detail
```http
GET /onboarding/api/v1/cloud-accounts/588989875114
```
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
  "schedule_engines_requested": ["discovery","check","inventory","threat","compliance","iam","datasec"],
  "schedule_enabled": true,
  "schedule_status": "active",
  "created_at": "2026-02-20T10:00:00.000000+00:00",
  "updated_at": "2026-02-22T07:00:00.000000+00:00"
}
```

### Register New Cloud Account
```http
POST /onboarding/api/v1/cloud-accounts
Content-Type: application/json

{
  "tenant_id": "my-tenant",
  "tenant_name": "My Organization",
  "customer_id": "cust-001",
  "customer_email": "admin@example.com",
  "account_name": "AWS Production",
  "provider": "aws",
  "credential_type": "access_key",
  "account_id": "123456789012",
  "credentials": {
    "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "aws_region": "ap-south-1"
  },
  "schedule_engines_requested": ["discovery","check","inventory","compliance"],
  "schedule_cron_expression": "0 2 * * *",
  "schedule_include_regions": ["ap-south-1","us-east-1"]
}
```
```json
{
  "account_id": "123456789012",
  "tenant_id": "my-tenant",
  "account_status": "active",
  "account_onboarding_status": "registered",
  "created_at": "2026-02-28T10:00:00.000000+00:00"
}
```

### Validate Account Credentials
```http
POST /onboarding/api/v1/cloud-accounts/588989875114/validate-credentials
```
```json
{
  "credential_validation_status": "valid",
  "credential_validation_message": "Credentials validated successfully",
  "credential_validated_at": "2026-02-28T10:00:00Z"
}
```

### Health Check
```http
GET /onboarding/api/v1/health
```
```json
{
  "status": "healthy",
  "database": "connected",
  "database_details": {
    "status": "connected",
    "database": "threat_engine_onboarding",
    "host": "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    "version": "PostgreSQL 15.12 on x86_64-pc-linux-gnu"
  },
  "version": "1.0.0",
  "service": "onboarding"
}
```

---

## 2. DISCOVERIES ENGINE

**Base path**: `/discoveries/api/v1/`
**Health**: `GET /discoveries/health` → 200

### Trigger Cloud Discovery
```http
POST /discoveries/api/v1/discovery
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "tenant_id": "test-tenant"
}
```
```json
{
  "scan_id": "7e3c4d2a-bf91-4f2e-9abc-123456789abc",
  "status": "started",
  "message": "Discovery scan initiated for aws account 588989875114"
}
```

### Get Discovery Scan Status
```http
GET /discoveries/api/v1/discovery/7e3c4d2a-bf91-4f2e-9abc-123456789abc
```
```json
{
  "scan_id": "7e3c4d2a-bf91-4f2e-9abc-123456789abc",
  "status": "completed",
  "provider": "aws",
  "hierarchy_id": "588989875114",
  "services_scanned": 38,
  "resources_found": 275,
  "started_at": "2026-02-28T10:00:00Z",
  "completed_at": "2026-02-28T10:17:00Z"
}
```

### Health Endpoints
```http
GET /discoveries/health                  → {"status": "healthy"}
GET /discoveries/api/v1/health/live      → {"status": "alive"}
GET /discoveries/api/v1/health/ready     → {"status": "ready", "database": "connected"}
```

---

## 3. CHECK ENGINE

**Base path**: `/check/api/v1/`
**Health**: `GET /check/api/v1/health` → 200

### Trigger Check Scan
```http
POST /check/api/v1/scan
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant"
}
```
```json
{
  "check_scan_id": "c8f2a1b3-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "started",
  "message": "Check scan initiated"
}
```

### List Check Scans
```http
GET /check/api/v1/checks?tenant_id=test-tenant&limit=20&offset=0
```
```json
{
  "scans": [
    {
      "check_scan_id": "c8f2a1b3-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
      "tenant_id": "test-tenant",
      "status": "completed",
      "total_checks": 4200,
      "passed": 3150,
      "failed": 1050,
      "pass_rate": 75.0,
      "started_at": "2026-02-28T10:18:00Z",
      "completed_at": "2026-02-28T10:20:00Z"
    }
  ],
  "total": 1
}
```

### Get Check Scan Status
```http
GET /check/api/v1/check/c8f2a1b3-4d5e-6f7a-8b9c-0d1e2f3a4b5c/status
```
```json
{
  "check_scan_id": "c8f2a1b3-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "status": "completed",
  "total_checks": 4200,
  "passed": 3150,
  "failed": 1050
}
```

### Get Available Providers
```http
GET /check/api/v1/providers
```
```json
{
  "providers": ["aws"]
}
```

---

## 4. INVENTORY ENGINE

**Base path**: `/inventory/api/v1/inventory/`
**Health**: `GET /inventory/health` → 200
**Live data**: 275 assets, 1 relationship (tenant: `test-tenant`, account: `588989875114`)

### Trigger Inventory Scan (from discoveries)
```http
POST /inventory/api/v1/inventory/scan/discovery
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant"
}
```
```json
{
  "inventory_scan_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
  "status": "completed",
  "total_assets": 275,
  "total_relationships": 1,
  "duration_seconds": 3.3
}
```

### Get Latest Scan Summary
```http
GET /inventory/api/v1/inventory/runs/latest/summary?tenant_id=test-tenant
```
```json
{
  "inventory_scan_id": "aa9c7896-bf57-4d7c-9df3-23b293c0d64c",
  "tenant_id": "test-tenant",
  "started_at": "2026-02-21T17:22:30.920727+00:00",
  "completed_at": "2026-02-21T17:22:34.219011+00:00",
  "status": "completed",
  "total_assets": 275,
  "total_relationships": 1,
  "assets_by_provider": {"aws": 275},
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
  "regions_scanned": ["us-east-1","ap-south-1"],
  "errors_count": 0
}
```

### List Assets (paginated)
```http
GET /inventory/api/v1/inventory/assets?tenant_id=test-tenant&limit=2&offset=0
```
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

**Filter parameters**: `resource_type`, `provider`, `region`, `account_id`, `account_ids`, `name`, `tag_key`, `tag_value`

### Get Single Asset by UID
```http
GET /inventory/api/v1/inventory/assets/{resource_uid}?tenant_id=test-tenant
```
> URL-encode the `resource_uid` (ARN contains colons and slashes)

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

### Get Relationships
```http
GET /inventory/api/v1/inventory/relationships?tenant_id=test-tenant&limit=10
```
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
  "limit": 10,
  "offset": 0,
  "has_more": false
}
```

### Get Graph (nodes + edges)
```http
GET /inventory/api/v1/inventory/graph?tenant_id=test-tenant
```
Returns `{"nodes": [...assets], "edges": [...relationships]}`

### Get Drift Analysis
```http
GET /inventory/api/v1/inventory/drift?tenant_id=test-tenant
```
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
  "by_provider": {}
}
```

### Get Per-Account Summary
```http
GET /inventory/api/v1/inventory/accounts/588989875114?tenant_id=test-tenant
```
```json
{
  "account_id": "588989875114",
  "total_assets": 274,
  "by_service": {"amp": 3, "bedrock": 271},
  "by_region": {"ap-south-1": 83, "us-east-1": 191},
  "provider": "aws"
}
```

### List All Scan Runs
```http
GET /inventory/api/v1/inventory/scans?tenant_id=test-tenant&limit=10
```
Returns list of past inventory scan summaries.

---

## 5. COMPLIANCE ENGINE

**Base path**: `/compliance/api/v1/compliance/`
**Health**: `GET /compliance/api/v1/health` → 200
**Supported frameworks**: `cis_aws`, `nist_800_53`, `soc2`, `pci_dss`, `hipaa`, `gdpr`, `iso_27001`, `ccpa`, `aws_well_architected`, `fedramp`, `cmmc`, `swift_csp`, `singapore_mas_trm`

> **NOTE**: Several compliance endpoints require `csp` query param (e.g., `csp=aws`). This is being standardized — see `API_UNIFORMITY.md`.

### Generate Compliance Report (from check engine findings)
```http
POST /compliance/api/v1/compliance/generate/from-threat-engine
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "account_id": "588989875114",
  "framework": "cis_aws",
  "csp": "aws",
  "scan_id": "optional-check-scan-id"
}
```
```json
{
  "report_id": "rpt-8a2b3c4d-...",
  "status": "completed",
  "framework": "cis_aws",
  "tenant_id": "test-tenant",
  "account_id": "588989875114",
  "score": 78.5,
  "controls_passed": 42,
  "controls_failed": 11,
  "controls_total": 53
}
```

### Generate Compliance Report (using orchestration_id)
```http
POST /compliance/api/v1/compliance/generate
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "csp": "aws",
  "frameworks": ["cis_aws", "nist_800_53", "soc2"]
}
```

### List Reports
```http
GET /compliance/api/v1/compliance/reports?tenant_id=test-tenant&limit=20
```
```json
{
  "total": 0,
  "limit": 20,
  "offset": 0,
  "reports": [],
  "source": "database"
}
```

### Get Report Detail
```http
GET /compliance/api/v1/compliance/report/{report_id}?tenant_id=test-tenant
```

### Mock Compliance Report (for UI testing without real scan data)
```http
POST /compliance/api/v1/compliance/mock/generate
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "framework": "cis_aws",
  "account_id": "588989875114"
}
```
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

### Framework Status
```http
GET /compliance/api/v1/compliance/framework/cis_aws/status?tenant_id=test-tenant&scan_id=latest&csp=aws
```

### Download PDF Report
```http
GET /compliance/api/v1/compliance/framework/cis_aws/download/pdf?tenant_id=test-tenant&scan_id=<id>&csp=aws
```
Returns `application/pdf`

---

## 6. THREAT ENGINE

**Base path**: `/threat/api/v1/`
**Health**: `GET /threat/health` → 200

> **NOTE**: Many threat endpoints require `scan_run_id` query param. The scan_run_id is a UUID generated when a threat scan is triggered. See `API_UNIFORMITY.md` for standardization plan.

### Trigger Threat Scan
```http
POST /threat/api/v1/scan
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "scan_run_id": "550e8400-e29b-41d4-a716-446655440000",
  "cloud": "aws",
  "started_at": "2026-02-28T10:00:00Z",
  "orchestration_id": "parent-orchestration-uuid",
  "accounts": ["588989875114"],
  "regions": ["ap-south-1", "us-east-1"],
  "services": []
}
```
> **Note**: `scan_run_id`, `cloud`, and `started_at` are required. This is different from other engines.

```json
{
  "scan_run_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "threats_found": 47,
  "critical": 3,
  "high": 12,
  "medium": 22,
  "low": 10
}
```

### Get Threat Checks Dashboard
```http
GET /threat/api/v1/checks/dashboard?tenant_id=test-tenant
```
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

### Get Graph Summary
```http
GET /threat/api/v1/graph/summary?tenant_id=test-tenant
```
```json
{
  "node_counts": {},
  "relationship_counts": {},
  "resources_by_type": {},
  "threats_by_severity": {}
}
```

### Get Threat Intel
```http
GET /threat/api/v1/intel?tenant_id=test-tenant
```
```json
{"intel": [], "total": 0}
```

### List Threat Threats (requires scan_run_id)
```http
GET /threat/api/v1/threat/threats?tenant_id=test-tenant&scan_run_id=<uuid>&limit=20
```
```json
{
  "threats": [
    {
      "threat_id": "thr-001",
      "rule_id": "aws.iam.root.access_key_active",
      "severity": "critical",
      "resource_uid": "arn:aws:iam::588989875114:root",
      "risk_score": 95,
      "mitre_technique": "T1078",
      "mitre_tactic": "Initial Access",
      "status": "active",
      "detected_at": "2026-02-28T10:20:00Z"
    }
  ],
  "total": 47
}
```

### Get Attack Paths
```http
GET /threat/api/v1/graph/attack-paths?tenant_id=test-tenant
```

### Get Blast Radius
```http
GET /threat/api/v1/graph/blast-radius/{resource_uid}?tenant_id=test-tenant
```

### List Remediation Queue
```http
GET /threat/api/v1/threat/remediation/queue?tenant_id=test-tenant&scan_run_id=<uuid>
```

### Check Scan History (via threat engine proxy)
```http
GET /threat/api/v1/checks/scans?tenant_id=test-tenant&limit=10
```
```json
{
  "scans": [],
  "total": 0,
  "page": 1,
  "page_size": 20,
  "total_pages": 0
}
```

---

## 7. IAM ENGINE

**Base path**: `/iam/api/v1/iam-security/`
**Health**: `GET /iam/health` → 200
**IAM Modules**: `least_privilege`, `policy_analysis`, `mfa`, `role_management`, `password_policy`, `access_control`

> **NOTE**: Most IAM GET endpoints require `csp` (e.g., `csp=aws`) and `scan_id` parameters. This is being standardized to match other engines. See `API_UNIFORMITY.md`.

### Trigger IAM Scan
```http
POST /iam/api/v1/iam-security/scan
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant",
  "csp": "aws"
}
```

### Get IAM Findings (requires csp + scan_id)
```http
GET /iam/api/v1/iam-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest
```
Optional filters: `account_id`, `service`, `module`, `status`, `resource_id`, `severity`
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

### List IAM Modules
```http
GET /iam/api/v1/iam-security/modules
```
```json
{
  "modules": ["least_privilege","policy_analysis","mfa","role_management","password_policy","access_control"]
}
```

### Get IAM Rule Patterns
```http
GET /iam/api/v1/iam-security/rule-ids?tenant_id=test-tenant&csp=aws&scan_id=latest
```
```json
{
  "method": "rule_id_pattern_matching",
  "patterns": [
    "\\.iam\\.", "\\.iam_", "\\.mfa[._]", "\\.password[._]",
    "\\.root[._]", "\\.sso[._]", "\\.entraid\\.", "\\.aad\\.",
    "\\.managedidentity\\.", "\\.serviceprincipal\\.", "\\.rbac\\.",
    "\\.pim\\.", "\\.serviceaccount\\.", "\\.workloadidentity\\.",
    "\\.orgpolicy\\."
  ],
  "description": "IAM relevance is determined by matching rule_id against these patterns"
}
```

### Get Account IAM Summary
```http
GET /iam/api/v1/iam-security/accounts/588989875114?tenant_id=test-tenant&csp=aws&scan_id=latest
```
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

---

## 8. DATA SECURITY ENGINE

**Base path**: `/datasec/api/v1/data-security/`
**Health**: `GET /datasec/health` → 200
**DataSec Modules**: `data_protection_encryption`, `data_access_governance`, `data_activity_monitoring`, `data_residency`, `data_compliance`, `data_classification`

> **NOTE**: Most DataSec GET endpoints require `csp` and `scan_id`. Same standardization applies as IAM. See `API_UNIFORMITY.md`.

### Trigger DataSec Scan
```http
POST /datasec/api/v1/data-security/scan
Content-Type: application/json

{
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "tenant_id": "test-tenant",
  "csp": "aws"
}
```

### Get DataSec Findings (requires csp + scan_id)
```http
GET /datasec/api/v1/data-security/findings?tenant_id=test-tenant&csp=aws&scan_id=latest
```

### List DataSec Modules
```http
GET /datasec/api/v1/data-security/modules?tenant_id=test-tenant&csp=aws&scan_id=latest
```
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

### Get Data Classification
```http
GET /datasec/api/v1/data-security/classification?tenant_id=test-tenant&csp=aws&scan_id=latest
```

### Get Data Residency
```http
GET /datasec/api/v1/data-security/residency?tenant_id=test-tenant&csp=aws&scan_id=latest
```

### Get Data Catalog
```http
GET /datasec/api/v1/data-security/catalog?tenant_id=test-tenant&csp=aws&scan_id=latest
```

---

## 9. SECOPS ENGINE (IaC Scanner)

**Base path**: `/secops/api/v1/secops/`
**Health**: `GET /secops/health` → 200
**2,454 built-in rules** across 14 languages

### Get Rules Statistics
```http
GET /secops/api/v1/secops/rules/stats
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

### Trigger IaC Scan (Git repo)
```http
POST /secops/api/v1/secops/scan
Content-Type: application/json

{
  "tenant_id": "test-tenant",
  "repo_url": "https://github.com/org/terraform-infra.git",
  "branch": "main",
  "orchestration_id": "550e8400-e29b-41d4-a716-446655440000",
  "languages": ["terraform", "docker", "kubernetes"]
}
```
```json
{
  "secops_scan_id": "sec-9f8e7d6c-...",
  "status": "accepted",
  "message": "IaC scan started"
}
```

### List Scans
```http
GET /secops/api/v1/secops/scans?tenant_id=test-tenant&limit=10
```
```json
{
  "tenant_id": "test-tenant",
  "total": 0,
  "scans": []
}
```

### Get Scan Status
```http
GET /secops/api/v1/secops/scan/{secops_scan_id}/status
```

### Get Scan Findings
```http
GET /secops/api/v1/secops/scan/{secops_scan_id}/findings?severity=high&limit=20
```
```json
{
  "findings": [
    {
      "rule_id": "terraform.aws_s3.public_acl",
      "severity": "high",
      "file": "main.tf",
      "line": 42,
      "message": "S3 bucket has public ACL enabled",
      "remediation": "Set acl = 'private' or remove the ACL argument"
    }
  ],
  "total": 15,
  "by_severity": {"high": 10, "medium": 5}
}
```

---

## Complete Scan Pipeline — Step-by-Step

Run a full security scan in this sequence:

### Step 1: Register account (if not already done)
```bash
curl -X POST $BASE/onboarding/api/v1/cloud-accounts \
  -H "Content-Type: application/json" \
  -d '{"tenant_id":"test-tenant","provider":"aws","account_id":"588989875114",...}'
```

### Step 2: Trigger discovery scan
```bash
curl -X POST $BASE/discoveries/api/v1/discovery \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"orch-001","provider":"aws","hierarchy_id":"588989875114","tenant_id":"test-tenant"}'
# → Returns discovery scan_id, poll until completed
```

### Step 3 + 4 (PARALLEL): Trigger check AND inventory
```bash
# Check (evaluates 400+ rules)
curl -X POST $BASE/check/api/v1/scan \
  -d '{"orchestration_id":"orch-001","tenant_id":"test-tenant"}'

# Inventory (normalizes assets, builds graph)
curl -X POST $BASE/inventory/api/v1/inventory/scan/discovery \
  -d '{"orchestration_id":"orch-001","tenant_id":"test-tenant"}'
```

### Step 5 (PARALLEL after check): Compliance + Threat + IAM + DataSec
```bash
# Compliance
curl -X POST $BASE/compliance/api/v1/compliance/generate/from-threat-engine \
  -d '{"tenant_id":"test-tenant","account_id":"588989875114","framework":"cis_aws","csp":"aws"}'

# Threat (note different schema)
curl -X POST $BASE/threat/api/v1/scan \
  -d '{"tenant_id":"test-tenant","scan_run_id":"threat-001","cloud":"aws","started_at":"2026-02-28T10:00:00Z"}'

# IAM
curl -X POST $BASE/iam/api/v1/iam-security/scan \
  -d '{"orchestration_id":"orch-001","tenant_id":"test-tenant","csp":"aws"}'

# DataSec
curl -X POST $BASE/datasec/api/v1/data-security/scan \
  -d '{"orchestration_id":"orch-001","tenant_id":"test-tenant","csp":"aws"}'
```

---

## Quick Health Check for All Engines

```bash
ELB="http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com"
for engine_path in \
  "onboarding/api/v1/health" \
  "check/api/v1/health" \
  "compliance/api/v1/health" \
  "discoveries/health" \
  "inventory/health" \
  "threat/health" \
  "iam/health" \
  "datasec/health" \
  "secops/health"; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$ELB/$engine_path")
  echo "$STATUS  $engine_path"
done
```

Expected output:
```
200  onboarding/api/v1/health
200  check/api/v1/health
200  compliance/api/v1/health
200  discoveries/health
200  inventory/health
200  threat/health
200  iam/health
200  datasec/health
200  secops/health
```

---

## Error Handling

All engines use FastAPI and return consistent error shapes:

### 422 Validation Error (missing required field)
```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["query", "tenant_id"],
      "msg": "Field required",
      "input": null
    }
  ]
}
```

### 404 Not Found
```json
{"detail": "Not Found"}
```

### 500 Server Error
```json
{"detail": "Internal error: <message>"}
```
