# CSPM Platform — Real API Data Reference

> **Purpose**: Copy-paste ready curl commands with real responses from the live production backend.
> No mocks. No placeholders. These IDs work right now.
>
> **Last verified**: 2026-02-28 — all responses captured from live cluster

---

## Live Connection Details

```
BASE_URL = http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

# Real tenant with full scan data
TENANT_ID     = 5a8b072b-8867-4476-a52f-f331b1cbacb3

# Scan identifiers
ORCHESTRATION_ID = 337a7425-5a53-4664-8569-04c1f0d6abf0
SCAN_RUN_ID      = bfed9ebc-68e7-4f9d-83e1-24ce75e21d01
THREAT_SCAN_ID   = threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01

# AWS account scanned
AWS_ACCOUNT      = 588989875114

# Inventory scan
INVENTORY_SCAN_ID = 8879bbd5-8741-4fe1-afd1-a8bdf924f2c7
```

> **Route pattern**: nginx strips the engine prefix before forwarding.
> `GET /inventory/api/v1/inventory/assets` → engine receives `GET /api/v1/inventory/assets`

---

## Quick Health Check — All Engines

```bash
BASE=http://a248499a3e9da47248ad0adca7dac106-365a099e4a3b2214.elb.ap-south-1.amazonaws.com

curl $BASE/onboarding/api/v1/health     # {"status":"healthy","database":"connected"}
curl $BASE/discoveries/api/v1/health/live  # {"status":"alive"}
curl $BASE/check/api/v1/health          # {"status":"healthy"}
curl $BASE/inventory/health             # {"status":"ok"}
curl $BASE/compliance/api/v1/health     # {"status":"healthy"}
curl $BASE/threat/health                # {"status":"ok"}
curl $BASE/iam/health                   # {"status":"ok"}
curl $BASE/datasec/health               # {"status":"ok"}
curl $BASE/secops/health                # {"status":"ok"}
```

---

## What Data Is Available

| Engine | Live Data |
|--------|-----------|
| Inventory | 1,529 assets across 17 AWS regions, 199 relationships |
| Threat | 193 threat detections (131 high, 58 medium, 4 critical) |
| IAM | 825 findings across 6 modules (policy_analysis, least_privilege, mfa…) |
| DataSec | 21 S3 data stores catalogued, 3,900 findings |
| Compliance | 2 reports, 13 frameworks (GDPR, HIPAA, CIS, PCI-DSS, NIST…) |
| Onboarding | 6 cloud accounts (AWS, GCP, Azure) |
| SecOps | 2,454 IaC security rules loaded (14 languages) |
| Check | Rules evaluated against SCAN_RUN_ID scan |

---

## 1. Onboarding Engine

**Prefix**: `/onboarding` → stripped to `/api/v1/`

### List all cloud accounts

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
      "schedule_engines_requested": ["discovery","check","inventory","threat","compliance","iam","datasec"],
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

### Get single account

```bash
curl "$BASE/onboarding/api/v1/cloud-accounts/588989875114"
```

---

## 2. Inventory Engine

**Prefix**: `/inventory` → stripped to `/api/v1/inventory/`

### Latest scan summary

```bash
curl "$BASE/inventory/api/v1/inventory/runs/latest/summary?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
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
    "ec2.instance": 16,
    "lambda.function": 22,
    "s3.bucket": 21,
    "iam.user": 23,
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
    "us-east-2": 53
  },
  "providers_scanned": ["aws"],
  "accounts_scanned": ["588989875114"],
  "errors_count": 0
}
```

### List assets (paginated)

```bash
# First page — 2 items
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=2"

# Next page
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=50&offset=50"

# Filter by resource type
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&resource_type=s3.bucket"
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
    }
  ],
  "total": 1440,
  "limit": 2,
  "offset": 0,
  "has_more": true
}
```

### Asset relationships

```bash
curl "$BASE/inventory/api/v1/inventory/relationships?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=3"
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
    }
  ],
  "total": 199,
  "limit": 3,
  "offset": 0,
  "has_more": true
}
```

### Inventory graph

```bash
curl "$BASE/inventory/api/v1/inventory/graph?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

---

## 3. Threat Engine

**Prefix**: `/threat` → stripped to `/api/v1/threat/`

### List threats

```bash
curl "$BASE/threat/api/v1/threat/list?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&scan_run_id=bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&limit=3"
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
      "mitre_tactics": ["Persistence","Initial Access","Defense Evasion","Credential Access","Privilege Escalation","Discovery"],
      "risk_score": 50,
      "remediation": {"summary": "Review and remediate 9 misconfiguration(s) to mitigate this threat"}
    },
    {
      "threat_id": "2d9f3506-094d-5847-8c5d-883733faf466",
      "threat_type": "misconfiguration",
      "title": "IAM avoidrootusage: Avoid Root Usage Configured - Misconfiguration",
      "severity": "critical",
      "confidence": "low",
      "status": "open",
      "mitre_techniques": ["T1087","T1078","T1201","T1110","T1556","T1069","T1098"],
      "mitre_tactics": ["Persistence","Privilege Escalation","Credential Access","Defense Evasion","Discovery","Initial Access"],
      "risk_score": 50,
      "remediation": {"summary": "Review and remediate 13 misconfiguration(s) to mitigate this threat"}
    }
  ]
  // 191 more (total=193)
}
```

### Threat risk analysis

```bash
curl "$BASE/threat/api/v1/threat/analysis?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
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
      "mitre_tactics": ["Persistence","Privilege Escalation","Credential Access","Defense Evasion","Discovery","Initial Access"],
      "mitre_techniques": ["T1087","T1078","T1201","T1110","T1556","T1069","T1098"],
      "impact_score": 0.664,
      "is_internet_reachable": false,
      "blast_radius_count": 0,
      "composite_formula": "severity×40 + blast_radius×25 + mitre_impact×25 + reachability×10"
    }
  ]
  // 99 more
}
```

### Graph summary (for attack-path visualisation)

```bash
curl "$BASE/threat/api/v1/graph/summary?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
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
    "high": 131,
    "medium": 58,
    "critical": 4
  }
}
```

---

## 4. Compliance Engine

**Prefix**: `/compliance` → stripped to `/api/v1/compliance/`

### List reports

```bash
curl "$BASE/compliance/api/v1/compliance/reports?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
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

### List frameworks

```bash
curl "$BASE/compliance/api/v1/compliance/frameworks?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&csp=aws"
```

### Get report detail

```bash
curl "$BASE/compliance/api/v1/compliance/report/ab169d0d-62db-4d19-82db-1da97e0423f9"
```

### Framework status

```bash
# e.g. CIS, GDPR, HIPAA, PCI-DSS, NIST_800-53, SOC2, ISO27001
curl "$BASE/compliance/api/v1/compliance/framework/CIS/status?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

---

## 5. IAM Security Engine

**Prefix**: `/iam` → stripped to `/api/v1/iam-security/`

> **Both route forms work** (new aliases added in v-uniform):
> `/iam/api/v1/iam-security/findings` = `/iam/api/v1/iam/findings`

### IAM findings

```bash
curl "$BASE/iam/api/v1/iam-security/findings?csp=aws&scan_id=threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=2"
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
      "title": "IAM resource: Root Hardware Mfa Enabled",
      "mitre_techniques": ["T1078","T1556","T1110","T1098","T1201"],
      "iam_security_modules": ["mfa"],
      "is_iam_relevant": true
    }
  ]
  // 823 more findings
}
```

### IAM modules list

```bash
curl "$BASE/iam/api/v1/iam-security/modules?csp=aws&scan_id=threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
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

## 6. Data Security Engine

**Prefix**: `/datasec` → stripped to `/api/v1/data-security/`

> **Both route forms work**: `/datasec/api/v1/data-security/findings` = `/datasec/api/v1/datasec/findings`

### Data store catalog (21 S3 buckets found)

```bash
curl "$BASE/datasec/api/v1/data-security/catalog?csp=aws&scan_id=bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

```json
{
  "total_stores": 21,
  "filters": {"account_id": null, "service": null, "region": null},
  "stores": [
    {"resource_arn": "arn:aws:s3:::aiwebsite01",                      "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::anup-backup",                      "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::cloudtrail-test-d736bbca",         "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::cspm-lgtech",                      "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::dynamodb-backup-20251128-105848",   "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::lgtech-website",                   "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::my-bucket-x2nc4n2t",               "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::vulnerabiliy-dump",                "resource_type": "s3", "service": "s3", "region": "global"},
    {"resource_arn": "arn:aws:s3:::www.lgtech.in",                    "resource_type": "s3", "service": "s3", "region": "global"}
    // ... 12 more S3 buckets
  ]
}
```

### Data security findings

```bash
curl "$BASE/datasec/api/v1/data-security/findings?csp=aws&scan_id=bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=2"
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
      "is_data_security_relevant": true
    }
  ]
  // 3898 more
}
```

### Classification results

```bash
curl "$BASE/datasec/api/v1/data-security/classification?csp=aws&scan_id=bfed9ebc-68e7-4f9d-83e1-24ce75e21d01&tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

```json
{
  "total_resources": 21,
  "classified_resources": 0,
  "results": []
}
```

> Classification is data-driven — enrichment tagging for `data_classification` module is in progress.

---

## 7. Check Engine

**Prefix**: `/check` → stripped to `/api/v1/`

> Check scans are triggered via POST and tracked in-memory during the scan run.
> Historical results live in the **threat engine** (findings come through as misconfig_findings).

### List active/recent scans

```bash
curl "$BASE/check/api/v1/checks?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

```json
{"scans": [], "total": 0}
```

> Returns 0 when no scan is actively running. Trigger a new scan via `POST /check/api/v1/scan`.

### Trigger new check scan

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
  "check_scan_id": "<new-uuid>",
  "status": "running",
  "message": "Check scan started"
}
```

---

## 8. SecOps Engine

**Prefix**: `/secops` → stripped to `/api/v1/secops/`

### Rules statistics (2,454 rules loaded)

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

### List scans

```bash
curl "$BASE/secops/api/v1/secops/scans?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3"
```

```json
{"tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3", "total": 0, "scans": []}
```

> Returns 0 until a code repository is submitted for scanning via `POST /secops/api/v1/secops/scan`.

### Trigger IaC scan

```bash
curl -X POST "$BASE/secops/api/v1/secops/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "5a8b072b-8867-4476-a52f-f331b1cbacb3",
    "scan_path": "/path/to/terraform/code",
    "scan_type": "terraform"
  }'
```

---

## 9. Discoveries Engine

**Prefix**: `/discoveries` → stripped to `/api/v1/`

### Health check

```bash
curl "$BASE/discoveries/api/v1/health/live"   # {"status":"alive"}
curl "$BASE/discoveries/api/v1/health/ready"  # {"status":"ready"}
```

### Poll scan status

```bash
# Use the discovery_scan_id returned from POST /api/v1/discovery
curl "$BASE/discoveries/api/v1/discovery/<discovery_scan_id>"
```

### Trigger new discovery

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
  "scan_id": "<new-discovery-scan-id>",
  "status": "running",
  "message": "Discovery scan started"
}
```

---

## Scan Pipeline — How to Trigger a Full Scan

```bash
# Step 1 — Start discovery
DISC=$(curl -s -X POST "$BASE/discoveries/api/v1/discovery" \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"337a7425-5a53-4664-8569-04c1f0d6abf0","provider":"aws","hierarchy_id":"588989875114"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")

# Step 2 — Poll until done (status = "completed")
curl "$BASE/discoveries/api/v1/discovery/$DISC"

# Step 3 — Run check scan
curl -X POST "$BASE/check/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"337a7425-5a53-4664-8569-04c1f0d6abf0","provider":"aws","hierarchy_id":"588989875114"}'

# Step 4 — Run inventory, threat, compliance in parallel
curl -X POST "$BASE/inventory/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"337a7425-5a53-4664-8569-04c1f0d6abf0"}'

curl -X POST "$BASE/threat/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"337a7425-5a53-4664-8569-04c1f0d6abf0"}'

curl -X POST "$BASE/compliance/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{"orchestration_id":"337a7425-5a53-4664-8569-04c1f0d6abf0","framework":"CIS"}'
```

---

## Pagination Pattern

All list endpoints support:

| Param | Default | Max | Description |
|-------|---------|-----|-------------|
| `limit` | 100 | 1000 | Items per page |
| `offset` | 0 | — | Skip N items |
| `has_more` | — | — | `true` if more pages exist |
| `total` | — | — | Total items across all pages |

```bash
# Page 2 of assets (50 per page)
curl "$BASE/inventory/api/v1/inventory/assets?tenant_id=5a8b072b-8867-4476-a52f-f331b1cbacb3&limit=50&offset=50"
```

---

## Common Filters

| Param | Engines | Example |
|-------|---------|---------|
| `tenant_id` | all | `5a8b072b-8867-4476-a52f-f331b1cbacb3` |
| `account_id` | inventory, threat | `588989875114` |
| `account_ids` | inventory | `588989875114,123456789` (comma-separated) |
| `region` | inventory, threat | `ap-south-1` |
| `severity` | threat, iam, datasec | `critical`, `high`, `medium`, `low` |
| `resource_type` | inventory | `s3.bucket`, `iam.role`, `lambda.function` |
| `csp` | iam, datasec | `aws` (default) |
| `scan_id` | iam, datasec | `threat_bfed9ebc-68e7-4f9d-83e1-24ce75e21d01` |
| `scan_run_id` | threat | `bfed9ebc-68e7-4f9d-83e1-24ce75e21d01` |
