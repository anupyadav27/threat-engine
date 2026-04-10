# Engine → BFF → UI: Data Contracts & Validation Plan

**Version:** 1.0
**Date:** 2026-03-31
**Purpose:** Define exact data contracts for every engine, every BFF view, and how to validate real engine data end-to-end.

---

## How This Document Works

```
Real Engine DB
     ↓  (engine ui-data endpoint)
Engine API Response  ←── CONTRACT A: what every engine MUST return
     ↓  (BFF parallel gather)
BFF View Response    ←── CONTRACT B: what every BFF view MUST return to UI
     ↓  (fetchView in UI)
UI Page              ←── CONTRACT C: what the UI destructures (already coded)
```

For each page, we define all three contracts, the gaps, and the validation steps.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| ✅ | Already implemented |
| ⚠️  | Partially implemented — needs fix |
| ❌ | Missing — must build |
| 🔴 | CALCULATED in engine/BFF |
| 🟡 | COMBINED from 2+ engines in BFF |
| 🟢 | DIRECT from one engine table |

---

## 1. Universal Engine Standards

**Every engine's `ui-data` endpoint MUST return this envelope:**

```python
# Standard engine ui-data response shape
{
  "success": True,
  "scan_run_id": "uuid",
  "tenant_id": "uuid",
  "generated_at": "2026-03-31T12:00:00Z",
  "kpi": {
    "posture_score": 0-100,        # weighted pass rate
    "total_findings": int,
    "critical": int,
    "high": int,
    "medium": int,
    "low": int,
    "severity_breakdown": {         # MUST be JSONB-serializable dict
      "critical": int,
      "high": int,
      "medium": int,
      "low": int
    }
  },
  "scan_trend": [                   # 8 most recent scans, oldest first
    {
      "date": "Jan 13",             # formatted as "Mon DD"
      "posture_score": float,
      "critical": int,
      "high": int,
      "medium": int,
      "low": int,
      "total": int
    }
  ],
  "module_scores": [                # per-module pass/fail for middle panel
    {
      "module": "Module Name",
      "pass": int,
      "total": int,
      "color": "#hex"               # optional accent color
    }
  ],
  "findings": [],                   # paginated list for table tabs
  "page_context": {
    "title": "Page Title",
    "brief": "One-sentence description",
    "tabs": [
      { "id": "tab_id", "label": "Tab Label", "count": int }
    ]
  }
}
```

**Every engine's DB report table MUST have these columns:**

```sql
-- {engine}_report table required columns
scan_run_id         VARCHAR(255) NOT NULL,
tenant_id           VARCHAR(255) NOT NULL,
account_id          VARCHAR(255),          -- NULL = all accounts aggregate
provider            VARCHAR(50),           -- NULL = all providers aggregate
posture_score       NUMERIC(5,2),          -- 0.00 to 100.00
total_findings      INTEGER DEFAULT 0,
critical_findings   INTEGER DEFAULT 0,
high_findings       INTEGER DEFAULT 0,
medium_findings     INTEGER DEFAULT 0,
low_findings        INTEGER DEFAULT 0,
findings_by_module  JSONB,                 -- { module_name: { pass, fail, total } }
severity_breakdown  JSONB,                 -- { critical, high, medium, low }
created_at          TIMESTAMP WITH TIME ZONE DEFAULT NOW()
-- NOTE: DO NOT overwrite rows on re-scan — insert new row so trend queries work
```

---

## 2. Page-by-Page: Engine Contract → BFF Contract → UI Contract

---

### 2.1 Threat Detection

**Status:** ✅ BFF view exists | ✅ Engine ui-data exists

#### CONTRACT A — Threat Engine Must Return

```python
# GET http://engine-threat:8020/api/v1/threat/ui-data
# Query params: tenant_id, provider?, account_id?, region?, scan_run_id?
{
  "kpi": {
    "total": int,
    "critical": int,
    "high": int,
    "medium": int,
    "low": int,
    "active": int,
    "resolved": int,
    "unassigned": int,
    "avg_risk_score": float,           # AVG(risk_score)
    "attack_path_count": int,          # COUNT WHERE has_attack_path=true ❌ ADD
    "posture_score": float             # detection effectiveness score ❌ ADD
  },
  "threats": [
    {
      "id": "uuid",
      "provider": "aws",
      "account": "123456789",
      "region": "us-east-1",
      "resourceType": "ec2",
      "title": "Threat title",
      "severity": "critical",
      "riskScore": 0-100,
      "status": "active",
      "mitreTechnique": "T1078",
      "threat_category": "initial_access",
      "isInternetExposed": bool,
      "hasAttackPath": bool,           # ❌ ADD to threat_findings
      "assignee": "user@email.com",    # ❌ ADD to threat_findings
      "lastSeen": "ISO datetime",
      "detected": "ISO datetime",
      "remediationSteps": ["step 1"]
    }
  ],
  "trend_data": [                      # 30 daily points
    { "date": "Feb 28", "critical": 10, "high": 32, "medium": 18, "low": 5 }
  ],
  "sparklines": {                      # 10 weekly points per KPI
    "total":       [int × 10],
    "critical":    [int × 10],
    "high":        [int × 10],
    "risk_score":  [float × 10],
    "attack_paths":[int × 10],
    "active":      [int × 10]
  },
  "mitre_matrix": {
    "Initial Access": [
      { "technique": "T1078", "count": 5, "severity": "critical" }
    ]
  },
  "attack_chains": [
    { "path_id": "uuid", "stages": [...], "risk_score": float }
  ],
  "toxic_combinations": [
    { "id": "uuid", "title": str, "risk_score": float, "resources": [...] }
  ],
  "threat_intel": [...]
}
```

#### CONTRACT B — BFF `/views/threats` Must Return (to UI)

```python
# Same shape — BFF passes through threat engine response
# BFF adds: filters applied, scan metadata
{
  "threats": [...],            # from threat engine
  "kpi": {...},                # from threat engine
  "trendData": [...],          # from threat engine trend_data
  "mitreMatrix": {...},        # from threat engine mitre_matrix
  "attackChains": [...],       # from threat engine
  "toxicCombinations": [...],  # from threat engine
  "threatIntel": [...],        # from threat engine
  "metadata": { "scan_run_id": str, "generated_at": str }
}
```

#### Validation Checklist

```
□ threat_findings.has_attack_path BOOLEAN column exists
□ threat_findings.assignee VARCHAR column exists
□ kpi.attack_path_count = COUNT(has_attack_path=true)
□ kpi.avg_risk_score = AVG(risk_score) rounded to 1 decimal
□ sparklines arrays each have exactly 10 elements
□ trend_data has 30 entries (one per day) or uses actual scan dates
□ mitre_matrix keys match MITRE ATT&CK tactic names exactly
□ each threat has all 14 UI-required fields (see CONTRACT A threats[])
□ status values are one of: active, investigating, resolved, suppressed, false-positive
```

---

### 2.2 IAM Security

**Status:** ✅ BFF view exists | ⚠️ Engine missing: scan_trend, module_scores, MFA stats

#### CONTRACT A — IAM Engine Must Return

```python
# GET http://engine-iam:8003/api/v1/iam-security/ui-data
{
  "kpi": {
    "posture_score": float,            # ✅ exists
    "total_findings": int,             # ✅ exists
    "critical": int,                   # ✅ exists
    "high": int,                       # ✅ exists
    "medium": int,                     # ✅ exists
    "low": int,                        # ✅ exists
    "identity_count": int,             # ❌ ADD: COUNT(DISTINCT resource_uid WHERE type='user')
    "keys_to_rotate": int,             # ❌ ADD: COUNT WHERE module='key_rotation' AND status='FAIL'
    "mfa_adoption_pct": float,         # ❌ ADD: 100 - (no_mfa_count / identity_count * 100)
    "overprivileged_count": int,       # ❌ ADD: COUNT WHERE module='overprivileged'
    "no_mfa_count": int,               # ❌ ADD: COUNT WHERE module='no_mfa' AND status='FAIL'
    "severity_breakdown": { critical, high, medium, low }  # ✅ exists
  },
  "scan_trend": [                      # ❌ ADD: last 8 scans from iam_report history
    {
      "date": "Jan 13",
      "posture_score": float,
      "total_findings": int,
      "overprivileged": int,
      "no_mfa": int,
      "total_identities": int,
      "safe": int                      # = total_identities - overprivileged - no_mfa
    }
  ],
  "module_scores": [                   # ❌ ADD: from findings_by_module JSONB
    { "module": "No MFA",              "pass": int, "total": int },
    { "module": "Overprivileged",      "pass": int, "total": int },
    { "module": "Key Rotation",        "pass": int, "total": int },
    { "module": "Privilege Escalation","pass": int, "total": int },
    { "module": "Service Accounts",    "pass": int, "total": int },
    { "module": "Admin Policies",      "pass": int, "total": int }
  ],
  "identities": [                      # ✅ exists (overview tab)
    {
      "username": str, "type": str, "account": str,
      "policies": int, "severity": str, "risk_score": int, "mfa": bool
    }
  ],
  "roles": [...],                      # ✅ exists
  "accessKeys": [...],                 # ✅ exists
  "privilegeEscalation": [...],        # ✅ exists
  "kpiGroups": [                       # ✅ exists (legacy format, keep for compat)
    {
      "title": "Severity & Score",
      "items": [
        {"label": "Posture Score", "value": float},
        {"label": "Total Findings", "value": int},
        {"label": "Critical", "value": int},
        {"label": "High", "value": int},
        {"label": "Medium", "value": int},
        {"label": "Low", "value": int}
      ]
    },
    {
      "title": "Identity Metrics",
      "items": [
        {"label": "Identities", "value": int},
        {"label": "Keys to Rotate", "value": int},
        {"label": "MFA Adoption", "value": float}
      ]
    }
  ],
  "page_context": { title, brief, tabs }
}
```

#### CONTRACT B — BFF `/views/iam` Must Return

```python
# BFF passes through engine response but restructures for UI
{
  "identities": [...],         # from engine identities[]
  "roles": [...],              # from engine roles[]
  "accessKeys": [...],         # from engine accessKeys[]
  "privilegeEscalation": [...],
  "kpiGroups": [...],          # from engine kpiGroups[]
  "pageContext": {...},        # from engine page_context
  "scanTrend": [...],          # ❌ ADD: from engine scan_trend[] (for IAM stacked area chart)
  "moduleScores": [...]        # ❌ ADD: from engine module_scores[]
}
```

#### Validation Checklist

```
□ iam_report table has one row PER scan (not overwritten) — verify with:
    SELECT COUNT(*), COUNT(DISTINCT scan_run_id) FROM iam_report WHERE tenant_id=X
    → both counts should be equal and > 1 after multiple scans
□ kpi.identity_count > 0 (COUNT DISTINCT of users/roles)
□ kpi.keys_to_rotate matches COUNT of iam_findings WHERE iam_modules @> '{key_rotation}' AND status='FAIL'
□ kpi.mfa_adoption_pct is between 0 and 100
□ scan_trend has 8 entries ordered by scan date ascending
□ scan_trend[].safe = total_identities - overprivileged - no_mfa (verify formula)
□ module_scores 6 modules all present with pass <= total
□ identities[].mfa is a boolean not null
□ identities[].risk_score is 0-100
```

---

### 2.3 Network Security

**Status:** ❌ BFF view missing | ❌ Engine ui-data endpoint missing

#### CONTRACT A — Network Engine Must Return

```python
# GET http://engine-network:8006/api/v1/network/ui-data  ← BUILD THIS
{
  "kpi": {
    "posture_score": float,
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "exposed_resources": int,        # COUNT DISTINCT resource_uid WHERE effective_exposure IN ('internet','any')
    "internet_exposed": int,         # COUNT WHERE exposure='internet'
    "open_sgs": int,                 # COUNT WHERE module='security_groups' AND exposure!='none'
    "waf_coverage_pct": float,       # waf_protected_lb / total_lb * 100
    "severity_breakdown": {...}
  },
  "scan_trend": [                    # 8 scans from network_report history
    {
      "date": "Jan 13",
      "posture_score": float,
      "critical": int, "high": int, "medium": int, "low": int, "total": int,
      "exposed_ports": int,
      "open_sgs": int
    }
  ],
  "module_scores": [
    { "module": "Security Groups",   "pass": int, "total": int },
    { "module": "Internet Exposure", "pass": int, "total": int },
    { "module": "WAF / DDoS",        "pass": int, "total": int },
    { "module": "VPC Topology",      "pass": int, "total": int },
    { "module": "DNS Security",      "pass": int, "total": int },
    { "module": "Load Balancer",     "pass": int, "total": int }
  ],
  "findings": [                      # overview tab
    {
      "resource_name": str, "rule_id": str, "module": str,
      "severity": str, "status": str, "account_id": str, "region": str, "resource_type": str
    }
  ],
  "security_groups": [...],          # SG tab
  "internet_exposure": [...],        # exposure tab
  "topology": [...],                 # VPC topology tab
  "waf": [...],                      # WAF tab
  "kpiGroups": [...],                # legacy compat
  "page_context": {...}
}
```

#### CONTRACT B — BFF `/views/network-security` Must Return

```python
# BUILD THIS in bff_views.py
# Single engine call → pass through engine response
{
  "findings": [...],
  "securityGroups": [...],
  "internetExposure": [...],
  "topology": [...],
  "waf": [...],
  "kpiGroups": [...],
  "pageContext": {...},
  "scanTrend": [...],
  "moduleScores": [...]
}
```

#### Validation Checklist

```
□ network_report table exists with posture_score, exposure_summary JSONB columns
□ network_report has multiple rows (one per scan) — trend will show 1 point otherwise
□ exposure_summary JSONB has keys: internet_exposed, cross_vpc, isolated, waf_protected
□ findings_by_module JSONB has all 6 module keys
□ kpi.waf_coverage_pct formula: engine queries network_findings WHERE module='waf'
□ network_findings.effective_exposure values are from enum: internet, cross_vpc, internal, isolated, none
□ network_security_groups table exists for SG tab
□ network_topology_snapshot table exists for topology tab
```

---

### 2.4 Data Security

**Status:** ✅ BFF view exists | ⚠️ Missing scan_trend in engine response

#### CONTRACT A — DataSec Engine Must Return

```python
# GET http://engine-datasec:8004/api/v1/data-security/ui-data  ✅ exists
{
  "kpi": {
    "posture_score": float,            # ✅ = data_risk_score
    "total_findings": int,             # ✅
    "critical": int, "high": int, "medium": int, "low": int,  # ✅
    "exposed_stores": int,             # ✅ = public_data_stores
    "dlp_violations": int,             # ❌ ADD: COUNT WHERE modules @> '{dlp}'
    "unencrypted_stores": int,         # ✅ derived from encrypted_pct
    "total_data_stores": int,          # ✅
    "classified_pct": float,           # ✅
    "severity_breakdown": {...}        # ✅
  },
  "scan_trend": [                      # ❌ ADD: query datasec_report history
    {
      "date": str, "posture_score": float,
      "critical": int, "high": int, "medium": int, "low": int, "total": int
    }
  ],
  "module_scores": [                   # ✅ from findings_by_module JSONB, restructure as array
    { "module": "Data Classification", "pass": int, "total": int },
    { "module": "Encryption Coverage", "pass": int, "total": int },
    { "module": "Public Access",       "pass": int, "total": int },
    { "module": "DLP Rules",           "pass": int, "total": int },
    { "module": "Data Residency",      "pass": int, "total": int },
    { "module": "Access Monitoring",   "pass": int, "total": int }
  ],
  "catalog": [...],          # ✅ data store inventory
  "classifications": [...],  # ✅
  "dlp": [...],              # ✅
  "encryption": [...],       # ✅
  "residency": [...],        # ✅
  "accessMonitoring": [...], # ✅
  "kpiGroups": [...],        # ✅
  "page_context": {...}      # ✅
}
```

#### Validation Checklist

```
□ datasec_report has multiple rows per tenant (historical trends work)
□ kpi.dlp_violations = COUNT WHERE datasec_modules @> '{dlp}'
□ kpi.exposed_stores = COUNT DISTINCT resource_uid WHERE modules @> '{public_access}' AND status='FAIL'
□ module_scores is an array (not the raw JSONB dict)
□ scan_trend[].posture_score uses data_risk_score field
□ catalog[] rows have: resource_uid, resource_type, service, classification, encryption_status
□ classifications[].sensitivity_score is 0-100
```

---

### 2.5 Encryption

**Status:** ❌ BFF view missing | ❌ Engine ui-data endpoint missing

#### CONTRACT A — Encryption Engine Must Return

```python
# GET http://engine-encryption:8007/api/v1/encryption/ui-data  ← BUILD THIS
{
  "kpi": {
    "posture_score": float,
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "total_resources": int,
    "encrypted_resources": int,
    "unencrypted_resources": int,      # = total - encrypted
    "expiring_certs_90d": int,         # COUNT WHERE cert_expiry BETWEEN NOW() AND NOW()+90d
    "keys_without_rotation": int,      # COUNT WHERE rotation_enabled=false
    "severity_breakdown": {...}
  },
  "scan_trend": [                      # 8 scans from encryption_report history
    {
      "date": str, "posture_score": float,
      "critical": int, "high": int, "medium": int, "low": int, "total": int
    }
  ],
  "module_scores": [
    { "module": "KMS Keys",       "pass": int, "total": int },
    { "module": "S3 Buckets",     "pass": int, "total": int },
    { "module": "RDS Instances",  "pass": int, "total": int },
    { "module": "EBS Volumes",    "pass": int, "total": int },
    { "module": "TLS/HTTPS",      "pass": int, "total": int },
    { "module": "Certificates",   "pass": int, "total": int }
  ],
  "findings": [...],
  "keys": [                            # Key inventory tab
    {
      "key_arn": str, "key_alias": str, "key_state": str,
      "rotation_enabled": bool, "rotation_interval_days": int,
      "pending_deletion_days": int, "grant_count": int
    }
  ],
  "certificates": [...],               # Cert tab
  "secrets": [...],                    # Secrets tab
  "kpiGroups": [...],
  "page_context": {...}
}
```

#### Validation Checklist

```
□ encryption_key_inventory table exists with pending_deletion_days column
□ expiring_certs_90d formula: COUNT WHERE cert_expiry IS NOT NULL AND cert_expiry < NOW() + 90 days
□ unencrypted_resources = total_resources - encrypted_resources (verify arithmetic)
□ posture_score formula: (coverage*0.35 + rotation*0.25 + algorithm*0.20 + transit*0.20)
□ module_scores pass <= total for all 6 modules
□ encryption_report has historical rows for scan_trend
```

---

### 2.6 Database Security

**Status:** ❌ BFF view missing | ❌ No dedicated engine — uses Check engine filtered

#### CONTRACT A — Check Engine Must Return (DB-filtered endpoint)

```python
# GET http://engine-check:8002/api/v1/check/ui-data?domain=database  ← BUILD THIS
# Filters check_findings WHERE resource_type IN ('rds','aurora','dynamodb','elasticache','redshift','documentdb')

DB_RESOURCE_TYPES = ['rds', 'aurora', 'dynamodb', 'elasticache', 'redshift', 'documentdb', 'neptune']

{
  "kpi": {
    "posture_score": float,    # passed_db_controls / total_db_controls * 100
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "public_databases": int,   # COUNT DISTINCT WHERE rule_id LIKE '%public%' AND status='FAIL'
    "unencrypted_dbs": int,    # COUNT DISTINCT WHERE rule_id LIKE '%encrypt%' AND status='FAIL'
    "severity_breakdown": {...}
  },
  "scan_trend": [              # derived from check_findings grouped by week
    {
      "date": str,
      "posture_score": float,  # pass rate that week
      "critical": int, "high": int, "medium": int, "low": int, "total": int
    }
  ],
  "module_scores": [           # grouped by rule category
    { "module": "Access Control",   "pass": int, "total": int },
    { "module": "Encryption",       "pass": int, "total": int },
    { "module": "Audit Logging",    "pass": int, "total": int },
    { "module": "Backup & Recovery","pass": int, "total": int },
    { "module": "Network Security", "pass": int, "total": int },
    { "module": "Configuration",    "pass": int, "total": int }
  ],
  "findings": [...],           # all DB findings
  "access_control": [...],
  "encryption_status": [...],
  "audit_logging": [...],
  "backup_recovery": [...],
  "network": [...],
  "kpiGroups": [...],
  "page_context": {
    "title": "Database Security",
    "brief": "...",
    "tabs": [overview, access_control, encryption, audit_logging, backup, network]
  }
}
```

#### Rule Category Mapping (in Check Engine)

```python
# Check engine needs this categorization logic:
DB_MODULE_RULES = {
  "access_control":  ["rds.iam_auth", "rds.master_username", "dynamodb.fine_grained_access"],
  "encryption":      ["rds.encryption", "rds.storage_encrypted", "dynamodb.encryption", "elasticache.encryption"],
  "audit_logging":   ["rds.cloudwatch_logs", "rds.enhanced_monitoring", "rds.audit_log"],
  "backup_recovery": ["rds.backup_retention", "rds.multi_az", "rds.automated_backup"],
  "network_security":["rds.publicly_accessible", "rds.vpc", "rds.sg_ingress"],
  "configuration":   ["rds.minor_upgrade", "rds.deletion_protection", "rds.parameter_group"]
}
```

#### Validation Checklist

```
□ check_findings.resource_type values include 'rds', 'aurora', 'dynamodb' etc.
□ check_findings.posture_category column exists (or rule_category — for module grouping)
□ DB posture_score = passed / total only for DB resource types
□ public_databases count: verify rule_id patterns match actual check rule IDs
□ scan_trend derived by grouping check_findings by week (Pattern B from UI-DATA-MAPPING.md)
□ module_scores all 6 categories have total > 0 (if no rules in category, return total=0 not omit)
```

---

### 2.7 Container Security

**Status:** ❌ BFF view missing | ❌ No dedicated engine — uses Check engine filtered

#### CONTRACT A — Check Engine Must Return (container-filtered endpoint)

```python
# GET http://engine-check:8002/api/v1/check/ui-data?domain=container  ← BUILD THIS
# Filters WHERE resource_type IN ('eks_cluster','ecs_cluster','ecs_task_definition','ecr_repository','ecs_service')

CONTAINER_RESOURCE_TYPES = ['eks_cluster','ecs_cluster','ecs_task_definition','ecr_repository','ecs_service','k8s_deployment','k8s_pod']

{
  "kpi": {
    "posture_score": float,
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "vulnerable_images": int,    # COUNT DISTINCT WHERE resource_type IN ('ecr','ecs_task_def') AND severity IN ('critical','high')
    "privileged_containers": int, # COUNT WHERE rule_id LIKE '%privileged%' AND status='FAIL'
    "severity_breakdown": {...}
  },
  "scan_trend": [...],           # same Pattern B
  "module_scores": [
    { "module": "Cluster Security",  "pass": int, "total": int },
    { "module": "Workload Security", "pass": int, "total": int },
    { "module": "Image Security",    "pass": int, "total": int },
    { "module": "Network Exposure",  "pass": int, "total": int },
    { "module": "RBAC Access",       "pass": int, "total": int },
    { "module": "Runtime Audit",     "pass": int, "total": int }
  ],
  "findings": [...],
  "kpiGroups": [...],
  "page_context": {...}
}
```

#### Rule Category Mapping

```python
CONTAINER_MODULE_RULES = {
  "cluster_security":  ["eks.endpoint_public", "eks.secrets_encryption", "eks.control_plane_logging"],
  "workload_security": ["ecs.privileged_containers", "ecs.root_user", "k8s.pod_security"],
  "image_security":    ["ecr.image_scanning", "ecr.immutable_tags", "ecs.image_digest"],
  "network_exposure":  ["eks.public_endpoint", "ecs.public_ip", "k8s.ingress_tls"],
  "rbac_access":       ["eks.rbac_roles", "ecs.task_role_least_priv", "k8s.service_accounts"],
  "runtime_audit":     ["eks.audit_logging", "ecs.execution_role", "k8s.audit_policy"]
}
```

#### Validation Checklist

```
□ check_findings has rows with resource_type='eks_cluster', 'ecr_repository' etc.
□ vulnerable_images: confirms resource_type filter matches actual ECR findings
□ privileged_containers: verify rule_id LIKE '%privileged%' matches actual rule IDs
□ scan_trend has ≥2 data points (need ≥2 scan runs with container findings)
```

---

### 2.8 Posture Security / Misconfigurations

**Status:** ✅ BFF view exists | ⚠️ Currently reads from Threat engine — should read Check engine directly

#### CONTRACT A — Check Engine Must Return (full misconfig endpoint)

```python
# GET http://engine-check:8002/api/v1/check/ui-data  ← BUILD THIS (no domain filter)
{
  "kpi": {
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "passed": int,
    "failed": int,
    "pass_rate": float,               # passed / total * 100
    "services_affected": int,         # COUNT DISTINCT service
    "providers_affected": int,        # COUNT DISTINCT provider
    "auto_remediable": int,           # COUNT WHERE auto_remediable=true AND status='FAIL'
    "sla_breached": int,              # (see SLA formula)
    "avg_finding_age_days": float,    # AVG(NOW() - first_seen_at) in days
    "new_this_scan": int,             # delta vs previous scan_run_id
    "severity_breakdown": {...}
  },
  "scan_trend": [                     # 8 weekly points
    {
      "date": str, "passRate": float,
      "critical": int, "high": int, "medium": int, "low": int, "total": int
    }
  ],
  "by_service": [                     # for services affected bar chart
    { "service": "s3", "count": int, "pass": int, "fail": int }
  ],
  "by_category": [                    # for radar chart
    { "category": "encryption", "fail": int, "total": int }
  ],
  "by_account": [
    { "account": "123456789", "provider": "aws", "count": int }
  ],
  "findings": [                       # full findings for table
    {
      "rule_id": str, "title": str, "severity": str, "status": str,
      "service": str, "provider": str, "account_id": str, "region": str,
      "resource_uid": str, "posture_category": str,
      "age_days": int,                # EXTRACT(day FROM NOW() - first_seen_at)
      "sla_status": str,             # 'active' | 'breached'
      "auto_remediable": bool,
      "risk_score": int
    }
  ],
  "page_context": {...}
}
```

#### Required Schema Additions to `check_findings`

```sql
-- ADD these columns to check_findings table:
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS service VARCHAR(100);           -- e.g. 's3', 'iam', 'ec2'
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS posture_category VARCHAR(100);  -- e.g. 'encryption', 'access_control'
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS auto_remediable BOOLEAN DEFAULT false;
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS risk_score INTEGER DEFAULT 0;
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS title TEXT;                     -- human-readable finding title
ALTER TABLE check_findings ADD COLUMN IF NOT EXISTS remediation TEXT;               -- fix instructions
```

#### SLA Formula in Check Engine

```python
def sla_status(severity: str, first_seen_at: datetime) -> str:
    thresholds = {"critical": 1, "high": 7, "medium": 30, "low": 90}
    days_open = (datetime.utcnow() - first_seen_at).days
    sla_days = thresholds.get(severity, 90)
    return "breached" if days_open > sla_days else "active"
```

#### Validation Checklist

```
□ check_findings.service column populated from rule metadata (e.g. rule aws.s3.* → service='s3')
□ check_findings.posture_category populated from rule metadata
□ check_findings.auto_remediable populated from rule YAML definition
□ sla_breached count matches manual calculation: COUNT WHERE (severity='critical' AND age>1) OR (high AND age>7)...
□ by_service array ordered by count DESC, services with 0 findings excluded
□ by_category radar data: all 6 categories present even if fail=0
□ new_this_scan: verify using consecutive scan_run_ids for same tenant
□ scan_trend derived from check_findings weekly groups (Pattern B)
```

---

### 2.9 CIEM

**Status:** ❌ BFF view missing (uses threats view) | ⚠️ Threat engine has CIEM data but not structured

#### CONTRACT A — Threat Engine CIEM Module Must Return

```python
# GET http://engine-threat:8020/api/v1/ciem/ui-data  ← BUILD THIS
# Filter: threat_category IN ('ciem','identity_risk','log_analysis','correlation','anomaly')
{
  "kpi": {
    "posture_score": float,          # rules_triggered / total_ciem_rules * 100
    "total_findings": int,
    "critical": int, "high": int, "medium": int, "low": int,
    "rules_triggered": int,          # COUNT DISTINCT rule_id
    "unique_actors": int,            # COUNT DISTINCT actor_principal
    "l2_findings": int,              # COUNT WHERE threat_category='correlation'
    "l3_findings": int,              # COUNT WHERE l3_anomaly_score > 0
    "severity_breakdown": {...}
  },
  "scan_trend": [                    # 8 weekly points, CIEM findings only
    {
      "date": str, "posture_score": float,
      "critical": int, "high": int, "medium": int, "low": int, "total": int,
      "overprivileged": int,         # COUNT DISTINCT actor_principal per week
      "detections": int              # COUNT WHERE threat_category='anomaly'
    }
  ],
  "module_scores": [                 # NOTE: this is COMBINED (see below)
    { "module": "Log Collection",     "pass": int, "total": int },
    { "module": "Rule Detection",     "pass": int, "total": int },
    { "module": "Identity Risk",      "pass": int, "total": int },
    { "module": "Correlation Engine", "pass": int, "total": int },
    { "module": "Anomaly Detection",  "pass": int, "total": int },
    { "module": "Threat Intel",       "pass": int, "total": int }
  ],
  "top_critical": [...],             # top findings by risk_score DESC
  "identities": [                    # grouped by actor_principal
    {
      "actor_principal": str, "risk_score": int,
      "total_findings": int, "critical": int, "high": int,
      "rules_triggered": int, "services_used": int, "resources_touched": int
    }
  ],
  "top_rules": [                     # grouped by rule_id
    {
      "rule_id": str, "severity": str, "title": str,
      "finding_count": int, "rule_source": str,
      "unique_actors": int, "unique_resources": int
    }
  ],
  "log_sources": [                   # from ciem_log_sources table (BUILD THIS)
    {
      "source_type": str,            # 'CloudTrail', 'VPC Flow Logs', etc.
      "source_bucket": str,
      "source_region": str,
      "event_count": int,
      "earliest": str,
      "latest": str
    }
  ]
}
```

#### Required New Table: `ciem_log_sources`

```sql
CREATE TABLE IF NOT EXISTS ciem_log_sources (
  id               SERIAL PRIMARY KEY,
  scan_run_id      VARCHAR(255) NOT NULL,
  tenant_id        VARCHAR(255) NOT NULL,
  account_id       VARCHAR(255),
  source_type      VARCHAR(100),    -- 'CloudTrail', 'VPCFlowLogs', 'S3AccessLogs'
  source_bucket    VARCHAR(500),
  source_region    VARCHAR(50),
  event_count      BIGINT DEFAULT 0,
  earliest_event   TIMESTAMP WITH TIME ZONE,
  latest_event     TIMESTAMP WITH TIME ZONE,
  created_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

#### CIEM Module Score Sources (multi-engine)

```python
# Log Collection: onboarding engine (accounts with CloudTrail enabled / total accounts)
log_collection_pass = GET /onboarding/accounts?cloudtrail=enabled COUNT
log_collection_total = GET /onboarding/accounts COUNT

# Rule Detection: rule engine (active CIEM rules)
rule_detection_pass = COUNT(DISTINCT rule_id) FROM ciem findings (rules that fired)
rule_detection_total = COUNT(*) FROM rule_metadata WHERE category='ciem'

# Identity Risk: iam engine data
identity_risk_at_risk = uniqueActors
identity_risk_total = iam_engine.kpi.identity_count

# Correlation Engine: threat engine
correlation_pass = l2_findings (correlations found)
correlation_total = total_ciem_findings

# Anomaly Detection: threat engine
anomaly_pass = l3_findings
anomaly_total = total_ciem_findings

# Threat Intel: threat intel matches
intel_pass = COUNT WHERE threat_intel_match=true
intel_total = total_ciem_findings
```

#### Validation Checklist

```
□ threat_findings has rows WHERE threat_category='ciem' or 'correlation' or 'anomaly'
□ unique_actors = COUNT(DISTINCT actor_principal) — actor_principal NOT NULL
□ l2_findings = COUNT WHERE threat_category='correlation'
□ l3_findings = COUNT WHERE l3_anomaly_score > 0 (or threat_category='anomaly')
□ identities[] rows aggregated correctly: total_findings per actor matches raw count
□ top_rules[] rule_source values: 'correlation', 'baseline', or 'direct'
□ ciem_log_sources table populated during discovery/CIEM scan
□ log_sources[] latest date is within last 7 days (data freshness check)
```

---

### 2.10 Compliance

**Status:** ✅ BFF view exists | ⚠️ Missing per-framework severity breakdown

#### CONTRACT A — Compliance Engine Must Return (additions needed)

```python
# GET http://engine-compliance:8010/api/v1/compliance/ui-data  ✅ mostly exists
{
  "frameworks": [
    {
      "compliance_framework": str,
      "framework_name": str,
      "total_controls": int,
      "passed_controls": int,
      "failed_controls": int,
      "partial_controls": int,
      "framework_score": float,
      "critical_controls": int,     # ❌ ADD: COUNT failed WHERE severity='critical'
      "high_controls": int,         # ❌ ADD
      "last_assessed": str          # ❌ ADD: timestamp of last scan for this framework
    }
  ],
  "posture_summary": {...},         # ✅
  "overall_score": float,           # ✅
  "failing_controls": [
    {
      "control_id": str, "title": str, "framework": str, "severity": str,
      "failing_resources": int, "passing_resources": int,
      "evidence": str, "remediation": str
    }
  ],
  "trend_data": [...],              # ✅
  "account_matrix": [               # ✅
    {
      "account": str, "provider": str,
      "CIS": float, "NIST": float, "PCI_DSS": float,  # etc.
    }
  ]
}
```

#### Validation Checklist

```
□ All 13 frameworks present: CIS, NIST, ISO27001, PCI-DSS, HIPAA, GDPR, SOC2, FedRAMP, CMMC, SWIFT, RBI, MAS, LGPD
□ framework_score for each = passed / total * 100 (verify calculation)
□ overall_score = AVG(framework_scores) — verify not just one framework
□ account_matrix has one row per (account × scan_run_id) not per (account × framework)
□ failing_controls sorted by failing_resources DESC
□ trend_data has one point per scan (≥8 points for sparkline to render)
```

---

### 2.11 Inventory

**Status:** ✅ BFF view exists | ⚠️ Missing cross-engine finding counts per asset

#### CONTRACT A — Inventory Engine Must Return (additions needed)

```python
# GET http://engine-inventory:8022/api/v1/inventory/ui-data  ✅ mostly exists
{
  "summary": {
    "total_assets": int,
    "total_relationships": int,
    "new_assets": int,             # ✅
    "removed_assets": int,         # ✅
    "changed_assets": int,         # ✅
    "providers_scanned": [...],
    "accounts_scanned": [...],
    "assets_by_provider": {...},
    "assets_by_resource_type": {...},
    "assets_by_region": {...}
  },
  "assets": [
    {
      "resource_id": str,
      "resource_name": str,
      "resource_type": str,
      "account_id": str,
      "provider": str,
      "region": str,
      "owner": str,
      "environment": str,
      "tags": {...},
      "last_scanned": str,
      "status": str,
      "findings": {                  # ❌ ADD: enriched by BFF from check engine
        "critical": int,
        "high": int,
        "medium": int,
        "low": int
      },
      "risk_score": int,             # ❌ ADD: MAX(risk_score) from check/threat findings
      "compliance_status": str       # ❌ ADD: from compliance engine (pass/fail/partial)
    }
  ]
}
```

#### BFF Enrichment for Inventory (in BFF Python)

```python
# BFF calls inventory engine AND check engine in parallel
# Then joins by resource_uid
async def build_inventory_view(tenant_id, filters):
    inventory_data, check_summary = await asyncio.gather(
        get("/inventory/ui-data"),
        get("/check/findings/by-resource")  # endpoint returns {resource_uid: {c,h,m,l}}
    )
    # Enrich each asset with finding counts
    finding_map = {r["resource_uid"]: r for r in check_summary}
    for asset in inventory_data["assets"]:
        enrichment = finding_map.get(asset["resource_id"], {})
        asset["findings"] = enrichment.get("findings", {"critical":0,"high":0,"medium":0,"low":0})
        asset["risk_score"] = enrichment.get("max_risk_score", 0)
    return inventory_data
```

#### Validation Checklist

```
□ inventory_findings.resource_uid matches check_findings.resource_uid (same format: ARN for AWS)
□ drift table new_assets = resource_uids in scan_N NOT in scan_(N-1)
□ asset.findings populated from check engine JOIN (not null/zero for all assets)
□ at least one asset has findings.critical > 0 (verify join works)
□ assets_by_resource_type top 10 are correct service names
```

---

### 2.12 Risk

**Status:** ✅ BFF view exists | ⚠️ Risk score formula needs all 4 engine inputs

#### CONTRACT A — Risk Engine Must Return

```python
# GET http://engine-risk:8009/api/v1/risk/ui-data  ✅ exists
{
  "risk_score": float,               # 0-100 composite score
  "level": str,                      # critical/high/medium/low/minimal
  "component_scores": {              # ❌ ADD: breakdown of what drives the score
    "threat_score": float,           # from threat engine AVG(risk_score) × 0.35
    "compliance_score": float,       # from compliance engine (100 - overall_score) × 0.25
    "posture_score": float,          # from check engine (100 - pass_rate) × 0.25
    "iam_score": float               # from iam engine (100 - posture_score) × 0.15
  },
  "risk_register": [...],
  "risk_categories": [...],
  "mitigation_roadmap": [...],
  "scenarios": [...],
  "trend_data": [                    # ✅ historical risk scores
    { "date": str, "risk_score": float, "level": str }
  ]
}
```

#### Risk Score Calculation (in Risk Engine)

```python
# Risk engine calls other engines internally:
async def calculate_risk_score(tenant_id):
    threat_kpi, compliance_score, check_pass_rate, iam_posture = await asyncio.gather(
        get_threat_kpi(tenant_id),        # avg_risk_score field
        get_compliance_overall(tenant_id), # overall_score (0-100)
        get_check_pass_rate(tenant_id),    # pass_rate (0-100)
        get_iam_posture(tenant_id)         # posture_score (0-100)
    )
    # Invert scores where 100 = good (pass rate 80% → risk 20)
    threat_component    = threat_kpi["avg_risk_score"]          * 0.35
    compliance_component= (100 - compliance_score)              * 0.25
    posture_component   = (100 - check_pass_rate)               * 0.25
    iam_component       = (100 - iam_posture["posture_score"])  * 0.15
    return round(threat_component + compliance_component + posture_component + iam_component, 1)
```

#### Validation Checklist

```
□ risk_score is between 0-100
□ component_scores sum = risk_score (verify arithmetic)
□ level thresholds: critical≥80, high≥60, medium≥40, low≥20, minimal<20
□ trend_data has ≥8 points (stored after each scan run)
□ risk score changes between scans reflect actual finding changes
□ risk_register items sorted by risk_score DESC
```

---

## 3. Cross-Engine Enrichment Map

Which BFF views need parallel engine calls and how they're merged:

```
┌─────────────────────────────────────────────────────────────────────┐
│ BFF VIEW            │ ENGINE CALLS                 │ MERGE LOGIC     │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/dashboard    │ inventory.summary            │ Stitch into     │
│                     │ threat.kpi + mitre + toxic   │ unified         │
│                     │ compliance.frameworks         │ {kpi, charts,   │
│                     │ check.by_service              │  alerts,        │
│                     │ onboarding.accounts + scans   │  accounts}      │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/inventory    │ inventory.ui-data            │ LEFT JOIN on    │
│                     │ check.findings_by_resource    │ resource_uid    │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/compliance   │ compliance.ui-data            │ Join control    │
│                     │ check.findings (rule→control) │ findings to     │
│                     │ onboarding.accounts           │ frameworks      │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/ciem         │ threat.ciem/ui-data           │ Merge identity  │
│                     │ iam.kpi (identity_count)      │ counts, module  │
│                     │ onboarding.cloudtrail_status  │ scores          │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/database-sec │ check.ui-data?domain=database│ Filter + derive │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/container-sec│ check.ui-data?domain=container│ Filter + derive │
├─────────────────────┼──────────────────────────────┼─────────────────┤
│ /views/risk         │ risk.ui-data                  │ Risk engine     │
│                     │ (risk engine fetches others   │ handles         │
│                     │ internally)                   │ internally      │
└─────────────────────┴──────────────────────────────┴─────────────────┘
```

---

## 4. End-to-End Validation Protocol

When 100 data points arrive from real engines, validate in this order:

### Phase 1: Engine Health (per engine)

```bash
# For each engine, run:
curl http://engine-{name}:{port}/api/v1/health/ready

# Then verify ui-data returns non-empty:
curl "http://engine-{name}:{port}/api/v1/{engine}/ui-data?tenant_id=TEST"

# Validation criteria:
# 1. HTTP 200
# 2. kpi.total_findings > 0
# 3. kpi.posture_score between 0-100
# 4. scan_trend array length >= 2
# 5. module_scores array length >= 4
# 6. findings array length >= 1
```

### Phase 2: BFF View Validation (per page)

```bash
# For each page, call the BFF view and validate shape:
curl "http://gateway:8000/api/v1/views/{page}?tenant_id=TEST"

# Validation criteria per view:
# /views/threats:
#   threats.length > 0
#   kpi.total == threats.length (or pagination is working)
#   trendData.length == 30 (daily) or 10 (weekly)
#   Object.keys(mitreMatrix).length > 0

# /views/iam:
#   identities.length > 0
#   kpiGroups[0].items has 'Posture Score' item
#   scanTrend.length >= 2

# /views/misconfig:
#   findings.length > 0
#   kpi.pass_rate between 0-100
#   by_service.length > 0

# /views/compliance:
#   frameworks.length >= 3 (at least CIS, NIST, PCI-DSS)
#   overallScore between 0-100

# /views/inventory:
#   assets.length > 0
#   summary.total_assets > 0
#   AT LEAST ONE asset has findings.critical > 0 or findings.high > 0
```

### Phase 3: UI Reconciliation Test

For each page, compare the static fallback values used in the UI vs the real API values:

```python
# Test script concept:
# 1. Fetch live BFF view
# 2. Fetch static fallback from UI code
# 3. Compare field presence (not values)
# 4. Report any fields in UI that are null/undefined from live API

REQUIRED_FIELDS = {
    "iam": ["kpiGroups[0].items", "identities", "roles", "scanTrend", "moduleScores"],
    "threats": ["threats", "kpi.total", "trendData", "mitreMatrix"],
    "misconfig": ["findings", "kpi.pass_rate", "by_service", "by_category"],
    "compliance": ["frameworks", "overallScore", "failingControls"],
    "inventory": ["assets", "summary.total_assets", "summary.assets_by_provider"],
    "datasec": ["kpiGroups", "catalog", "moduleScores", "scanTrend"],
    "ciem": ["totalFindings", "identities", "topRules", "logSources", "scanTrend"]
}
```

### Phase 4: KPI Arithmetic Verification

```python
# Critical checks — these must hold exactly:

# IAM
assert kpi.critical + kpi.high + kpi.medium + kpi.low == kpi.total_findings
assert kpi.identity_count >= kpi.keys_to_rotate   # can't rotate more keys than identities
assert 0 <= kpi.mfa_adoption_pct <= 100
assert scanTrend[-1].safe == scanTrend[-1].total_identities - scanTrend[-1].overprivileged - scanTrend[-1].no_mfa

# Threats
assert kpi.active + kpi.resolved <= kpi.total
assert kpi.avg_risk_score between 0-100

# Compliance
assert sum(f.total_controls for f in frameworks) >= overall_posture.total_controls
assert 0 <= overallScore <= 100

# Misconfig
assert kpi.pass_rate == kpi.passed / kpi.total_findings * 100   (± 0.5 for rounding)
assert kpi.failed == kpi.total_findings - kpi.passed

# Inventory
assert summary.total_assets == len(assets)   (or total field + has_more flag)
assert summary.new_assets + summary.removed_assets + summary.changed_assets <= summary.total_assets
```

### Phase 5: Trend/Sparkline Completeness

```python
# All sparkline arrays must:
assert len(sparkline_array) >= 2          # minimum to render line
assert len(sparkline_array) <= 10         # maximum kept in UI

# Trend data must be ordered oldest → newest
assert trend_data[0].date < trend_data[-1].date

# Trend posture_score must be non-decreasing or have explanation
# (security posture generally improves over time — a spike means incident)
```

---

## 5. Missing Implementation Checklist (Prioritised)

### 🔴 Priority 1 — Blocks real data from appearing in UI

| # | Task | Owner | File to Create/Edit |
|---|------|-------|-------------------|
| 1 | Add `has_attack_path` + `assignee` columns to `threat_findings` | Backend | `shared/database/schemas/threat_schema.sql` |
| 2 | Add `scan_trend` to IAM engine ui-data response | Backend | `engines/iam/iam_engine/api/ui_data_router.py` |
| 3 | Add `module_scores` array to IAM engine response | Backend | `engines/iam/iam_engine/api/ui_data_router.py` |
| 4 | Add `identity_count`, `keys_to_rotate`, `mfa_adoption_pct` to IAM kpi | Backend | same |
| 5 | Build `GET /api/v1/check/ui-data` endpoint | Backend | `engines/check/common/api_server.py` |
| 6 | Add `service`, `posture_category`, `auto_remediable`, `title` to `check_findings` | Backend | `shared/database/schemas/check_schema.sql` |
| 7 | Build BFF `/views/network-security` | Backend | `shared/api_gateway/bff_views.py` |
| 8 | Build Network engine `GET /api/v1/network/ui-data` | Backend | `engines/network-security/.../api_server.py` |

### 🟡 Priority 2 — Data appears but incomplete/inaccurate

| # | Task | Owner | Notes |
|---|------|-------|-------|
| 9 | Build BFF `/views/encryption` | Backend | Call encryption engine ui-data |
| 10 | Build Encryption engine `GET /api/v1/encryption/ui-data` | Backend | |
| 11 | Build BFF `/views/ciem` (separate from threats) | Backend | |
| 12 | Build `/api/v1/ciem/ui-data` in threat engine | Backend | Filter by threat_category CIEM types |
| 13 | Add `scan_trend` to DataSec engine response | Backend | Query `datasec_report` history |
| 14 | Ensure all `{engine}_report` tables retain history (don't overwrite) | Backend/DB | Verify with COUNT(*) > 1 |
| 15 | Add `dlp_violations` count to DataSec kpi | Backend | COUNT WHERE modules@>'{dlp}' |

### 🟢 Priority 3 — Enhancement for richer UI

| # | Task | Notes |
|---|------|-------|
| 16 | Build BFF `/views/database-security` | Check engine filtered by DB types |
| 17 | Build BFF `/views/container-security` | Check engine filtered by container types |
| 18 | Add Check engine `?domain=database` and `?domain=container` params | |
| 19 | Create `ciem_log_sources` table + populate in CIEM scan | |
| 20 | Add `component_scores` to Risk engine response | Show threat/compliance/iam breakdown |
| 21 | Enrich inventory assets with per-asset finding counts (BFF join) | |
| 22 | Add compliance_status per asset to inventory | |

---

## 6. Static Fallback Replacement Guide

Each UI page uses static fallback data when the API returns empty. Once real data is flowing, these constants become test baselines:

| UI Constant | Page | Real API Field | Replace When |
|-------------|------|---------------|-------------|
| `IAM_KPI_FALLBACK` | iam | `kpiGroups[].items` | kpi.total_findings > 0 |
| `IAM_SCAN_TREND` | iam | `scanTrend[]` | scanTrend.length >= 2 |
| `IAM_SPARKLINES` | iam | `scanTrend[]` slices | scanTrend.length >= 8 |
| `MOCK_THREAT_TREND` | threats | `trendData[]` | trendData.length > 0 |
| `THREAT_SPARKLINES` | threats | `sparklines{}` | sparklines defined |
| `NET_SCAN_TREND` | network-security | `scanTrend[]` | scanTrend.length >= 2 |
| `NET_MODULE_SCORES` | network-security | `moduleScores[]` | moduleScores.length > 0 |
| `DS_KPI_FALLBACK` | datasec | `kpi{}` | kpi.total_findings > 0 |
| `ENC_SCAN_TREND` | encryption | `scanTrend[]` | scanTrend.length >= 2 |
| `DB_SPARKLINES` | database-security | `scanTrend[]` | scanTrend.length >= 2 |
| `CS_SPARKLINES` | container-security | `scanTrend[]` | scanTrend.length >= 2 |
| `CIEM_SCAN_TREND` | ciem | `scanTrend[]` | scanTrend.length >= 2 |
| `CIEM_MODULE_SCORES` | ciem | `moduleScores[]` | moduleScores.length > 0 |
| `MISCONFIG_SPARKLINES` | misconfig | `scanTrend[]` | scanTrend.length >= 8 |

**How to switch from static to live (per page):**

```javascript
// Pattern already used in UI — replace static array with API data:
const scanTrend = (data.scanTrend && data.scanTrend.length >= 2)
  ? data.scanTrend
  : IAM_SCAN_TREND;   // ← fallback only when API data insufficient

const moduleScores = (data.moduleScores && data.moduleScores.length > 0)
  ? data.moduleScores
  : IAM_MODULE_SCORES_FALLBACK;
```

---

## 7. Environment & Deployment Validation

```bash
# Verify all engine service DNS resolves in K8s:
kubectl exec -n threat-engine-engines deploy/api-gateway -- \
  sh -c 'for svc in engine-iam engine-threat engine-check engine-compliance engine-inventory engine-datasec engine-network engine-encryption engine-risk engine-onboarding; do echo -n "$svc: "; nslookup $svc 2>&1 | grep -c "Address"; done'

# Verify all engine health endpoints:
for ENGINE in iam threat check compliance inventory datasec; do
  kubectl port-forward svc/engine-$ENGINE :8001 &
  curl -s localhost:PORT/api/v1/health/ready | jq .status
done

# Verify BFF view endpoints return data:
kubectl port-forward svc/api-gateway 8000:8000 -n threat-engine-engines
for VIEW in threats iam compliance inventory datasec misconfig risk; do
  echo "=== /views/$VIEW ===" && curl -s "localhost:8000/api/v1/views/$VIEW?tenant_id=TEST" | jq '{total_findings: .kpi.total_findings, status: .success}'
done
```

---

*Document: `ENGINE-BFF-CONTRACTS.md` — Generated 2026-03-31*
*Companion to: `UI-DATA-MAPPING.md`*
