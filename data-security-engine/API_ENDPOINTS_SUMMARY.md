# Data Security Engine - API Endpoints Summary

## ✅ All 17 Endpoints Implemented

Base URL: `http://localhost:8000`
Swagger Docs: `http://localhost:8000/docs`

---

## 📊 Core Endpoints

### 1. Health & Status

```http
GET /
GET /health
```

**Purpose**: Check API availability
**Response**: `{"status": "healthy"}`

---

### 2. Generate Data Security Report

```http
POST /api/v1/data-security/scan
```

**Body**:
```json
{
  "csp": "aws",
  "scan_id": "latest",
  "tenant_id": "my-tenant",
  "include_classification": true,
  "include_lineage": true,
  "include_residency": true,
  "include_activity": true,
  "allowed_regions": ["us-east-1", "us-west-2", "ap-south-1"],
  "max_findings": 5000
}
```

**Response**: Complete report with all modules
**Use Case**: Trigger a new analysis run

---

## 🗂️ Discovery & Catalog Endpoints

### 3. Get Data Catalog

```http
GET /api/v1/data-security/catalog?csp=aws&scan_id=latest&account_id={id}&service={svc}&region={region}
```

**Query Params**:
- `csp` (required): Cloud provider
- `scan_id` (required): Scan identifier
- `account_id` (optional): Filter by account
- `service` (optional): Filter by service (s3, rds, dynamodb...)
- `region` (optional): Filter by region

**Response**:
```json
{
  "total_stores": 117,
  "filters": {...},
  "stores": [
    {
      "resource_id": "arn:aws:dynamodb:...",
      "resource_arn": "...",
      "resource_uid": "...",
      "resource_type": "dynamodb:table",
      "service": "dynamodb",
      "region": "ap-south-1",
      "account_id": "155052200811",
      "name": "threat-engine-accounts",
      "tags": {},
      "lifecycle_state": "ACTIVE",
      "health_status": "Healthy"
    }
  ]
}
```

**UI Use**: Data Catalog Browser, Resource Lists

---

## 🔍 Findings Endpoints

### 4. Get All Findings

```http
GET /api/v1/data-security/findings?csp=aws&scan_id=latest&account_id={id}&service={svc}&module={mod}&status={status}&resource_id={arn}
```

**Query Params**:
- `csp` (required)
- `scan_id` (required)
- `account_id` (optional)
- `service` (optional)
- `module` (optional): data_protection_encryption, data_access_governance, etc.
- `status` (optional): PASS, FAIL, WARN
- `resource_id` (optional): Filter by resource ARN/UID

**Response**:
```json
{
  "filters": {...},
  "summary": {
    "total_findings": 2429,
    "by_module": {
      "data_protection_encryption": 1791,
      "data_access_governance": 668,
      ...
    },
    "by_status": {"PASS": 1200, "FAIL": 1100, "WARN": 129}
  },
  "findings": [
    {
      "schema_version": "cspm_finding.v1",
      "scan_run_id": "latest",
      "rule_id": "aws.rds.instance.storage_encrypted",
      "status": "FAIL",
      "result": "FAIL",
      "resource_uid": "arn:aws:rds:...",
      "resource_arn": "...",
      "resource_id": "default",
      "resource_type": "secgrp",
      "service": "rds",
      "region": "ap-south-1",
      "account_id": "155052200811",
      "data_security_modules": ["data_protection_encryption"],
      "is_data_security_relevant": true,
      "data_security_context": {
        "modules": ["data_protection_encryption"],
        "categories": ["encryption", "sensitive_data_protection"],
        "priority": "high",
        "impact": {
          "gdpr": "Article 32 - Encryption requirement for personal data",
          "pci": "Requirement 3.4 - Render PAN unreadable via encryption",
          "hipaa": "§164.312(a)(2)(iv) - Encryption of ePHI at rest"
        },
        "sensitive_data_context": "Encryption is mandatory for..."
      }
    }
  ]
}
```

**UI Use**: All dashboards, filters, tables

---

### 5. Get Governance Findings for Resource

```http
GET /api/v1/data-security/governance/{resource_id}?csp=aws&scan_id=latest
```

**Response**: Findings filtered to access governance module
**UI Use**: Resource detail page - Governance tab

---

### 6. Get Protection Findings for Resource

```http
GET /api/v1/data-security/protection/{resource_id}?csp=aws&scan_id=latest
```

**Response**: Findings filtered to protection/encryption module
**UI Use**: Resource detail page - Protection tab

---

## 🎯 Module-Specific Endpoints

### 7. Classification

```http
GET /api/v1/data-security/classification?csp=aws&scan_id=latest&account_id={id}&service={svc}&resource_id={arn}
```

**Response**:
```json
{
  "total_resources": 50,
  "classified_resources": 45,
  "results": [
    {
      "resource_id": "user-uploads",
      "resource_arn": "arn:aws:s3:::user-uploads",
      "resource_type": "s3:bucket",
      "classification": ["PII", "SENSITIVE"],
      "confidence": 0.92,
      "matched_patterns": ["bucket_name:user", "public:true"]
    }
  ]
}
```

**UI Use**: Classification Dashboard, Resource Detail

---

### 8. Lineage

```http
GET /api/v1/data-security/lineage?csp=aws&scan_id=latest&account_id={id}&service={svc}&resource_id={arn}
```

**Response**:
```json
{
  "total_resources": 10,
  "lineage_graph": {
    "arn:aws:s3:::source-bucket": [
      {
        "source_resource_id": "source-bucket",
        "source_resource_type": "s3:bucket",
        "target_resource_id": "target-rds",
        "target_resource_type": "rds:instance",
        "transformation": "ETL via Lambda",
        "relationship_type": "data_flow",
        "timestamp": "2026-01-18T10:00:00Z"
      }
    ]
  }
}
```

**UI Use**: Lineage Dashboard (graph visualization)

---

### 9. Residency

```http
GET /api/v1/data-security/residency?csp=aws&scan_id=latest&account_id={id}&service={svc}&resource_id={arn}&allowed_regions=us-east-1,us-west-2
```

**Response**:
```json
{
  "total_resources": 117,
  "results": [
    {
      "resource_id": "arn:aws:dynamodb:...",
      "resource_arn": "...",
      "primary_region": "ap-south-1",
      "replication_regions": [],
      "policy_name": "tenant_policy",
      "compliance_status": "compliant",
      "violations": []
    },
    {
      "resource_id": "arn:aws:rds:...",
      "primary_region": "eu-central-1",
      "compliance_status": "non_compliant",
      "violations": ["Resource in non-allowed region: eu-central-1"]
    }
  ]
}
```

**UI Use**: Residency Dashboard (map view), Resource Detail

---

### 10. Activity Monitoring

```http
GET /api/v1/data-security/activity?csp=aws&scan_id=latest&account_id={id}&service={svc}&resource_id={arn}&days_back=7
```

**Response**:
```json
{
  "total_resources": 5,
  "days_back": 7,
  "activity": {
    "arn:aws:dynamodb:...": [
      {
        "event_id": "evt_abc123",
        "timestamp": "2026-01-18T10:30:00Z",
        "resource_id": "threat-engine-accounts",
        "resource_arn": "...",
        "principal": "arn:aws:iam::155052200811:user/admin",
        "action": "dynamodb:GetItem",
        "ip_address": "203.0.113.5",
        "location": "Singapore",
        "anomaly_score": 0.85,
        "risk_level": "high",
        "alert_triggered": true
      }
    ]
  }
}
```

**UI Use**: Activity Monitoring Dashboard, Anomaly Alerts

---

### 11. Compliance

```http
GET /api/v1/data-security/compliance?csp=aws&scan_id=latest&account_id={id}&service={svc}&resource_id={arn}&framework=gdpr
```

**Query Params**:
- `framework` (optional): gdpr, pci, hipaa, soc2, iso27001

**Response**:
```json
{
  "account_id": null,
  "framework": "gdpr",
  "summary": {
    "total_findings": 850,
    "by_framework": {
      "gdpr": {"total": 850, "pass": 612, "fail": 238}
    },
    "by_status": {"PASS": 612, "FAIL": 238}
  },
  "findings": [
    {
      "rule_id": "aws.s3.bucket.encryption_at_rest_enabled",
      "status": "FAIL",
      "data_security_context": {
        "impact": {
          "gdpr": "Article 32 - Encryption requirement for personal data"
        }
      }
    }
  ]
}
```

**UI Use**: Compliance Dashboard, Framework Scorecards

---

## 🏢 Account & Service Endpoints

### 12. Account Overview

```http
GET /api/v1/data-security/accounts/{account_id}?csp=aws&scan_id=latest&service={svc}
```

**Response**:
```json
{
  "account_id": "155052200811",
  "summary": {
    "total_findings": 1500,
    "total_data_stores": 75,
    "findings_by_status": {"PASS": 900, "FAIL": 600},
    "findings_by_module": {
      "data_protection_encryption": 800,
      "data_access_governance": 400,
      ...
    },
    "services": ["s3", "rds", "dynamodb", "redshift"]
  },
  "findings": [...],
  "data_stores": [...]
}
```

**UI Use**: Account Dashboard, Account Selector

---

### 13. Service Overview

```http
GET /api/v1/data-security/services/{service}?csp=aws&scan_id=latest&account_id={id}
```

**Response**:
```json
{
  "service": "rds",
  "account_id": null,
  "summary": {
    "total_findings": 450,
    "total_resources": 35,
    "findings_by_status": {"PASS": 200, "FAIL": 250},
    "findings_by_module": {...},
    "accounts": ["155052200811", "194722442770"]
  },
  "findings": [...],
  "resources": [...]
}
```

**UI Use**: Service Dashboard, Service Selector

---

## 🛠️ Utility Endpoints

### 14. List Modules

```http
GET /api/v1/data-security/modules
```

**Response**:
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

**UI Use**: Module selector, navigation menu

---

### 15. Get Rules by Module

```http
GET /api/v1/data-security/modules/{module}/rules?service=s3
```

**Response**:
```json
{
  "module": "data_protection_encryption",
  "rules": {
    "s3": [
      "aws.s3.bucket.encryption_at_rest_enabled",
      "aws.s3.bucket.default_encryption_enabled",
      "aws.s3.bucket.require_tls_in_transit_configured",
      ...
    ],
    "rds": [...],
    "dynamodb": [...]
  }
}
```

**UI Use**: Rule browser, policy configuration

---

### 16. Get Rule Details

```http
GET /api/v1/data-security/rules/{rule_id}?service=dynamodb
```

**Response**:
```json
{
  "rule_id": "aws.dynamodb.accelerator.cluster_encryption_enabled",
  "metadata": {
    "title": "DAX cluster encryption enabled",
    "description": "Verifies that Amazon DynamoDB Accelerator (DAX) cluster has encryption at rest enabled...",
    "severity": "high",
    "scope": "dynamodb.accelerator.data_protection",
    "domain": "data_protection",
    "compliance": [
      "gdpr_article_32",
      "pci_requirement_3_4",
      "hipaa_164_312_a_2_iv"
    ],
    "remediation": "1. Open DynamoDB console\n2. Select DAX cluster\n3. Enable encryption...",
    "references": [
      "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/DAXEncryptionAtRest.html"
    ]
  },
  "data_security": {
    "applicable": true,
    "modules": ["data_protection_encryption"],
    "categories": ["encryption", "sensitive_data_protection"],
    "priority": "high",
    "impact": {
      "gdpr": "Article 32 - Encryption requirement for personal data",
      "pci": "Requirement 3.4 - Render PAN unreadable via encryption",
      "hipaa": "§164.312(a)(2)(iv) - Encryption of ePHI at rest"
    },
    "sensitive_data_context": "Encryption is mandatory for all resources containing:\n- PII\n- PCI data\n- PHI\n- Financial records"
  }
}
```

**UI Use**: Finding detail modal, remediation steps

---

## 📁 Output File Structure (Alternative to API)

For UI that reads directly from files:

```
{timestamp}/{account_id}/{csp}/{region}/
├── discovery/data_catalog.ndjson          ← All discovered resources
├── governance/access_analysis.ndjson      ← Access governance findings
├── protection/encryption_status.ndjson    ← Encryption findings
├── compliance/compliance_status.ndjson    ← Compliance findings
├── residency/location_map.ndjson          ← Residency results
├── residency/residency_findings.ndjson    ← Residency-related findings
├── monitoring/monitoring_findings.ndjson  ← Activity monitoring findings
├── classification/classified_data.ndjson  ← Classification results
├── lineage/data_lineage.json              ← Lineage graph
├── findings.ndjson                        ← All findings combined
└── summary.json                           ← Region summary stats
```

**Each file contains NDJSON (newline-delimited JSON)**:
```json
{"resource_id": "...", "status": "FAIL", ...}
{"resource_id": "...", "status": "PASS", ...}
```

**Summary file structure**:
```json
{
  "generated_at": "2026-01-18T15:12:57+00:00",
  "timestamp": "20260118_151257",
  "tenant_id": "test-tenant",
  "scan_run_id": "latest",
  "account_id": "155052200811",
  "csp": "aws",
  "region": "ap-south-1",
  "summary": {
    "total_findings": 147,
    "total_discovered_resources": 25,
    "classification_count": 0,
    "residency_count": 7
  }
}
```

---

## 🎯 API Mapping to UI Screens

### Executive Dashboard

| Metric | API Endpoint |
|--------|--------------|
| Total Data Stores | `GET /catalog` |
| Total Findings | `GET /findings` (summary) |
| Security Score | Calculate from PASS/FAIL ratio |
| Residency Compliance | `GET /residency` (count statuses) |
| Findings by Module | `GET /findings` (summary.by_module) |
| Top Risks | `GET /findings?status=FAIL` (sort by priority) |

### Data Catalog Browser

| Feature | API Endpoint |
|---------|--------------|
| List Resources | `GET /catalog?account_id=X&service=Y&region=Z` |
| Group by Account | `GET /catalog` → group in UI |
| Group by Service | `GET /catalog` → group in UI |
| Quick Security Status | Join catalog with findings by resource_id |

### Resource Detail View

| Tab | API Endpoint |
|-----|--------------|
| Overview | `GET /catalog?resource_id={arn}` |
| Protection | `GET /protection/{resource_id}` |
| Governance | `GET /governance/{resource_id}` |
| Compliance | `GET /compliance?resource_id={arn}` |
| Residency | `GET /residency?resource_id={arn}` |
| Classification | `GET /classification?resource_id={arn}` |
| Activity | `GET /activity?resource_id={arn}&days_back=7` |
| Remediation Steps | `GET /rules/{rule_id}` (metadata.remediation) |

### Protection Dashboard

| Metric | API Endpoint |
|--------|--------------|
| Encryption Rate | `GET /findings?module=data_protection_encryption` |
| Unencrypted Resources | `GET /findings?module=data_protection_encryption&status=FAIL` |
| By Service Breakdown | `GET /services/{service}` (filter module in UI) |

### Access Governance Dashboard

| Metric | API Endpoint |
|--------|--------------|
| Public Exposure Count | `GET /findings?module=data_access_governance&status=FAIL` (filter public_access rules) |
| Overly Permissive | `GET /findings?module=data_access_governance&status=FAIL` (filter rbac rules) |
| Top Violations | `GET /findings?module=data_access_governance&status=FAIL` (sort by priority) |

### Compliance Dashboard

| Framework | API Endpoint |
|-----------|--------------|
| GDPR | `GET /compliance?framework=gdpr` |
| PCI | `GET /compliance?framework=pci` |
| HIPAA | `GET /compliance?framework=hipaa` |
| All Frameworks | `GET /compliance` (aggregate by_framework) |

### Residency Dashboard

| Feature | API Endpoint |
|---------|--------------|
| Geographic Map | `GET /residency` → visualize by primary_region |
| Compliant/Non-Compliant | `GET /residency` (count by compliance_status) |
| Policy Configuration | Pass `allowed_regions` query param |
| Non-Compliant List | `GET /residency` (filter non_compliant) |

### Account Dashboard

| Section | API Endpoint |
|---------|--------------|
| Account Summary | `GET /accounts/{account_id}` |
| Services List | `GET /accounts/{account_id}` (summary.services) |
| Findings Breakdown | `GET /accounts/{account_id}` (findings array) |
| Regional Distribution | Group findings by region in UI |

### Service Dashboard

| Section | API Endpoint |
|---------|--------------|
| Service Summary | `GET /services/{service}` |
| Accounts List | `GET /services/{service}` (summary.accounts) |
| Common Issues | `GET /services/{service}` (group by rule_id) |
| Resources | `GET /services/{service}` (resources array) |

---

## 🚀 Starting the API Server

```bash
cd /Users/apple/Desktop/threat-engine/data-security-engine
python3 -m uvicorn data_security_engine.api_server:app --reload --host 0.0.0.0 --port 8000
```

**Swagger UI**: http://localhost:8000/docs
**ReDoc**: http://localhost:8000/redoc

---

## 📊 Sample UI API Call Sequences

### Load Executive Dashboard

```javascript
async function loadExecutiveDashboard() {
  const [findings, catalog, residency] = await Promise.all([
    fetch('/api/v1/data-security/findings?csp=aws&scan_id=latest'),
    fetch('/api/v1/data-security/catalog?csp=aws&scan_id=latest'),
    fetch('/api/v1/data-security/residency?csp=aws&scan_id=latest')
  ]);
  
  return {
    totalStores: catalog.total_stores,
    totalFindings: findings.summary.total_findings,
    securityScore: calculateScore(findings.summary.by_status),
    moduleBreakdown: findings.summary.by_module,
    residencyCompliance: {
      compliant: residency.results.filter(r => r.compliance_status === 'compliant').length,
      nonCompliant: residency.results.filter(r => r.compliance_status === 'non_compliant').length
    }
  };
}
```

### Load Resource Detail Page

```javascript
async function loadResourceDetail(resourceArn) {
  const [resource, findings, classification, residency] = await Promise.all([
    fetch(`/api/v1/data-security/catalog?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
    fetch(`/api/v1/data-security/findings?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
    fetch(`/api/v1/data-security/classification?csp=aws&scan_id=latest&resource_id=${resourceArn}`),
    fetch(`/api/v1/data-security/residency?csp=aws&scan_id=latest&resource_id=${resourceArn}`)
  ]);
  
  // Load remediation steps for each failing finding
  const failedFindings = findings.findings.filter(f => f.status === 'FAIL');
  const rulesDetails = await Promise.all(
    failedFindings.map(f => 
      fetch(`/api/v1/data-security/rules/${f.rule_id}?service=${f.service}`)
    )
  );
  
  return {
    resource: resource.stores[0],
    findings: findings.findings,
    classification: classification.results[0],
    residency: residency.results[0],
    remediationSteps: rulesDetails.map(r => r.metadata.remediation)
  };
}
```

### Load Compliance Dashboard (GDPR)

```javascript
async function loadComplianceDashboard(framework = 'gdpr') {
  const response = await fetch(
    `/api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=${framework}`
  );
  
  return {
    framework: framework.toUpperCase(),
    complianceRate: (response.summary.by_framework[framework].pass / 
                     response.summary.by_framework[framework].total * 100),
    totalControls: response.summary.by_framework[framework].total,
    passingControls: response.summary.by_framework[framework].pass,
    failingControls: response.summary.by_framework[framework].fail,
    findings: response.findings
  };
}
```

---

## 🔑 Required Fields in Every Finding

All findings include:
- `scan_run_id` - Scan identifier
- `resource_arn` or `resource_uid` - Resource identifier  
- `rule_id` - Rule that was checked
- `status` / `result` - PASS/FAIL/WARN
- `data_security_modules` - Which modules this affects
- `data_security_context` - Impact, priority, compliance mapping

---

## 📝 Notes for Frontend Developers

1. **Pagination**: For large datasets, implement client-side pagination (APIs return full results)
2. **Caching**: Cache catalog and rules responses (they don't change during a scan)
3. **Real-time Updates**: Poll `/findings` endpoint every 30s for live scans
4. **Error Handling**: All endpoints return 500 with error details on failure
5. **CORS**: Enabled for all origins (configure for production)
6. **Filters**: Combine multiple filters in single API call for efficiency

---

## 🎨 UI Design Principles

1. **Dashboard-First**: Start with high-level metrics, drill down to details
2. **Action-Oriented**: Every finding should have clear remediation steps
3. **Context-Rich**: Show compliance impact, not just pass/fail
4. **Visual**: Use charts, maps, and color coding (red/yellow/green)
5. **Filterable**: Every list should support filtering by account/service/region/status

---

## ✅ API Completeness Checklist

- ✅ Executive Dashboard endpoints
- ✅ Data Catalog endpoints
- ✅ Resource Detail endpoints
- ✅ Module-specific endpoints (6 modules)
- ✅ Account view endpoints
- ✅ Service view endpoints
- ✅ Utility endpoints (modules, rules)
- ✅ Swagger documentation (auto-generated)
- ✅ CORS enabled
- ✅ Error handling

**All endpoints are implemented and ready for UI integration!**



