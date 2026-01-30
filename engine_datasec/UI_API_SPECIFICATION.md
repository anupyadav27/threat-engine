# Data Security Engine - UI/API Specification

## Overview

This document defines the complete API specification for the Data Security UI, mapping UI screens to backend API endpoints.

---

## 🎯 UI Navigation Structure

```
┌─ Executive Dashboard (Level 1)
├─ Data Discovery & Catalog (Level 2)
│  └─ Resource Detail View (Level 3)
├─ Module Dashboards (Level 2)
│  ├─ Protection & Encryption
│  ├─ Access Governance
│  ├─ Compliance
│  ├─ Data Residency
│  ├─ Activity Monitoring
│  └─ Data Classification
├─ Account View (Level 2)
├─ Service View (Level 2)
└─ Trending & Analytics (Level 2)
```

---

## 📊 Level 1: Executive Dashboard

### Screen: Landing Page

**Purpose**: High-level overview of data security posture

**Metrics to Display**:
- Total data stores discovered
- Total findings (PASS/FAIL breakdown)
- Security score (% compliance)
- Residency compliance (compliant/non-compliant)
- Findings by module (bar chart)
- Top risks (critical/high findings)

**API Endpoints**:

```http
# Get overall summary
GET /api/v1/data-security/findings?csp=aws&scan_id=latest
Response:
{
  "summary": {
    "total_findings": 2429,
    "by_module": {
      "data_protection_encryption": 1791,
      "data_access_governance": 668,
      "data_compliance": 360,
      "data_activity_monitoring": 273,
      "data_residency": 134
    },
    "by_status": {"PASS": 1200, "FAIL": 1100, "WARN": 129}
  },
  "findings": [...]
}

# Get total data stores
GET /api/v1/data-security/catalog?csp=aws&scan_id=latest
Response:
{
  "total_stores": 117,
  "filters": {...},
  "stores": [...]
}

# Get residency summary
GET /api/v1/data-security/residency?csp=aws&scan_id=latest
Response:
{
  "total_resources": 117,
  "results": [
    {
      "compliance_status": "compliant",
      "resource_id": "...",
      "primary_region": "us-east-1",
      ...
    }
  ]
}
```

---

## 🗂️ Level 2: Data Discovery & Catalog

### Screen: Data Catalog Browser

**Purpose**: Browse all discovered data stores with filtering

**Display**:
- Grouped view (by account/region/service)
- Quick security status per resource
- Filter/search capabilities

**API Endpoints**:

```http
# Get all data stores with filters
GET /api/v1/data-security/catalog?csp=aws&scan_id=latest&account_id={id}&service={svc}&region={region}
Response:
{
  "total_stores": 25,
  "filters": {
    "account_id": "155052200811",
    "service": "dynamodb",
    "region": "ap-south-1"
  },
  "stores": [
    {
      "resource_id": "arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts",
      "resource_arn": "arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts",
      "resource_uid": "arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts",
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

# Get list of accounts
GET /api/v1/data-security/catalog?csp=aws&scan_id=latest
# Extract unique account_ids from response

# Get list of services per account
GET /api/v1/data-security/accounts/{account_id}?csp=aws&scan_id=latest
Response:
{
  "account_id": "155052200811",
  "summary": {
    "total_findings": 1500,
    "total_data_stores": 75,
    "services": ["s3", "rds", "dynamodb", "redshift"]
  },
  "findings": [...],
  "data_stores": [...]
}
```

---

## 🔍 Level 3: Resource Detail View

### Screen: Individual Resource Dashboard

**Purpose**: Complete security posture for a single resource

**Tabs**:
1. Overview
2. Protection & Encryption
3. Access Governance
4. Compliance
5. Residency
6. Activity (if enabled)
7. Classification (if enabled)

**API Endpoints**:

```http
# Get all findings for a resource
GET /api/v1/data-security/findings?csp=aws&scan_id=latest&resource_id={arn}
Response:
{
  "summary": {
    "total_findings": 12,
    "by_module": {...},
    "by_status": {"PASS": 7, "FAIL": 5}
  },
  "findings": [
    {
      "schema_version": "cspm_finding.v1",
      "scan_run_id": "latest",
      "rule_id": "aws.dynamodb.accelerator.cluster_encryption_enabled",
      "status": "FAIL",
      "resource_uid": "arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts",
      "resource_arn": "arn:aws:dynamodb:ap-south-1:155052200811:table/threat-engine-accounts",
      "resource_id": "threat-engine-accounts",
      "service": "dynamodb",
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
        "sensitive_data_context": "Encryption is mandatory for all resources containing..."
      }
    }
  ]
}

# Get governance status
GET /api/v1/data-security/governance/{resource_id}?csp=aws&scan_id=latest
Response:
{
  "resource_id": "arn:aws:dynamodb:...",
  "findings": [
    {
      "rule_id": "aws.dynamodb.table.rbac_least_privilege",
      "status": "FAIL",
      "data_security_modules": ["data_access_governance"],
      ...
    }
  ]
}

# Get protection status
GET /api/v1/data-security/protection/{resource_id}?csp=aws&scan_id=latest
Response: {...}

# Get classification
GET /api/v1/data-security/classification?csp=aws&scan_id=latest&resource_id={arn}
Response:
{
  "total_resources": 1,
  "classified_resources": 1,
  "results": [
    {
      "resource_id": "threat-engine-accounts",
      "resource_arn": "arn:aws:dynamodb:...",
      "resource_type": "dynamodb:table",
      "classification": ["PII", "SENSITIVE"],
      "confidence": 0.89,
      "matched_patterns": ["table_name:accounts", "likely_contains:user_data"]
    }
  ]
}

# Get residency
GET /api/v1/data-security/residency?csp=aws&scan_id=latest&resource_id={arn}
Response:
{
  "total_resources": 1,
  "results": [
    {
      "resource_id": "threat-engine-accounts",
      "resource_arn": "arn:aws:dynamodb:...",
      "primary_region": "ap-south-1",
      "replication_regions": [],
      "policy_name": "tenant_policy",
      "compliance_status": "compliant",
      "violations": []
    }
  ]
}

# Get rule details (for remediation steps)
GET /api/v1/data-security/rules/{rule_id}?service=dynamodb
Response:
{
  "rule_id": "aws.dynamodb.accelerator.cluster_encryption_enabled",
  "metadata": {
    "title": "DAX cluster encryption enabled",
    "description": "...",
    "severity": "high",
    "remediation": "1. Open DynamoDB console...",
    "references": ["https://docs.aws.amazon.com/..."]
  },
  "data_security": {
    "modules": ["data_protection_encryption"],
    "priority": "high",
    "impact": {...}
  }
}
```

---

## 🔐 Level 2: Module-Specific Dashboards

### A. Protection & Encryption Dashboard

**Purpose**: Focus on encryption status across all resources

```http
# Get all encryption findings
GET /api/v1/data-security/findings?csp=aws&scan_id=latest&module=data_protection_encryption&status=FAIL
Response:
{
  "summary": {
    "total_findings": 1791,
    "by_status": {"FAIL": 1100, "PASS": 691}
  },
  "findings": [...]
}

# Breakdown by service
GET /api/v1/data-security/services/s3?csp=aws&scan_id=latest
GET /api/v1/data-security/services/rds?csp=aws&scan_id=latest
GET /api/v1/data-security/services/dynamodb?csp=aws&scan_id=latest
Response:
{
  "service": "s3",
  "summary": {
    "total_findings": 450,
    "total_resources": 50,
    "findings_by_status": {"PASS": 200, "FAIL": 250},
    "findings_by_module": {
      "data_protection_encryption": 250,
      "data_access_governance": 150,
      ...
    }
  },
  "findings": [...],
  "resources": [...]
}
```

**UI Metrics**:
- Encryption rate per service (calculate from PASS/FAIL ratio)
- Unencrypted resources count
- Critical encryption gaps

### B. Access Governance Dashboard

```http
# Get all access governance findings
GET /api/v1/data-security/findings?csp=aws&scan_id=latest&module=data_access_governance&status=FAIL
Response: {...}

# Group by public access, RBAC, etc. (filter by rule_id pattern)
# Public access rules: *.public_access*, *.publicly_accessible*
# RBAC rules: *.rbac*, *.iam_authentication*
```

**UI Metrics**:
- Public exposure risk count
- Overly permissive policies
- Resources without least privilege

### C. Compliance Dashboard

```http
# Get compliance by framework
GET /api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=gdpr
GET /api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=pci
GET /api/v1/data-security/compliance?csp=aws&scan_id=latest&framework=hipaa
Response:
{
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

**UI Metrics**:
- Compliance % per framework
- Failing controls per article/requirement
- Compliance roadmap (what needs fixing)

### D. Data Residency Dashboard

```http
# Get residency with policy
GET /api/v1/data-security/residency?csp=aws&scan_id=latest&allowed_regions=us-east-1,us-west-2,ap-south-1
Response:
{
  "total_resources": 117,
  "results": [
    {
      "resource_id": "...",
      "primary_region": "eu-central-1",
      "compliance_status": "non_compliant",
      "violations": ["Resource in non-allowed region: eu-central-1"]
    }
  ]
}

# Get all resources in non-compliant regions
# Filter results where compliance_status = "non_compliant"
```

**UI Metrics**:
- Compliant/non-compliant/unknown counts
- Resources per region (geographic map)
- Cross-region replication tracking

### E. Activity Monitoring Dashboard

```http
# Get activity events
GET /api/v1/data-security/activity?csp=aws&scan_id=latest&days_back=7&resource_id={arn}
Response:
{
  "total_resources": 1,
  "days_back": 7,
  "activity": {
    "arn:aws:dynamodb:...": [
      {
        "event_id": "evt_123",
        "timestamp": "2026-01-18T10:30:00Z",
        "resource_id": "threat-engine-accounts",
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

**UI Metrics**:
- Total events tracked
- High-risk events
- Anomaly detection alerts
- Access patterns timeline

### F. Data Classification Dashboard

```http
# Get classification results
GET /api/v1/data-security/classification?csp=aws&scan_id=latest&service=s3
Response:
{
  "total_resources": 50,
  "classified_resources": 45,
  "results": [
    {
      "resource_id": "user-uploads-bucket",
      "resource_arn": "arn:aws:s3:::user-uploads",
      "resource_type": "s3:bucket",
      "classification": ["PII", "SENSITIVE"],
      "confidence": 0.92,
      "matched_patterns": ["bucket_name:user", "public_access:true"]
    }
  ]
}
```

**UI Metrics**:
- Resources by classification (PII/PCI/PHI/SENSITIVE)
- Confidence levels
- Unclassified resources

---

## 🏢 Level 2: Account View

### Screen: Account Security Dashboard

**Purpose**: All data security info for a specific AWS account

```http
# Get account overview
GET /api/v1/data-security/accounts/{account_id}?csp=aws&scan_id=latest
Response:
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

# Get account findings by service
GET /api/v1/data-security/accounts/{account_id}?csp=aws&scan_id=latest&service=rds
```

**UI Display**:
- Account summary cards
- Findings breakdown by service
- Security score per service
- Regional distribution
- Compliance status

---

## 🛠️ Level 2: Service View

### Screen: Service Security Dashboard

**Purpose**: All data security info for a specific service (e.g., RDS, S3)

```http
# Get service overview
GET /api/v1/data-security/services/{service}?csp=aws&scan_id=latest
Response:
{
  "service": "rds",
  "account_id": null,  # All accounts
  "summary": {
    "total_findings": 450,
    "total_resources": 35,
    "findings_by_status": {"PASS": 200, "FAIL": 250},
    "findings_by_module": {
      "data_protection_encryption": 180,
      "data_access_governance": 150,
      ...
    },
    "accounts": ["155052200811", "194722442770"]
  },
  "findings": [...],
  "resources": [...]
}

# Filter by account
GET /api/v1/data-security/services/rds?csp=aws&scan_id=latest&account_id=155052200811
```

**UI Display**:
- Service-specific metrics
- Common misconfigurations
- Best/worst performing accounts
- Remediation priorities

---

## 📈 Level 2: Trending & Analytics

### Screen: Trends Dashboard

**Purpose**: Historical trends and progress tracking

**Note**: Requires multiple scan runs over time

```http
# Get findings for multiple scans (trending)
GET /api/v1/data-security/findings?csp=aws&scan_id=scan_20260118
GET /api/v1/data-security/findings?csp=aws&scan_id=scan_20260117
GET /api/v1/data-security/findings?csp=aws&scan_id=scan_20260116
# UI calculates deltas

# For single scan, show:
# - New resources added
# - New findings detected
# - Fixed findings (compare to baseline)
```

**UI Metrics**:
- Security score trend (30/60/90 days)
- New risks detected
- Remediation velocity
- Resources added/removed

---

## 🔧 Additional Utility Endpoints

### Get Available Modules

```http
GET /api/v1/data-security/modules
Response:
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

### Get Rules by Module

```http
GET /api/v1/data-security/modules/{module}/rules?service=s3
Response:
{
  "module": "data_protection_encryption",
  "rules": {
    "s3": [
      "aws.s3.bucket.encryption_at_rest_enabled",
      "aws.s3.bucket.default_encryption_enabled",
      ...
    ]
  }
}
```

### Get Rule Details

```http
GET /api/v1/data-security/rules/{rule_id}?service=s3
Response:
{
  "rule_id": "aws.s3.bucket.encryption_at_rest_enabled",
  "metadata": {
    "title": "S3 bucket encryption at rest enabled",
    "description": "Verifies that Amazon S3 bucket has encryption...",
    "severity": "high",
    "compliance": [
      "gdpr_article_32",
      "pci_requirement_3_4",
      ...
    ],
    "remediation": "1. Open S3 console...",
    "references": ["https://docs.aws.amazon.com/..."]
  },
  "data_security": {
    "applicable": true,
    "modules": ["data_protection_encryption"],
    "categories": ["encryption_at_rest", "sensitive_data_protection"],
    "priority": "high",
    "impact": {
      "gdpr": "Article 32 - Encryption requirement",
      "pci": "Requirement 3.4 - Render PAN unreadable",
      "hipaa": "§164.312(a)(2)(iv) - Encryption of ePHI"
    }
  }
}
```

### Health Check

```http
GET /api/v1/data-security/health
Response:
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600
}
```

---

## 🎨 UI Component Recommendations

### 1. **Dashboard Cards**
**Data Source**: Summary endpoints
- Total resources card
- Findings breakdown card
- Security score gauge
- Compliance status card

### 2. **Data Tables**
**Data Source**: Catalog, Findings endpoints
- Sortable columns (status, priority, service, region)
- Filterable (dropdown filters)
- Exportable (CSV/PDF)
- Action buttons (Remediate, Suppress, Details)

### 3. **Charts**
- **Donut Chart**: Findings by module
- **Bar Chart**: Compliance by framework
- **Line Chart**: Security score over time
- **Geographic Map**: Data residency
- **Treemap**: Resources by service/account

### 4. **Resource Cards**
**Data Source**: Catalog endpoint
```
┌─────────────────────────────────────┐
│ 🗄️ threat-engine-accounts          │
│ DynamoDB Table | ap-south-1         │
│ ❌ 5 Critical  🟡 3 Medium          │
│ Contains: PII | Encrypted: ✅       │
│ [View Details →]                    │
└─────────────────────────────────────┘
```

### 5. **Finding Cards**
**Data Source**: Findings endpoint
```
┌─────────────────────────────────────┐
│ ❌ FAIL | HIGH PRIORITY              │
│ DAX Cluster Encryption Not Enabled  │
│ Rule: aws.dynamodb.accelerator...   │
│                                      │
│ Impact: GDPR Art.32, PCI Req.3.4    │
│ Affected: 3 resources                │
│                                      │
│ [Remediate] [Details] [Suppress]    │
└─────────────────────────────────────┘
```

---

## 📋 Data Fields Available for UI

### From Discovery Catalog:
- `resource_id`, `resource_arn`, `resource_uid`
- `resource_type`, `service`
- `name`, `tags`
- `region`, `account_id`
- `lifecycle_state`, `health_status`

### From Findings:
- `scan_run_id`, `rule_id`, `status`, `result`
- `data_security_modules` (which modules this affects)
- `is_data_security_relevant`
- `data_security_context`:
  - `modules`, `categories`, `priority`
  - `impact` (GDPR/PCI/HIPAA mappings)
  - `sensitive_data_context` (why it matters)

### From Classification:
- `classification` (PII/PCI/PHI/SENSITIVE)
- `confidence` (0-1 score)
- `matched_patterns`

### From Residency:
- `primary_region`, `replication_regions`
- `policy_name`, `compliance_status`
- `violations` (list of issues)

### From Rule Metadata:
- `title`, `description`, `severity`
- `remediation` (step-by-step fix)
- `references` (AWS docs)
- `compliance` (frameworks/controls)

---

## 🚀 Implementation Priority

### Phase 1: MVP (Week 1-2)
1. Executive Dashboard
2. Data Catalog Browser
3. Resource Detail View
4. Protection & Encryption Module

### Phase 2: Core Features (Week 3-4)
5. Access Governance Module
6. Compliance Module
7. Account View
8. Service View

### Phase 3: Advanced (Week 5-6)
9. Data Residency Module
10. Classification Module
11. Activity Monitoring
12. Trending & Analytics

---

## 🔗 API Base URL

**Local Development**: `http://localhost:8000`
**Production**: `https://api.data-security.yourcompany.com`

**Swagger Docs**: `http://localhost:8000/docs`

---

## 📊 Sample API Call Flow for Resource Detail Page

```javascript
// 1. Load resource from catalog
const resource = await fetch(`/api/v1/data-security/catalog?resource_id=${arn}`)

// 2. Load findings for resource
const findings = await fetch(`/api/v1/data-security/findings?resource_id=${arn}`)

// 3. Load classification
const classification = await fetch(`/api/v1/data-security/classification?resource_id=${arn}`)

// 4. Load residency
const residency = await fetch(`/api/v1/data-security/residency?resource_id=${arn}`)

// 5. For each failing finding, get rule details for remediation
const ruleDetails = await fetch(`/api/v1/data-security/rules/${rule_id}`)
```

**Result**: Complete resource security profile with actionable remediation steps!



