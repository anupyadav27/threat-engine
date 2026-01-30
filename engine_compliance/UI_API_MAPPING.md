# Compliance Engine UI - Updated with Database-Driven APIs

## Database Backend

**All UI screens now query:**
- `threat_engine_compliance.compliance_control_detail` VIEW (main data source)
- `threat_engine_compliance.resource_compliance_status` TABLE (resource-level)
- `threat_engine_compliance.compliance_control_mappings` TABLE (control definitions)

---

## 🏠 Screen 1: Executive Compliance Dashboard

**URL**: `/compliance/dashboard`

**API Endpoint**: 
```
GET /api/v1/compliance/dashboard?tenant_id=test-tenant&scan_id=latest
```

**Response Structure**:
```json
{
  "scan_id": "check_20260129_162625",
  "tenant_id": "test-tenant",
  "overall_score": 3.12,
  "frameworks": {
    "total": 13,
    "passing": 0,
    "partial": 4,
    "failing": 9
  },
  "framework_scores": [
    {
      "compliance_framework": "FedRAMP",
      "total_controls": 69,
      "passed_controls": 0,
      "failed_controls": 65,
      "partial_controls": 4,
      "framework_score": 11.59
    },
    {
      "compliance_framework": "CIS",
      "total_controls": 34,
      "framework_score": 0.00
    }
  ]
}
```

**Database Query (Behind the Scene)**:
```sql
SELECT 
    compliance_framework,
    COUNT(*) as total_controls,
    ROUND(AVG(avg_compliance_score), 2) as framework_score
FROM compliance_control_detail
GROUP BY compliance_framework
ORDER BY framework_score DESC;
```

**UI Components**:
- Overall Score: `overall_score` (3.12%)
- Framework Status Cards: `framework_scores` array
- Framework Progress Bars: `framework_score` percentages

---

## 📋 Screen 2: Framework Detail View

**URL**: `/compliance/framework/{framework}`

**API Endpoint**:
```
GET /api/v1/compliance/framework-detail/CIS?tenant_id=test-tenant&scan_id=latest
```

**Response Structure**:
```json
{
  "framework": "CIS",
  "scan_id": "check_20260129_162625",
  "summary": {
    "total_controls": 34,
    "passed_controls": 0,
    "failed_controls": 34,
    "partial_controls": 0,
    "framework_score": 0.00
  },
  "controls": [
    {
      "control_id": "1.14",
      "control_description": "Ensure access keys are rotated every 90 days",
      "status": "FAIL",
      "resources_checked": 6,
      "total_passed": 0,
      "total_failed": 6,
      "compliance_score": 0.00,
      "mapped_rule_ids": ["aws.iam.key.rotation_90_days_configured"],
      "failed_resources": [
        "arn:aws:iam::123:user/admin",
        "arn:aws:iam::123:user/user1"
      ]
    }
  ]
}
```

**Database Query**:
```sql
SELECT * FROM compliance_control_detail
WHERE compliance_framework = 'CIS'
ORDER BY control_id;
```

**UI Components**:
- Framework Score: `summary.framework_score`
- Control List: `controls` array
- Failed/Passed Tabs: Filter by `status`
- Control Cards: Show `control_id`, `control_description`, `compliance_score`

---

## 🔍 Screen 3: Control Detail View

**URL**: `/compliance/framework/{framework}/control/{control_id}`

**API Endpoint**:
```
GET /api/v1/compliance/control-detail/CIS/1.14?tenant_id=test-tenant&scan_id=latest
```

**Response Structure**:
```json
{
  "compliance_framework": "CIS",
  "control_id": "1.14",
  "control_description": "Ensure access keys are rotated every 90 days",
  "resources_checked": 6,
  "total_passed": 0,
  "total_failed": 6,
  "avg_compliance_score": 0.00,
  "mapped_rule_ids": ["aws.iam.key.rotation_90_days_configured"],
  "failed_resources": [
    "arn:aws:iam::588989875114:user/administrator",
    "arn:aws:iam::588989875114:user/ajay",
    "arn:aws:iam::588989875114:user/lgtech_admin"
  ],
  "affected_resources": [
    {
      "resource_uid": "arn:aws:iam::588989875114:user/administrator",
      "resource_type": "iam",
      "account_id": "588989875114",
      "total_checks": 1,
      "passed_checks": 0,
      "failed_checks": 1,
      "compliance_score": 0.00
    }
  ],
  "failed_resource_count": 6,
  "passed_resource_count": 0
}
```

**Database Query**:
```sql
-- Control summary
SELECT * FROM compliance_control_detail
WHERE compliance_framework = 'CIS' AND control_id = '1.14';

-- Affected resources
SELECT * FROM resource_compliance_status
WHERE compliance_framework = 'CIS' AND requirement_id = '1.14';
```

**UI Components**:
- Control Header: `control_description`
- Status Badge: `FAIL` (from avg_compliance_score)
- Mapped Rules: `mapped_rule_ids` array
- Resource List: `affected_resources` array
- Failed Resources: Filter where `failed_checks > 0`

---

## 🏢 Screen 4: Account Compliance View

**Existing Endpoint**:
```
GET /api/v1/compliance/accounts/{account_id}
```

**Enhancement Needed**: Add database query for account-level compliance

**Database Query**:
```sql
SELECT 
    compliance_framework,
    COUNT(*) as total_controls,
    SUM(failed_checks) as failures
FROM resource_compliance_status
WHERE account_id = '588989875114'
GROUP BY compliance_framework;
```

---

## 📦 Screen 5: Resource Compliance View

**URL**: `/compliance/resource/{resource_uid}`

**API Endpoint** (NEW):
```
GET /api/v1/compliance/resource/{resource_uid}/compliance?tenant_id=test-tenant
```

**Response Structure**:
```json
{
  "resource_uid": "arn:aws:s3:::cspm-lgtech",
  "frameworks_applicable": 7,
  "total_controls_applicable": 15,
  "framework_summaries": [
    {
      "framework": "CIS",
      "total_controls": 4,
      "passed_controls": 0,
      "failed_controls": 4,
      "compliance_score": 0.00
    },
    {
      "framework": "PCI-DSS",
      "total_controls": 1,
      "compliance_score": 0.00
    }
  ],
  "controls": [
    {
      "compliance_framework": "CIS",
      "control_id": "2.1.3",
      "control_name": "Ensure S3 data is discovered",
      "total_checks": 1,
      "passed_checks": 0,
      "failed_checks": 1,
      "compliance_score": 0.00
    }
  ]
}
```

**Database Query**:
```sql
SELECT * FROM resource_compliance_status
WHERE resource_uid = 'arn:aws:s3:::cspm-lgtech'
ORDER BY compliance_framework, requirement_id;
```

**UI Components**:
- Resource Header: `resource_uid`
- Framework Badges: `frameworks_applicable` count
- Framework Cards: `framework_summaries` array
- Control List: `controls` array with pass/fail status

---

## 🔧 Screen 6: Service Compliance View

**URL**: `/compliance/service/{service}`

**Database Query** (for this screen):
```sql
-- Get service compliance from compliance_by_service VIEW
SELECT * FROM compliance_by_service
WHERE service = 'IAM'
ORDER BY compliance_framework;
```

**Shows**:
- IAM: Which frameworks have IAM controls
- S3: S3-related compliance
- EC2: EC2 security compliance

---

## API Endpoint Summary

### Existing Endpoints (File-Based):
- ❌ `/api/v1/compliance/generate` - Uses S3/files
- ✅ `/api/v1/compliance/generate/from-check-db` - **Use this!**

### New Database-Driven Endpoints:
1. ✅ `GET /api/v1/compliance/dashboard` - Executive dashboard
2. ✅ `GET /api/v1/compliance/framework-detail/{framework}` - Framework controls
3. ✅ `GET /api/v1/compliance/control-detail/{framework}/{control_id}` - Control details
4. ✅ `GET /api/v1/compliance/resource/{resource_uid}/compliance` - Resource compliance

### Recommended UI API Flow:

```javascript
// Dashboard
const dashboard = await fetch('/api/v1/compliance/dashboard?tenant_id=test-tenant')

// Framework detail (CIS)
const cisDetail = await fetch('/api/v1/compliance/framework-detail/CIS?tenant_id=test-tenant')

// Control detail (CIS 1.14)
const controlDetail = await fetch('/api/v1/compliance/control-detail/CIS/1.14?tenant_id=test-tenant')

// Resource compliance (S3 bucket)
const resourceComp = await fetch('/api/v1/compliance/resource/arn:aws:s3:::cspm-lgtech/compliance?tenant_id=test-tenant')
```

---

## Database Views Used by UI

All endpoints query these database objects:

### Primary Data Source:
- **compliance_control_detail** VIEW ⭐
  - 362 controls with complete data
  - Mapped rules, failed resources, scores

### Supporting Tables:
- **resource_compliance_status** (23,998 rows)
  - Per-resource compliance
- **compliance_control_mappings** (960 rows)
  - Control definitions

### Additional Views:
- **compliance_by_service** - Service-level compliance
- **framework_coverage** - Framework statistics
- **multi_cloud_framework_summary** - Framework tech coverage

---

## Testing New Endpoints

```bash
kubectl -n threat-engine-local port-forward svc/compliance-service 8010:8010 &

# Dashboard
curl "http://localhost:8010/api/v1/compliance/dashboard?tenant_id=test-tenant" | jq

# Framework detail
curl "http://localhost:8010/api/v1/compliance/framework-detail/CIS?tenant_id=test-tenant" | jq

# Control detail
curl "http://localhost:8010/api/v1/compliance/control-detail/CIS/1.14?tenant_id=test-tenant" | jq

# Resource compliance
curl "http://localhost:8010/api/v1/compliance/resource/arn:aws:s3:::cspm-lgtech/compliance?tenant_id=test-tenant" | jq
```

---

## Summary

**All UI screens can now be built using database-driven APIs:**

✅ Executive Dashboard → `/api/v1/compliance/dashboard`  
✅ Framework Detail → `/api/v1/compliance/framework-detail/{framework}`  
✅ Control Detail → `/api/v1/compliance/control-detail/{framework}/{control_id}`  
✅ Resource Compliance → `/api/v1/compliance/resource/{resource_uid}/compliance`  

**No CSV files needed - all data from PostgreSQL!**
