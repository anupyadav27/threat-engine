# Threat Engine UI - API Mapping & Database Queries

## Database Backend

**All UI endpoints query:**
- `threat_engine_threat.threats` TABLE (489 threats)
- `threat_engine_threat.threat_resources` TABLE (threat-resource mappings)
- `threat_engine_threat.threat_scans` TABLE (scan summaries)
- `threat_engine_threat.drift_records` TABLE (drift tracking)

---

## UI Screens & API Endpoints

### 1. Threat Dashboard
**URL**: `/threats/dashboard`

**API Endpoint**:
```
GET /api/v1/threat/scans/{scan_run_id}/summary?tenant_id=test-tenant
```

**Response**:
```json
{
  "scan_run_id": "check_20260129_162625",
  "total_threats": 489,
  "critical_count": 6,
  "high_count": 347,
  "medium_count": 136,
  "identity_count": 240,
  "exposure_count": 94,
  "data_exfiltration_count": 21,
  "data_breach_count": 0,
  "misconfiguration_count": 134
}
```

**Database Query**:
```sql
SELECT * FROM threat_scans
WHERE scan_run_id = 'check_20260129_162625';
```

**UI Components**:
- Total Threats: `total_threats`
- Severity Breakdown: `critical_count`, `high_count`, `medium_count`
- Category Cards: `identity_count`, `exposure_count`, etc.

---

### 2. Threat List View
**URL**: `/threats/list`

**API Endpoint**:
```
GET /api/v1/threat/threats?tenant_id=test-tenant&severity=high&category=identity&limit=50
```

**Response**:
```json
{
  "threats": [
    {
      "threat_id": "thr_6c62dc6f8119b715",
      "severity": "critical",
      "category": "identity",
      "title": "Identity Threat Detected",
      "description": "12 IAM misconfigurations...",
      "misconfig_count": 12,
      "affected_resource_count": 1,
      "primary_rule_id": "aws.iam.group.has_users_configured",
      "first_seen_at": "2026-01-30T05:02:14Z",
      "status": "open"
    }
  ],
  "total": 240,
  "limit": 50,
  "offset": 0,
  "has_more": true
}
```

**Database Query**:
```sql
SELECT * FROM threats
WHERE tenant_id = 'test-tenant'
  AND severity = 'high'
  AND category = 'identity'
ORDER BY severity, first_seen_at DESC
LIMIT 50;
```

**Filters Available**:
- `severity`: critical, high, medium, low
- `category`: identity, exposure, data_exfiltration, misconfiguration
- `status`: open, resolved, suppressed
- `resource_uid`: Filter by specific resource

---

### 3. Threat Detail View
**URL**: `/threats/{threat_id}`

**API Endpoint**:
```
GET /api/v1/threat/threats/{threat_id}?tenant_id=test-tenant
```

**Response**:
```json
{
  "threat_id": "thr_6c62dc6f8119b715",
  "severity": "critical",
  "category": "identity",
  "title": "Identity Threat Detected",
  "description": "Detected 12 IAM misconfigurations on user/administrator",
  "primary_rule_id": "aws.iam.group.has_users_configured",
  "misconfig_count": 12,
  "misconfig_finding_refs": ["fnd_123", "fnd_456"],
  "remediation_summary": "Review and remediate 12 misconfigurations",
  "remediation_steps": [
    "Review finding fnd_123",
    "Apply remediation",
    "Re-scan to verify"
  ],
  "affected_resources": [
    {
      "resource_uid": "arn:aws:iam::123:user/administrator",
      "resource_type": "iam",
      "account_id": "588989875114",
      "failed_rule_ids": ["rule1", "rule2", ...]
    }
  ],
  "status": "open",
  "first_seen_at": "2026-01-30T05:02:14Z"
}
```

**Database Query**:
```sql
-- Threat detail
SELECT * FROM threats WHERE threat_id = 'thr_6c62dc6f8119b715';

-- Affected resources
SELECT * FROM threat_resources WHERE threat_id = 'thr_6c62dc6f8119b715';
```

---

### 4. Resource Threat View
**URL**: `/resources/{resource_uid}/threats`

**API Endpoint**:
```
GET /api/v1/threat/resources/{resource_uid}/threats?tenant_id=test-tenant
```

**Response**:
```json
{
  "resource_uid": "arn:aws:s3:::cspm-lgtech",
  "total": 4,
  "threats": [
    {
      "threat_id": "thr_3021e97dc76e87ed",
      "threat_type": "exposure",
      "severity": "high",
      "title": "Exposure Threat Detected",
      "misconfig_count": 9,
      "failed_rule_ids": [
        "aws.s3.bucket.block_public_access_configured",
        "aws.s3.bucket.public_read_prohibited_configured"
      ]
    },
    {
      "threat_id": "thr_63f3eae1dac5d220",
      "threat_type": "data_exfiltration",
      "severity": "high",
      "misconfig_count": 12
    }
  ]
}
```

**Database Query**:
```sql
SELECT 
    t.threat_id,
    t.severity,
    t.category,
    t.title,
    t.misconfig_count,
    tr.failed_rule_ids
FROM threats t
JOIN threat_resources tr ON t.threat_id = tr.threat_id
WHERE tr.resource_uid = 'arn:aws:s3:::cspm-lgtech';
```

---

### 5. Resource Posture View
**URL**: `/resources/{resource_uid}/posture`

**API Endpoint**:
```
GET /api/v1/threat/resources/{resource_uid}/posture?tenant_id=test-tenant&scan_id=check_20260129_162625
```

**Response**:
```json
{
  "resource_uid": "arn:aws:s3:::cspm-lgtech",
  "resource_type": "s3",
  "account_id": "588989875114",
  "total_checks": 56,
  "passed": 3,
  "failed": 53,
  "warnings": 0,
  "failed_rule_ids": [
    "aws.s3.bucket.encryption_enabled",
    "aws.s3.bucket.public_access_configured",
    "aws.s3.bucket.versioning_enabled"
  ],
  "critical_failures": 0,
  "high_failures": 38,
  "medium_failures": 15,
  "last_scanned": "2026-01-29T21:56:25Z"
}
```

**Database Query** (queries Check DB):
```sql
-- This endpoint queries threat_engine_check database
SELECT 
    cr.resource_uid,
    COUNT(*) as total_checks,
    COUNT(*) FILTER (WHERE cr.status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE cr.status = 'FAIL') as failed,
    jsonb_agg(cr.rule_id) FILTER (WHERE cr.status = 'FAIL') as failed_rule_ids
FROM check_results cr
WHERE cr.resource_uid = 'arn:aws:s3:::cspm-lgtech'
  AND cr.scan_id = 'check_20260129_162625'
GROUP BY cr.resource_uid;
```

---

### 6. Drift Monitoring View
**URL**: `/threats/drift`

**API Endpoint**:
```
GET /api/v1/threat/drift?tenant_id=test-tenant&current_scan_id=check_20260129_162625
```

**Response**:
```json
{
  "drift_records": [
    {
      "drift_id": "drift_123",
      "resource_uid": "arn:aws:s3:::bucket1",
      "config_drift_detected": true,
      "change_type": "modified",
      "status_drift_detected": true,
      "newly_failed_rules": ["aws.s3.bucket.encryption_enabled"],
      "newly_passed_rules": [],
      "threat_id": "thr_456"
    }
  ],
  "total": 0,
  "has_more": false
}
```

**Database Query**:
```sql
SELECT * FROM drift_records
WHERE tenant_id = 'test-tenant'
  AND current_scan_id = 'check_20260129_162625'
ORDER BY detected_at DESC;
```

**Note**: Currently empty (requires 2+ scans for drift detection)

---

## Threat Engine API Summary

### Dashboard & Lists:
- `GET /api/v1/threat/scans/{scan_run_id}/summary` - Scan summary
- `GET /api/v1/threat/threats` - List threats (filterable)
- `GET /api/v1/threat/drift` - List drift records

### Detail Views:
- `GET /api/v1/threat/threats/{threat_id}` - Threat detail
- `GET /api/v1/threat/resources/{resource_uid}/threats` - Resource threats
- `GET /api/v1/threat/resources/{resource_uid}/posture` - Resource check posture

### Generation:
- `POST /api/v1/threat/generate/async` - Generate threats (async)
- `GET /api/v1/threat/jobs/{job_id}` - Check generation status

---

## Database Views for Threat UI

### Existing Views (in threat_engine_threat):
- `threats_by_severity` - Threat count by severity
- `threats_by_category` - Threat count by category
- `high_risk_resources` - Resources with most threats

### Queries for UI Components:

**Threat Count by Severity**:
```sql
SELECT severity, COUNT(*) 
FROM threats 
WHERE scan_run_id = 'check_20260129_162625'
GROUP BY severity;
```

**Top Affected Resources**:
```sql
SELECT 
    resource_uid,
    COUNT(DISTINCT threat_id) as threat_count
FROM threat_resources
GROUP BY resource_uid
ORDER BY threat_count DESC
LIMIT 10;
```

**Threats by Category (for pie chart)**:
```sql
SELECT category, COUNT(*)
FROM threats
GROUP BY category;
```

---

## Testing Threat UI APIs

```bash
kubectl -n threat-engine-local port-forward svc/threat-service 8020:8020 &

# Dashboard summary
curl "http://localhost:8020/api/v1/threat/scans/check_20260129_162625/summary?tenant_id=test-tenant" | jq

# List critical threats
curl "http://localhost:8020/api/v1/threat/threats?tenant_id=test-tenant&severity=critical" | jq

# Threat detail
curl "http://localhost:8020/api/v1/threat/threats/thr_6c62dc6f8119b715?tenant_id=test-tenant" | jq

# Resource threats
curl "http://localhost:8020/api/v1/threat/resources/arn:aws:s3:::cspm-lgtech/threats?tenant_id=test-tenant" | jq

# Resource posture
curl "http://localhost:8020/api/v1/threat/resources/arn:aws:s3:::cspm-lgtech/posture?tenant_id=test-tenant" | jq
```

---

## Files Created

1. `engine_compliance/UI_API_MAPPING.md` - Compliance UI APIs
2. `engine_compliance/COMPLIANCE_UI_API_MAPPING.md` - Compliance API reference
3. `engine_threat/UI_API_MAPPING.md` (this file) - Threat UI APIs

**Next**: Inventory and Check/Discovery engine UI mappings
