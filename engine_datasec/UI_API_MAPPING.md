# Data Security Engine - API Mapping (View-Based)

## Architecture

**DataSec Engine = Filtered View of Check DB**

Instead of separate processing, Data Security uses:
- **Database Views** in `threat_engine_check` (filters by `data_security.applicable=true`)
- **Threat Engine** filters (filters by `category IN ('data_exfiltration', 'data_breach')`)

---

## Database Views (threat_engine_check)

### 1. data_security_posture
- **Rows**: All data security check results (4,556 checks)
- **Filters**: `data_security.applicable = true`
- **Shows**: resource_uid, status, data security modules, priority

### 2. datasec_by_module
- **Groups by**: Data security modules (encryption, access_governance, etc.)
- **Shows**: Pass/fail per module

### 3. datasec_resource_summary
- **Rows**: Resources with data security checks
- **Shows**: Per-resource summary, failing modules, priority failures

### 4. security_posture_summary
- **Shows**: Overall DataSec score: 8.08%

---

## Data Security Modules

Based on `rule_metadata.data_security->modules`:

| Module | Checks | Failures | Score |
|--------|--------|----------|-------|
| **data_access_governance** | 1,385 | 1,320 | 17.99% |
| **data_compliance** | 1,041 | 809 | 3.70% |
| **data_protection_encryption** | 362 | 324 | 5.93% |
| **data_activity_monitoring** | 250 | 250 | 0.00% |

---

## API Endpoints

### Check DB Queries (Use DBeaver or Direct SQL)

**Query Data Security Posture:**
```sql
SELECT * FROM data_security_posture
WHERE scan_id = 'check_20260129_162625'
  AND status = 'FAIL'
ORDER BY datasec_priority, severity;
```

**Query by Module:**
```sql
SELECT * FROM datasec_by_module
WHERE scan_id = 'check_20260129_162625'
ORDER BY failed DESC;
```

---

### Threat API - Data Security Threats

**Query Data Exfiltration Threats:**
```
GET /api/v1/threat/threats?tenant_id=test-tenant&category=data_exfiltration
```

**Returns**: 21 data exfiltration threats

**Query Data Breach Threats:**
```
GET /api/v1/threat/threats?tenant_id=test-tenant&category=data_breach
```

**Returns**: 0 data breach threats (none detected in current scan)

---

## Data Security Dashboard UI

### Metrics (from security_posture_summary):

```sql
SELECT 
    datasec_total_checks,
    datasec_failures,
    datasec_score
FROM security_posture_summary
WHERE scan_id = 'check_20260129_162625';
```

**Results:**
- Total Checks: 4,556
- Failures: 4,188
- Score: 8.08%

---

### Module Breakdown (from datasec_by_module):

**Access Governance:**
- 1,385 checks
- 1,320 failures
- 17.99% score (best module)

**Encryption:**
- 362 checks
- 324 failures
- 5.93% score

**Activity Monitoring:**
- 250 checks
- All failing (0%)

---

## Data Security Resource View

**For S3 bucket:**

```sql
SELECT * FROM datasec_resource_summary
WHERE resource_uid = 'arn:aws:s3:::cspm-lgtech'
  AND scan_id = 'check_20260129_162625';
```

**Shows**:
- Total data security checks: ~50
- Failed checks: ~45
- High priority failures: ~20
- Failing modules: encryption, access_governance, logging
- Failed rules: Array of rule IDs

---

## Current Data (check_20260129_162625)

**From `datasec_resource_summary` view:**
- **Resources evaluated**: S3 buckets, RDS, DynamoDB, etc.
- **Total checks**: 4,556 data security checks
- **Failures**: 4,188 (91.9% failure rate)
- **Score**: 8.08% compliant

**Resource Types with Most DataSec Checks:**
- S3 buckets (21 resources, ~50 checks each)
- RDS instances
- DynamoDB tables

---

## DataSec Threats (from Threat Engine)

**Data Exfiltration Threats**: 21 threats
**Data Breach Threats**: 0 threats

**Query**:
```sql
SELECT * FROM threats
WHERE category IN ('data_exfiltration', 'data_breach');
```

---

## Files & Endpoints

**UI Documentation**: `engine_datasec/UI_API_MAPPING.md` (this file)

**Database Views**: `threat_engine_check` database
- `data_security_posture` (all data security checks)
- `datasec_by_module` (grouped by module)
- `datasec_resource_summary` (per-resource summary)
- `security_posture_summary` (overall IAM + DataSec scores)

**API Access**:
- Check DB views (query in DBeaver)
- Threat API: `/api/v1/threat/threats?category=data_exfiltration`

---

## Testing

```bash
# View DataSec data in DBeaver
# Connect to: threat_engine_check
# Query:
SELECT * FROM datasec_resource_summary
WHERE scan_id = 'check_20260129_162625'
ORDER BY high_priority_failures DESC
LIMIT 10;

# Or query threats API
kubectl -n threat-engine-local port-forward svc/threat-service 8020:8020 &
curl "http://localhost:8020/api/v1/threat/threats?tenant_id=test-tenant&category=data_exfiltration" | jq
```

**Data Security is now a filtered view - no separate processing needed!**
