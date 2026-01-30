# IAM Security Engine - API Mapping (View-Based)

## Architecture

**IAM Engine = Filtered View of Check DB**

Instead of a separate processing engine, IAM Security uses:
- **Database Views** in `threat_engine_check` (filters by `service='iam'`)
- **Threat Engine** filters (filters by `category='identity'`)

---

## Database Views (threat_engine_check)

### 1. iam_security_posture
- **Rows**: All IAM check results (2,512 checks)
- **Filters**: `service = 'iam'`
- **Shows**: resource_uid, rule_id, status, severity, threat_category

### 2. iam_resource_summary
- **Rows**: 214 IAM resources
- **Shows**: Per-resource IAM check summary (passed, failed, score)

### 3. security_posture_summary
- **Shows**: Overall IAM vs DataSec scores
- **Current**: IAM: 2.15%, DataSec: 8.08%

---

## API Endpoints (Use Existing Services)

### Check Service (Port 8002) - Detailed IAM Checks

**Query IAM Security Posture:**
```
Direct Database Query (DBeaver):
SELECT * FROM iam_security_posture
WHERE scan_id = 'check_20260129_162625'
  AND status = 'FAIL';
```

**Or via Check API** (if endpoint added):
```
GET /api/v1/check/iam/posture?scan_id=check_20260129_162625&tenant_id=test-tenant
```

**Returns**:
```json
{
  "scan_id": "check_20260129_162625",
  "total_iam_checks": 2512,
  "passed": 54,
  "failed": 2458,
  "iam_score": 2.15,
  "resources": [
    {
      "resource_uid": "arn:aws:iam::123:role/RoleName",
      "total_checks": 8,
      "failed": 7,
      "failed_rules": ["rule1", "rule2"]
    }
  ]
}
```

---

### Threat Service (Port 8020) - IAM Threats

**Query Identity Threats:**
```
GET /api/v1/threat/threats?tenant_id=test-tenant&category=identity
```

**Returns**:
```json
{
  "threats": [...240 identity threats...],
  "total": 240
}
```

**Database Query**:
```sql
SELECT * FROM threats
WHERE category = 'identity';
-- Returns 240 IAM-related threats
```

---

## IAM Security Dashboard UI

### Data Sources:

**1. IAM Posture Score** (from Check DB):
```sql
SELECT iam_score FROM security_posture_summary
WHERE scan_id = 'check_20260129_162625';
-- Returns: 2.15%
```

**2. IAM Resources** (from Check DB):
```sql
SELECT * FROM iam_resource_summary
WHERE scan_id = 'check_20260129_162625'
ORDER BY failed DESC
LIMIT 20;
-- Returns: 214 IAM resources with check summaries
```

**3. IAM Threats** (from Threat DB):
```sql
SELECT * FROM threats
WHERE category = 'identity'
  AND severity IN ('critical', 'high');
-- Returns: 239 high/critical identity threats
```

---

## IAM Resource Detail View

**For a specific IAM role:**

```sql
-- IAM checks for this role
SELECT * FROM iam_security_posture
WHERE resource_uid = 'arn:aws:iam::123:role/RoleName'
  AND scan_id = 'check_20260129_162625';
```

**Shows**:
- 8 IAM checks run
- 7 failed, 1 passed
- Failed rules: MFA, least privilege, trust policy, etc.
- Severity: 5 high, 2 medium

---

## Current IAM Data (check_20260129_162625)

**From `iam_resource_summary` view:**
- **214 IAM resources** evaluated
- **2,512 total IAM checks**
- **2,458 failures** (97.8% failure rate)
- **54 passing checks** (2.15% score)

**Resource Breakdown:**
- IAM Roles: 136 resources
- IAM Policies: 54 resources  
- IAM Users: 6 resources
- IAM Groups, Instance Profiles, etc.

---

## Files & Endpoints

**UI Documentation**: `engine_iam/UI_API_MAPPING.md` (this file)

**Database Views**: `threat_engine_check` database
- `iam_security_posture`
- `iam_resource_summary`
- `security_posture_summary`

**API Access**:
- Check DB views (query directly in DBeaver)
- Threat API: `/api/v1/threat/threats?category=identity`
- Future: Add `/api/v1/check/iam/*` endpoints

---

## Testing

```bash
# View IAM data in DBeaver
# Connect to: threat_engine_check
# Query:
SELECT * FROM iam_resource_summary
WHERE scan_id = 'check_20260129_162625'
ORDER BY failed DESC
LIMIT 10;

# Or query threats API for IAM threats
kubectl -n threat-engine-local port-forward svc/threat-service 8020:8020 &
curl "http://localhost:8020/api/v1/threat/threats?tenant_id=test-tenant&category=identity&limit=10" | jq
```

**IAM Security is now a filtered view - no separate processing needed!**
