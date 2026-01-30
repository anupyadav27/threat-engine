# IAM & Data Security - Usage Guide

## ✅ View-Based Architecture (No Separate DBs Needed)

IAM and DataSec engines use **database views in Check DB** instead of separate processing.

---

## How to Access IAM Security Data

### Option 1: Direct Database Query (Recommended)

**Connect to**: `threat_engine_check` database in DBeaver

**Views to Use:**
```sql
-- IAM resource summary
SELECT * FROM iam_resource_summary
WHERE scan_id = 'check_20260129_162625'
ORDER BY failed DESC;

-- IAM security posture (all checks)
SELECT * FROM iam_security_posture
WHERE scan_id = 'check_20260129_162625'
  AND status = 'FAIL';

-- IAM threats (from Threat DB)
-- Connect to threat_engine_threat:
SELECT * FROM threats WHERE category = 'identity';
```

---

### Option 2: Via Threat API (Filter by Category)

```bash
# IAM/Identity threats
curl "http://localhost:8020/api/v1/threat/scans/check_20260129_162625/summary?tenant_id=test-tenant" | jq

# Filter threats by category
# Note: Currently has route conflict, use database query instead
```

---

### Option 3: Via IAM Engine API (Legacy)

**Endpoint**: `http://localhost:8003/api/v1/iam-security/scan`

**Status**: Works but processes from Threat DB (old approach)

**Recommendation**: Use database views (Option 1) instead

---

## How to Access Data Security Data

### Option 1: Direct Database Query (Recommended)

**Connect to**: `threat_engine_check` database in DBeaver

**Views to Use:**
```sql
-- Data security by module
SELECT * FROM datasec_by_module
WHERE scan_id = 'check_20260129_162625'
ORDER BY failed DESC;

-- Data security resource summary
SELECT * FROM datasec_resource_summary
WHERE scan_id = 'check_20260129_162625'
ORDER BY high_priority_failures DESC;

-- Data security posture (all checks)
SELECT * FROM data_security_posture
WHERE scan_id = 'check_20260129_162625'
  AND status = 'FAIL'
  AND datasec_priority = 'high';

-- Overall IAM + DataSec summary
SELECT * FROM security_posture_summary
WHERE scan_id = 'check_20260129_162625';
```

---

### Option 2: Via Threat API

```bash
# Data exfiltration threats
# Connect to threat_engine_threat:
SELECT * FROM threats WHERE category = 'data_exfiltration';
# Returns: 21 threats
```

---

### Option 3: Via DataSec Engine API (Legacy)

**Endpoint**: `http://localhost:8004/api/v1/data-security/scan`

**Status**: Works but processes from Threat DB (old approach)

**Recommendation**: Use database views (Option 1) instead

---

## Current Data Summary

### IAM Security:
**Source**: `threat_engine_check.iam_resource_summary`

- **214 IAM resources** evaluated
  - 136 IAM roles
  - 54 IAM policies  
  - 6 IAM users
- **2,512 total IAM checks**
- **2,458 failures** (97.8% failure rate)
- **IAM Score: 2.15%**

**Top Issues:**
- 6 IAM users without MFA (critical)
- 54 IAM policies with excessive permissions
- 136 IAM roles with trust policy issues

**Threats**: 240 identity threats in `threat_engine_threat.threats`

---

### Data Security:
**Source**: `threat_engine_check.datasec_by_module`

- **4,556 total DataSec checks**
- **4,188 failures** (91.9% failure rate)
- **DataSec Score: 8.08%**

**By Module:**
| Module | Checks | Failures | Score |
|--------|--------|----------|-------|
| Access Governance | 1,385 | 1,320 | 17.99% |
| Data Compliance | 1,041 | 809 | 3.70% |
| Encryption | 362 | 324 | 5.93% |
| Activity Monitoring | 250 | 250 | 0.00% |

**By Priority:**
| Priority | Checks | Failures | Score |
|----------|--------|----------|-------|
| High | 1,564 | 1,493 | 6.44% |
| Medium | 2,926 | 2,629 | 2.96% |
| Critical | 18 | 18 | 0.00% |

**Threats**: 21 data exfiltration threats in `threat_engine_threat.threats`

---

## Recommended Approach

**For IAM/DataSec Analysis:**

1. **Primary Source**: Query Check DB views in DBeaver
   - Most detailed data
   - Includes PASS + FAIL
   - Real-time (auto-updates)

2. **For Threats**: Query Threat DB
   - High-level risk summary
   - Grouped by resource
   - Only shows failures

3. **Don't Use**: Separate IAM/DataSec engine APIs
   - Legacy approach
   - Processes same data differently
   - Views are simpler and faster

---

## DBeaver Quick Start

**Connect to**: `threat_engine_check`
```
Host: localhost
Port: 5432
Database: threat_engine_check
Username: check_user
Password: check_password
```

**Navigate to**: Schemas → public → Views

**Query IAM:**
```sql
SELECT * FROM iam_resource_summary
WHERE scan_id = 'check_20260129_162625';
```

**Query DataSec:**
```sql
SELECT * FROM datasec_by_module
WHERE scan_id = 'check_20260129_162625';
```

**Combined Summary:**
```sql
SELECT * FROM security_posture_summary
WHERE scan_id = 'check_20260129_162625';
-- Shows: IAM 2.15%, DataSec 8.08%
```

---

## Summary

**IAM & DataSec are now view-based filters:**
- ✅ No separate databases
- ✅ No duplicate processing
- ✅ Use Check DB views
- ✅ Threat DB for threat summaries
- ✅ All data queryable in DBeaver

**Files:**
- `IAM_DATASEC_USAGE_GUIDE.md` (this file)
- `IAM_DATASEC_ARCHITECTURE.md` (architecture)
- `engine_iam/UI_API_MAPPING.md` (UI spec)
- `engine_datasec/UI_API_MAPPING.md` (UI spec)

**Use database views for IAM/DataSec analysis - no separate engines needed!**
