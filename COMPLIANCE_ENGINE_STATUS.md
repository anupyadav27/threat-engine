# Compliance Engine - Current Status

**Date:** February 1, 2026  
**Engine:** `yadavanup84/threat-engine-compliance-engine:latest` (git HEAD version)

---

## ✅ What's Working

### 1. Infrastructure
- ✅ Pod running (2/2 containers: main + S3 sidecar)
- ✅ Service ports corrected: `80` → `8000`
- ✅ LoadBalancer endpoint active
- ✅ Health checks passing

### 2. Database Connections
```bash
✅ CHECK_DB: 1,056 check_results rows available
   - Host: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
   - Database: threat_engine_check
   - Scan ID: check_20260201_044813

✅ COMPLIANCE_DB: Connected (0 report_index rows)
   - Host: same RDS
   - Database: threat_engine_compliance
   - Tables: report_index, finding_index ready
```

### 3. Environment Variables
```
CHECK_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
CHECK_DB_NAME=threat_engine_check
COMPLIANCE_DB_HOST=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
COMPLIANCE_DB_NAME=threat_engine_compliance
S3_BUCKET=cspm-lgtech
OUTPUT_DIR=/output
INPUT_DIR=/input
AWS_REGION=ap-south-1
```

### 4. S3 Sidecar
- ✅ Sidecar container running
- ✅ `/output` and `/input` volumes mounted
- ✅ Configured to sync to `s3://cspm-lgtech/engine_output/compliance/`

---

## ❌ What's NOT Working

### Compliance API Call Hangs

**Issue:** `/api/v1/compliance/generate/from-check-db` endpoint times out (>60s, no response)

**Symptoms:**
- Health endpoint works fine (`/api/v1/health`)
- No error logs in pod
- Request never reaches the endpoint handler
- LoadBalancer receives request but no processing happens

**Likely Causes:**
1. **Missing `compliance_control_mappings` data** in RDS
   - The compliance engine needs this table populated to map rules → frameworks
   - Check with: `SELECT COUNT(*) FROM compliance_control_mappings;`

2. **Framework loader hanging** trying to load from DB/files
   - Git version may try to load `data_compliance/` CSVs
   - May be waiting on file I/O or DB query

3. **Missing framework CSV files** in container
   - Check if `/app/compliance/` folder has AWS compliance CSVs

---

## 🔍 Recommended Debug Steps

### Step 1: Login to Pod
```bash
kubectl -n threat-engine-engines exec -it deployment/compliance-engine -c compliance-engine -- bash
```

### Step 2: Check Compliance Control Mappings
```bash
python3 << 'EOF'
import os, psycopg2
conn = psycopg2.connect(
    host=os.getenv('COMPLIANCE_DB_HOST'),
    database=os.getenv('COMPLIANCE_DB_NAME'),
    user=os.getenv('COMPLIANCE_DB_USER'),
    password=os.getenv('COMPLIANCE_DB_PASSWORD')
)
with conn.cursor() as cur:
    cur.execute('SELECT COUNT(*) FROM compliance_control_mappings')
    print(f'compliance_control_mappings rows: {cur.fetchone()[0]}')
conn.close()
EOF
```

**Expected:** Should have ~960 rows from `aws_consolidated_rules_with_final_checks.csv`

### Step 3: Check Framework Files
```bash
ls -la /app/compliance/
ls -la /app/data/
```

**Expected:** Should see AWS CSV files with compliance mappings

### Step 4: Test Minimal Compliance Generation
```python
python3 << 'EOF'
import sys
sys.path.insert(0, '/app')

# Test framework loader
from compliance_engine.mapper.framework_loader import FrameworkLoader
loader = FrameworkLoader()
print("Framework loader initialized")

# Test loading AWS frameworks
frameworks = loader.get_frameworks_for_csp('aws')
print(f"Frameworks found: {frameworks}")
EOF
```

### Step 5: Test Check DB Loader
```python
python3 << 'EOF'
from compliance_engine.loader.check_db_loader import CheckDBLoader

with CheckDBLoader() as loader:
    results = loader.load_and_convert(
        scan_id='check_20260201_044813',
        tenant_id='dbeaver-demo',
        csp='aws'
    )
    print(f"Loaded {len(results.get('results', []))} result groups")
    total_checks = sum(len(r.get('checks', [])) for r in results.get('results', []))
    print(f"Total checks: {total_checks}")
EOF
```

---

## 📋 Next Actions

### Option A: Fix in Running Pod (Fast)
1. Login to pod
2. Run debug steps above to identify exact blocker
3. Fix directly in container (install missing deps, add files, etc.)
4. Test `/from-check-db` endpoint works
5. Once working, replicate fixes to `engine_compliance/` code
6. Rebuild Docker image with fixes
7. Push to Docker Hub
8. Redeploy

### Option B: Fix Locally First (Safer)
1. Ensure `compliance_control_mappings` table is populated on RDS:
   ```bash
   python3 consolidated_services/database/scripts/upload_aws_compliance_to_db.py \
     --csv data_compliance/aws/aws_consolidated_rules_with_final_checks.csv
   ```

2. Check framework loader works locally:
   ```bash
   cd engine_compliance
   python3 -c "from compliance_engine.mapper.framework_loader import FrameworkLoader; print(FrameworkLoader().get_frameworks_for_csp('aws'))"
   ```

3. Fix any issues, rebuild, deploy

---

## 🎯 Expected Flow (Once Working)

```
1. POST /api/v1/compliance/generate/from-check-db
   ├─ Input: tenant_id, scan_id, csp
   └─ Loads 1,056 check_results from threat_engine_check

2. Maps checks → compliance controls
   ├─ Uses compliance_control_mappings table
   └─ Groups by framework (CIS, PCI-DSS, NIST, etc.)

3. Generates compliance report
   ├─ Calculates scores per framework
   ├─ Identifies failing controls
   └─ Creates finding rows

4. Persists to RDS
   ├─ 1 row in report_index
   └─ N rows in finding_index (one per failed check)

5. Writes to /output for S3 sync
   ├─ /output/compliance/dbeaver-demo/check_20260201_044813/full_report.json
   ├─ /output/compliance/dbeaver-demo/check_20260201_044813/findings.ndjson
   └─ /output/compliance/dbeaver-demo/check_20260201_044813/{framework}_report.json

6. S3 sidecar syncs to S3
   └─ s3://cspm-lgtech/engine_output/compliance/...
```

---

## 📊 Verification Queries (After Success)

### Check RDS
```sql
-- See compliance reports
SELECT report_id, scan_run_id, total_controls, controls_passed, controls_failed, total_findings
FROM report_index
ORDER BY created_at DESC;

-- See findings
SELECT finding_id, rule_id, severity, status, resource_arn
FROM finding_index
WHERE scan_run_id = 'check_20260201_044813'
LIMIT 20;
```

### Check S3
```bash
aws s3 ls s3://cspm-lgtech/engine_output/compliance/ --recursive
```

---

**Recommendation:** Start with **Option A** (fix in running pod) to quickly identify the blocker, then apply the same fix to the local code before final rebuild/redeploy.
