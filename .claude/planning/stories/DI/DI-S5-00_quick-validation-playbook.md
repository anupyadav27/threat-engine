# DI-S5-00 — Per-CSP Quick Validation Playbook
**Sprint**: DI-S5 | **Type**: Reference | **Status**: Active

## Why This Exists
Full AWS scan = 10,645 tasks × ~3s avg = ~52 minutes.
Quick smoke test = 3-5 key services × ~17 regions = ~50-200 tasks = **2-5 minutes per CSP**.

Use this playbook to validate each CSP with 3-5 high-value services before investing in a
full scan. Full scan only needed for DI-S4-02 sign-off.

---

## Pre-requisite: engine-di v-di-s3-7+
`run_scan.py` now supports `--services ec2,s3,iam` flag.
Deployed: `yadavanup84/engine-di:v-di-s3-7`

---

## Service Selection by CSP (3-5 highest check-rule density services)

| CSP | Services | Why |
|-----|----------|-----|
| **AWS** | `ec2,s3,iam,rds,lambda` | Most check rules; core infra; each has clear ARNs |
| **Azure** | `compute,storage,network,keyvault,sql` | ARM-heavy; most compliance rules |
| **GCP** | `compute,storage,iam,sql,container` | selfLink emitted; most rules |
| **OCI** | `compute,objectstorage,identity,database,core` | All emit OCIDs; 100% uid_template coverage |
| **IBM** | `account,containers,block_storage,vpc,iam` | CRN emitted; top 5 IBM services |
| **AliCloud** | `ecs,oss,ram,rds,vpc` | Standard id field; composed UID validated |
| **K8s** | `pod,deployment,service,namespace,role` | Flat metadata keys; uid assembly |

---

## scan_runs Record Format Per CSP

```python
# Template — replace <> values per CSP, run inside engine-di pod
kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
import psycopg2, os, uuid
conn = psycopg2.connect(
    host=os.environ['ONBOARDING_DB_HOST'], port=os.environ['ONBOARDING_DB_PORT'],
    dbname=os.environ['ONBOARDING_DB_NAME'], user=os.environ['ONBOARDING_DB_USER'],
    password=os.environ['ONBOARDING_DB_PASSWORD'],
)
cur = conn.cursor()
scan_run_id = str(uuid.uuid4())
cur.execute('''
    INSERT INTO scan_runs (scan_run_id, tenant_id, account_id, provider, credential_type, credential_ref, status)
    VALUES (%s,%s,%s,%s,%s,%s,%s)
    ON CONFLICT (scan_run_id) DO NOTHING
''', (scan_run_id, 'test-tenant-002', '<ACCOUNT_ID>', '<PROVIDER>',
      '<CRED_TYPE>', '<SECRET_ARN_OR_in_cluster>', 'pending'))
conn.commit()
print('SCAN_RUN_ID=', scan_run_id)
"
```

---

## Quick Scan Command (per CSP)

```bash
# AWS — full scan (no --services filter, using existing scan_run_id)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id 9669d115-8deb-4b2b-a33b-22b4c3ef9a03 \
   > /tmp/di_scan_aws.log 2>&1 & disown && echo started"

# Azure — 5 services (~2 min)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <AZURE_SCAN_RUN_ID> \
   --services compute,storage,network,keyvault,sql \
   > /tmp/di_scan_azure.log 2>&1 & disown && echo started"

# GCP — 5 services (~2 min)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <GCP_SCAN_RUN_ID> \
   --services compute,storage,iam,sql,container \
   > /tmp/di_scan_gcp.log 2>&1 & disown && echo started"

# OCI — 5 services (~2 min)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <OCI_SCAN_RUN_ID> \
   --services compute,objectstorage,identity,database,core \
   > /tmp/di_scan_oci.log 2>&1 & disown && echo started"

# IBM Cloud — 5 services (~2 min)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <IBM_SCAN_RUN_ID> \
   --services account,containers,block_storage,vpc,iam \
   > /tmp/di_scan_ibm.log 2>&1 & disown && echo started"

# AliCloud — 5 services (~2 min)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <ALICLOUD_SCAN_RUN_ID> \
   --services ecs,oss,ram,rds,vpc \
   > /tmp/di_scan_alicloud.log 2>&1 & disown && echo started"

# K8s — 5 resource types (~30 sec, cluster is local)
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <K8S_SCAN_RUN_ID> \
   --services pod,deployment,service,namespace,role \
   > /tmp/di_scan_k8s.log 2>&1 & disown && echo started"
```

---

## Monitor Any Scan

```bash
CSP=aws  # change to azure, gcp, oci, ibm, alicloud, k8s
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "grep -E 'Phase 0 dispatch|Phase 0 complete|Phase 2|complete|FAIL|ERROR' /tmp/di_scan_${CSP}.log | tail -10"
```

---

## Quick Validation SQL (run after scan completes)

```sql
-- Substitute <SCAN_RUN_ID> for each CSP
-- 1. Row counts
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory WHERE scan_run_id = '<SCAN_RUN_ID>'
GROUP BY provider;

-- 2. Canonical UID check (CSP-specific expected prefix)
--   AWS    → arn:
--   Azure  → /subscriptions/
--   GCP    → https://www.googleapis.com/ OR projects/
--   OCI    → ocid1.
--   IBM    → crn:
--   AliCloud → alicloud: OR acs:
--   K8s    → k8s://
SELECT count(*) as non_canonical FROM asset_inventory
WHERE scan_run_id = '<SCAN_RUN_ID>'
  AND resource_uid NOT LIKE '<EXPECTED_PREFIX>%';
-- Expected: 0

-- 3. Auth errors (zero tolerance)
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 4. Phase 0 dispatch count (confirms services filter worked)
-- Check log:  grep "Phase 0 dispatch" /tmp/di_scan_<csp>.log
-- Should show N tasks where N = num_services × num_regions (typically 5 × 1–17)
```

---

## Pass/Fail Gate Per CSP

| Check | Threshold | Notes |
|-------|-----------|-------|
| `asset_inventory` rows | ≥ 1 per service | At least 1 resource per scanned service |
| Non-canonical UIDs | 0 | All written rows use canonical prefix |
| AuthError count | 0 | Auth setup is correct |
| Phase 0 dispatch log | Visible | Confirms --services filter applied |
| ResourceIdMissingError rate | < 20% | Some edge-case resources are OK |

All 5 must pass per CSP before marking DI-S5-0x complete.

---

## Test Resource Cost Summary

| CSP | Resource | Cost |
|-----|----------|------|
| AWS | S3 bucket | $0 (free) |
| Azure | Storage Account (LRS) | ~$0.01/month, delete after |
| GCP | Cloud Storage bucket | $0 (5GB free tier) |
| OCI | Object Storage bucket | $0 (Always Free) |
| IBM | COS instance (Lite) | $0 (Lite never expires) |
| AliCloud | OSS bucket or ECS Security Group | ~$0.001 or $0 |
| K8s | Namespace + ConfigMap | $0 (existing cluster) |

**Total budget for all 7 CSP tests: < $0.05**