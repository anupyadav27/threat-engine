# DI-S5-03 — GCP Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for GCP produces canonical UIDs (`projects/…` or
`https://www.googleapis.com/…`) in `asset_inventory`. GCP selfLink URLs are the canonical
identifier. Provision a free GCS bucket, scan, validate, tear down.

## Test Resource
**Cloud Storage Bucket** (free up to 5 GB). GCS bucket emits `selfLink` which starts with
`https://www.googleapis.com/storage/v1/b/{bucket}`.

```bash
# Provision
PROJECT_ID=$(gcloud config get-value project)
BUCKET_NAME="cspm-di-test-$(date +%s)"
gcloud storage buckets create gs://${BUCKET_NAME} \
  --location=us-central1 \
  --project=${PROJECT_ID}
gcloud storage buckets add-labels gs://${BUCKET_NAME} \
  --labels=cspm-di-test=true
```

```bash
# Teardown
gcloud storage rm --recursive gs://${BUCKET_NAME}
gcloud storage buckets delete gs://${BUCKET_NAME}
```

## Pre-requisites
- GCP service account JSON key stored in AWS Secrets Manager
- `scan_runs` record created for GCP (see below)
- GCP SDK installed in engine-di image (verified in DI-S1-03)

## Create scan_runs Record
```python
kubectl exec -n threat-engine-engines deployment/engine-di -- python3 -c "
import psycopg2, os, uuid
conn = psycopg2.connect(
    host=os.environ['ONBOARDING_DB_HOST'],
    port=os.environ['ONBOARDING_DB_PORT'],
    dbname=os.environ['ONBOARDING_DB_NAME'],
    user=os.environ['ONBOARDING_DB_USER'],
    password=os.environ['ONBOARDING_DB_PASSWORD'],
)
cur = conn.cursor()
scan_run_id = str(uuid.uuid4())
cur.execute('''
    INSERT INTO scan_runs
      (scan_run_id, tenant_id, account_id, provider, credential_type, credential_ref, status)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
''', (scan_run_id, 'test-tenant-002', '<GCP_PROJECT_ID>', 'gcp',
      'service_account_key', '<SECRET_ARN>', 'pending'))
conn.commit()
print('scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <GCP_SCAN_RUN_ID> \
   > /tmp/di_scan_gcp.log 2>&1 & disown && echo 'started'"
```

## Validation Checklist

```sql
-- 1. rows written for gcp
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<GCP_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=gcp, rows > 10, types > 3

-- 2. canonical GCP UIDs (selfLink or projects/ prefix)
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<GCP_SCAN_RUN_ID>'
  AND provider = 'gcp'
  AND resource_uid NOT LIKE 'https://www.googleapis.com/%'
  AND resource_uid NOT LIKE 'projects/%';
-- Expected: 0

-- 3. test GCS bucket appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<GCP_SCAN_RUN_ID>'
  AND resource_type LIKE '%storage%'
LIMIT 5;

-- 4. auth errors
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<GCP_SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 5. uid_template coverage check
SELECT count(*) as total,
       count(*) FILTER (WHERE resource_uid LIKE 'https://www.googleapis.com/%'
                           OR resource_uid LIKE 'projects/%') as canonical
FROM asset_inventory
WHERE scan_run_id = '<GCP_SCAN_RUN_ID>' AND provider = 'gcp';
-- Expected: canonical / total >= 0.80 (80% — 590 ops may fall to ResourceIdMissingError, acceptable)
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 10 rows for `provider=gcp`
- [ ] 0 non-canonical UIDs for rows that ARE written
- [ ] Test GCS bucket appears in `asset_inventory`
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] Phase 0 dispatch log visible: `Phase 0 dispatch: N tasks for provider=gcp`

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] GCS bucket provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-03_gcp_results.md`

## Notes
- GCP canonical prefixes: `https://www.googleapis.com/` (selfLink) and `projects/` (resource name)
- uid_template covers ~80% (2438/3028 ops) — remaining 590 are complex objects (IAM policies,
  SCC findings) that produce `ResourceIdMissingError` and are logged to `di_scan_errors` (acceptable)
- GCP credential: service_account_key JSON — `project_id`, `private_key`, `client_email`
- GCP regions: variable — scanner uses `list_available_regions()` or falls back to `us-central1`