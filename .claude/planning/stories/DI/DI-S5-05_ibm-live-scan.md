# DI-S5-05 — IBM Cloud Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for IBM Cloud produces canonical CRN UIDs (`crn:v1:…`) in
`asset_inventory`. IBM CRNs (Cloud Resource Names) are the canonical identifier for all IBM
Cloud resources.

## Test Resource
**Cloud Object Storage bucket** (IBM Lite plan — free, no expiry). CRN emitted as `crn` field
in all IBM resource responses.

```bash
# Provision via IBM Cloud CLI
ibmcloud login --apikey <IBM_API_KEY> -r us-south
ibmcloud resource service-instance-create \
  cspm-di-test-cos cloud-object-storage lite global \
  -p '{"HMAC": true}'
# Create bucket inside the COS instance
ibmcloud cos bucket-create \
  --bucket cspm-di-test-$(date +%s) \
  --ibm-service-instance-id <COS_INSTANCE_GUID> \
  --region us-south
```

```bash
# Teardown
ibmcloud cos bucket-delete --bucket cspm-di-test-<TIMESTAMP> --force
ibmcloud resource service-instance-delete cspm-di-test-cos -f
```

## Pre-requisites
- IBM Cloud API key stored in AWS Secrets Manager
- `scan_runs` record created for IBM (see below)
- IBM SDK (`ibm-platform-services`, `ibm-cloud-sdk-core`) installed in engine-di image

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
''', (scan_run_id, 'test-tenant-002', '<IBM_ACCOUNT_ID>', 'ibm',
      'api_key', '<SECRET_ARN>', 'pending'))
conn.commit()
print('scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <IBM_SCAN_RUN_ID> \
   > /tmp/di_scan_ibm.log 2>&1 & disown && echo 'started'"
```

## Validation Checklist

```sql
-- 1. rows written for ibm
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<IBM_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=ibm, rows > 5, types > 2

-- 2. canonical CRN UIDs (must start with crn:)
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<IBM_SCAN_RUN_ID>'
  AND provider = 'ibm'
  AND resource_uid NOT LIKE 'crn:%';
-- Expected: 0

-- 3. test COS instance appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<IBM_SCAN_RUN_ID>'
  AND resource_type LIKE '%cos%'
LIMIT 5;

-- 4. auth errors
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<IBM_SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 5. uid_template coverage
SELECT count(*) as total,
       count(*) FILTER (WHERE resource_uid LIKE 'crn:%') as canonical
FROM asset_inventory
WHERE scan_run_id = '<IBM_SCAN_RUN_ID>' AND provider = 'ibm';
-- Expected: canonical = total (97% of IBM ops patched with uid_template="{item.crn}")
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 5 rows for `provider=ibm`
- [ ] 0 non-canonical UIDs — all CRNs (`crn:` prefix)
- [ ] Test COS instance/bucket appears with CRN `resource_uid`
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] Phase 0 dispatch log visible for provider=ibm

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] COS instance/bucket provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-05_ibm_results.md`

## Notes
- IBM CRN format: `crn:v1:{cname}:{ctype}:{service_name}:{location}:{scope}:{service_instance}:{resource_type}:{resource}`
- uid_template `{item.crn}` covers 97% of IBM ops (536/549); remaining 13 ops fall to `{item.id}` heuristic
- IBM credential: `apikey` — single field, no subscription ID needed
- IBM regions: `us-south`, `us-east`, `eu-gb`, `eu-de`, `jp-tok`, `au-syd`
- IBM Lite plan resources never expire and have no time limit (genuinely free)