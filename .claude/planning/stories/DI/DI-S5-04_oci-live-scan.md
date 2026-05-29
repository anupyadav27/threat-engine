# DI-S5-04 — OCI Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for OCI produces canonical OCID UIDs (`ocid1.…`) in
`asset_inventory`. OCI Always Free tier resources allow zero-cost testing.

## Test Resource
**Object Storage Bucket** (OCI Always Free). OCIDs are emitted as `id` field in most OCI API
responses.

```bash
# Provision (using OCI CLI)
COMPARTMENT_ID=$(oci iam compartment list --query 'data[0].id' --raw-output)
oci os bucket create \
  --compartment-id ${COMPARTMENT_ID} \
  --name cspm-di-test-$(date +%s) \
  --freeform-tags '{"cspm-di-test": "true"}'
```

```bash
# Teardown
oci os bucket delete --name cspm-di-test-<TIMESTAMP> --force
```

## Pre-requisites
- OCI credentials (user OCID + fingerprint + private key) in AWS Secrets Manager
- `scan_runs` record created for OCI (see below)
- OCI SDK installed in engine-di image (verified in DI-S1-03)

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
''', (scan_run_id, 'test-tenant-002', '<OCI_TENANCY_OCID>', 'oci',
      'api_key', '<SECRET_ARN>', 'pending'))
conn.commit()
print('scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <OCI_SCAN_RUN_ID> \
   > /tmp/di_scan_oci.log 2>&1 & disown && echo 'started'"
```

## Validation Checklist

```sql
-- 1. rows written for oci
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<OCI_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=oci, rows > 10, types > 3

-- 2. canonical OCID UIDs (all must start with ocid1.)
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<OCI_SCAN_RUN_ID>'
  AND provider = 'oci'
  AND resource_uid NOT LIKE 'ocid1.%';
-- Expected: 0 (100% OCID coverage via uid_template="{item.ocid}")

-- 3. test bucket appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<OCI_SCAN_RUN_ID>'
  AND resource_type LIKE '%bucket%'
LIMIT 5;

-- 4. auth errors
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<OCI_SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 5. full uid_template coverage (OCI is 100%)
SELECT count(*) as total,
       count(*) FILTER (WHERE resource_uid LIKE 'ocid1.%') as canonical
FROM asset_inventory
WHERE scan_run_id = '<OCI_SCAN_RUN_ID>' AND provider = 'oci';
-- Expected: canonical = total (100% — all 2419 OCI ops have uid_template="{item.ocid}")
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 10 rows for `provider=oci`
- [ ] 0 non-canonical UIDs — 100% OCID coverage (`ocid1.` prefix)
- [ ] Test Object Storage bucket appears with OCID `resource_uid`
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] Phase 0 dispatch log visible for provider=oci

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] OCI bucket provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-04_oci_results.md`

## Notes
- OCI OCID format: `ocid1.{resource_type}.{realm}.{region}.{unique_id}`
- uid_template `{item.ocid}` covers 100% of OCI ops (2419/2419 — highest coverage CSP)
- OCI compartments are multi-region — scanner uses compartment OCID as account_id
- OCI credential fields: `user`, `fingerprint`, `key_file_content`, `tenancy`, `region`
- OCI Always Free resources: 2× AMD VMs (1/8 OCPU, 1GB RAM), 4× Arm-based VMs, 200GB total storage