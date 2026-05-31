# DI-S5-02 — Azure Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for Azure produces canonical ARM resource ID UIDs
(`/subscriptions/…`) in `asset_inventory`. Provision a free test resource, scan, validate,
tear down.

## Test Resource
**Azure Resource Group** (free) + **Storage Account** (LRS, ~$0.02/GB/month — delete after).
Resource Group alone is sufficient for discovery; Storage Account ensures a richer resource type is tested.

```bash
# Provision
az group create --name cspm-di-test-rg --location eastus \
  --tags cspm-di-test=true
az storage account create \
  --name cspmditeststg$(date +%s | tail -c 8) \
  --resource-group cspm-di-test-rg \
  --location eastus \
  --sku Standard_LRS \
  --kind StorageV2
```

```bash
# Teardown (deletes RG + all resources inside)
az group delete --name cspm-di-test-rg --yes --no-wait
```

## Pre-requisites
- Azure credentials stored in AWS Secrets Manager under the onboarded account
- `scan_runs` record created for Azure (see below)
- Azure SDK installed in engine-di image (verified in DI-S1-03)

## Create scan_runs Record
```python
# Run inside engine-di pod
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
print('scan_run_id:', scan_run_id)
cur.execute('''
    INSERT INTO scan_runs
      (scan_run_id, tenant_id, account_id, provider, credential_type, credential_ref, status)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
''', (scan_run_id, 'test-tenant-002', '<AZURE_SUBSCRIPTION_ID>', 'azure',
      'service_principal', '<SECRET_ARN_IN_SECRETS_MANAGER>', 'pending'))
conn.commit()
print('Created scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <AZURE_SCAN_RUN_ID> \
   > /tmp/di_scan_azure.log 2>&1 & disown && echo 'started'"
```

## Monitor
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "grep -E 'Phase 0|provider=azure|Phase 2|complete|error' /tmp/di_scan_azure.log | tail -30"
```

## Validation Checklist

```sql
-- 1. rows written for azure
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<AZURE_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=azure, rows > 20, types > 5

-- 2. canonical ARM UIDs (must start with /subscriptions/)
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<AZURE_SCAN_RUN_ID>'
  AND provider = 'azure'
  AND resource_uid NOT LIKE '/subscriptions/%';
-- Expected: 0

-- 3. test storage account appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<AZURE_SCAN_RUN_ID>'
  AND resource_type LIKE '%storage%'
LIMIT 5;
-- Expected: rows with ARM ID resource_uid

-- 4. auth errors
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<AZURE_SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 5. uid_template coverage
SELECT count(*) as total, count(*) FILTER (WHERE resource_uid LIKE '/subscriptions/%') as canonical
FROM asset_inventory
WHERE scan_run_id = '<AZURE_SCAN_RUN_ID>' AND provider = 'azure';
-- Expected: canonical = total (100% ARM IDs)
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 20 rows for `provider=azure`
- [ ] 0 rows where `resource_uid NOT LIKE '/subscriptions/%'` for Azure
- [ ] Test Storage Account appears with ARM resource_uid
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] Phase 0 dispatches tasks log line visible: `Phase 0 dispatch: N tasks for provider=azure`

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] Storage account + resource group provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-02_azure_results.md`
- [ ] scan_run_id saved for cross-CSP comparison report

## Notes
- Azure ARM resource ID format: `/subscriptions/{sub}/resourceGroups/{rg}/providers/{ns}/{type}/{name}`
- uid_template `{item.id}` covers 93% of Azure ops (1087/1167 ops patched in batch)
- Remaining 7% falls to Strategy 2 heuristic (checks `id` and `resourceId` fields)
- Azure credential type: `service_principal` with `client_id`, `client_secret`, `tenant_id`, `subscription_id`