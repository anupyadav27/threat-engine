# DI-S5-06 — AliCloud Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: Pending

## Goal
Prove end-to-end DI scan for AliCloud produces canonical composed UIDs
(`alicloud:{account_id}:{region}:{resource_id}`) in `asset_inventory`. AliCloud short IDs
(e.g. `i-xxx`) don't embed account/region, so uid_template explicitly composes them.

## Test Resource
**OSS Bucket** (~$0.001/scan, negligible cost) or **ECS Security Group** (free, no compute).
OSS Bucket is preferred as it's universally discovered across AliCloud accounts.

```bash
# Option A: OSS Bucket via ossutil
ossutil mb oss://cspm-di-test-$(date +%s) \
  --region cn-hangzhou \
  --endpoint oss-cn-hangzhou.aliyuncs.com
```

```bash
# Option B: Security Group (free) via aliyun CLI
aliyun ecs CreateSecurityGroup \
  --RegionId cn-hangzhou \
  --SecurityGroupName cspm-di-test-sg-$(date +%s) \
  --Description "CSPM DI test - delete after scan"
```

```bash
# Teardown OSS bucket
ossutil rm oss://cspm-di-test-<TIMESTAMP> -r -f
ossutil rm oss://cspm-di-test-<TIMESTAMP> -b
# Teardown Security Group
aliyun ecs DeleteSecurityGroup --RegionId cn-hangzhou --SecurityGroupId sg-xxx
```

## Pre-requisites
- AliCloud AccessKey ID + AccessKey Secret in AWS Secrets Manager
- `scan_runs` record created for AliCloud (see below)
- AliCloud SDK (`alibabacloud-*`) installed in engine-di image (verified in DI-S1-03)

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
''', (scan_run_id, 'test-tenant-002', '<ALICLOUD_ACCOUNT_ID>', 'alicloud',
      'access_key', '<SECRET_ARN>', 'pending'))
conn.commit()
print('scan_run_id:', scan_run_id)
"
```

## Trigger Scan
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id <ALICLOUD_SCAN_RUN_ID> \
   > /tmp/di_scan_alicloud.log 2>&1 & disown && echo 'started'"
```

## Validation Checklist

```sql
-- 1. rows written for alicloud
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '<ALICLOUD_SCAN_RUN_ID>'
GROUP BY provider;
-- Expected: provider=alicloud, rows > 5, types > 2

-- 2. canonical composed UIDs (alicloud:{account_id}:{region}:{id})
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '<ALICLOUD_SCAN_RUN_ID>'
  AND provider = 'alicloud'
  AND resource_uid NOT LIKE 'alicloud:%'
  AND resource_uid NOT LIKE 'acs:%';
-- Expected: 0

-- 3. test OSS bucket or security group appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '<ALICLOUD_SCAN_RUN_ID>'
LIMIT 10;

-- 4. auth errors
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '<ALICLOUD_SCAN_RUN_ID>'
  AND error_type IN ('AuthError', 'AuthenticationError');
-- Expected: 0

-- 5. uid_template decomposition visible in uid format
SELECT resource_uid, provider, account_id, region
FROM asset_inventory
WHERE scan_run_id = '<ALICLOUD_SCAN_RUN_ID>'
  AND provider = 'alicloud'
LIMIT 5;
-- Expected: resource_uid = alicloud:{account_id}:{region}:{short_id}
--           confirms context.account_id and context.region are correctly injected
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 5 rows for `provider=alicloud`
- [ ] All UIDs start with `alicloud:` or `acs:` (0 non-canonical)
- [ ] UID format confirms account_id + region are embedded in the composed key
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] Phase 0 dispatch log visible for provider=alicloud

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] Test OSS bucket or security group provisioned, found in scan, torn down
- [ ] Results recorded in `DI-S5-06_alicloud_results.md`

## Notes
- **uid_template**: `alicloud:{context.account_id}:{context.region}:{item.id}` — explicitly
  composes account + region + short ID because AliCloud short IDs (`i-xxx`, `sg-xxx`) are
  only unique within an account × region
- AliCloud canonical prefixes: `("acs:", "alicloud:")` — the composed template produces
  `alicloud:` prefix which satisfies `_is_canonical()` in uid_builder.py
- Coverage: 28% (736/2615 ops) patched with uid_template — ops with standard `id`/`ResourceId`/
  `InstanceId` fields; remaining 1879 ops fall to heuristic or ResourceIdMissingError
- AliCloud credential: `access_key_id` + `access_key_secret`
- Default region for scan: `cn-hangzhou`; scanner should enumerate other regions too