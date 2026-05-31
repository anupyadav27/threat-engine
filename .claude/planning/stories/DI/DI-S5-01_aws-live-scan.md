# DI-S5-01 — AWS Live Scan Validation
**Sprint**: DI-S5 | **Points**: 3 | **Status**: In Progress

## Goal
Prove end-to-end DI scan for AWS produces canonical ARN UIDs in `asset_inventory` and zero
auth errors. Currently running in background with scan_run_id `9669d115-8deb-4b2b-a33b-22b4c3ef9a03`.

## Test Resource
**S3 Bucket** — free, ARN emitted by scanner, check rules available.

```bash
# Provision (already exists if account already onboarded — re-use)
aws s3 mb s3://cspm-di-test-$(date +%s) --region ap-south-1
# Tag it so we can identify it
aws s3api put-bucket-tagging --bucket <bucket-name> \
  --tagging 'TagSet=[{Key=cspm-di-test,Value=true}]'
```

```bash
# Teardown after scan validated
aws s3 rb s3://<bucket-name> --force
```

## Scan Details
| Field | Value |
|-------|-------|
| scan_run_id | `9669d115-8deb-4b2b-a33b-22b4c3ef9a03` |
| provider | aws |
| account_id | 588989875114 |
| credential_type | access_key |
| Phase 0 tasks | 10,645 (661 identifiers × 17 regions) |
| Max workers | 15 (parallel asyncio.gather) |
| Expected duration | ~52 min |

## Trigger Scan
```bash
# Scan already running. If restarting:
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "nohup python3 /app/run_scan.py --scan-run-id 9669d115-8deb-4b2b-a33b-22b4c3ef9a03 \
   > /tmp/di_scan.log 2>&1 & disown && echo 'started'"
```

## Monitor
```bash
kubectl exec -n threat-engine-engines deployment/engine-di -- bash -c \
  "grep -E 'Phase 0 complete|Phase 2|resources_written|rows=|DI scan complete' /tmp/di_scan.log | tail -20"
```

## Validation Checklist
Run after scan completes:

```python
# Port-forward to engine-di and call status endpoint
# kubectl port-forward svc/engine-di 8025:80 -n threat-engine-engines
# python3 -c "import urllib.request, json; r=urllib.request.urlopen('http://localhost:8025/api/v1/di/scan/9669d115-8deb-4b2b-a33b-22b4c3ef9a03/status'); print(json.loads(r.read()))"
```

```sql
-- 1. rows written
SELECT provider, count(*) as rows, count(DISTINCT resource_type) as types
FROM asset_inventory
WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03'
GROUP BY provider;
-- Expected: provider=aws, rows > 100, types > 20

-- 2. canonical UIDs only (all must start with arn:)
SELECT count(*) as non_canonical
FROM asset_inventory
WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03'
  AND provider = 'aws'
  AND resource_uid NOT LIKE 'arn:%';
-- Expected: 0

-- 3. test bucket appears
SELECT resource_uid, resource_name, resource_type
FROM asset_inventory
WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03'
  AND resource_type = 'aws.s3.bucket'
LIMIT 5;
-- Expected: rows with ARN resource_uid

-- 4. auth errors (must be zero)
SELECT count(*) FROM di_scan_errors
WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03'
  AND error_type = 'AuthError';
-- Expected: 0

-- 5. ResourceIdMissingError rate
SELECT count(*) as total_errors,
       (SELECT count(*) FROM asset_inventory WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03') as total_rows
FROM di_scan_errors
WHERE scan_run_id = '9669d115-8deb-4b2b-a33b-22b4c3ef9a03';
-- Expected: error_rate < 5% (errors / (errors + rows))
```

## Acceptance Criteria
- [ ] `asset_inventory` has > 100 rows for `provider=aws`
- [ ] 0 rows where `resource_uid NOT LIKE 'arn:%'` for AWS
- [ ] Test S3 bucket appears with correct ARN `resource_uid`
- [ ] 0 `AuthError` in `di_scan_errors`
- [ ] `ResourceIdMissingError` rate < 5% of total items scanned
- [ ] Phase 0 → Phase 2 log sequence visible in `/tmp/di_scan.log`

## Definition of Done
- [ ] All 5 SQL checks documented with actual values
- [ ] Test bucket provisioned, found, torn down
- [ ] Results recorded in `DI-S5-01_aws_results.md`
- [ ] Unblocks DI-S5 CSP series + DI-S4-03 cutover gate

## Notes
- Phase 1 (enrichment) is absorbed into Phase 0 — single scanner pass with `[root_op] + enrich_ops`
- Phase 0 → Phase 2 directly; no separate enrichment step
- 10,645 tasks dispatched via `asyncio.gather` with `Semaphore(15)` — confirms v-di-s3-6 parallel enumerator