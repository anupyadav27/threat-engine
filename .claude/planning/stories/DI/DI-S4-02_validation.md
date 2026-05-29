# DI-S4-02 — Validation (Parallel Run + DI vs Legacy Comparison)
**Sprint**: DI-S4 | **Points**: 8 | **Status**: Ready for Dev

## Goal
Run both pipelines in parallel for 1 complete scan cycle. Compare `asset_inventory` (DI path)
against `discovery_findings`/`inventory_findings` (legacy path) on: row counts, UID format, canonical
UID coverage, downstream engine finding counts, and attack-path BFS output. Sign off that DI engine
is production-ready before flipping `DI_PIPELINE_ENABLED=true`.

## Context
This is a gate story — no code changes. It is a structured QA exercise that proves DI engine
correctness before cutover. All validation runs against the production EKS cluster.

## Validation Checklist

### 1. asset_inventory vs discovery_findings Row Count
```sql
-- DI engine output
SELECT provider, count(*) as di_count
FROM asset_inventory
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
GROUP BY provider;

-- Legacy engine output
SELECT provider, count(*) as legacy_count
FROM discovery_findings
WHERE scan_run_id = '<LEGACY_SCAN_RUN_ID>'
GROUP BY provider;

-- Delta must be ≤ 5% per provider
```

### 2. Canonical UID Coverage
```sql
-- DI: 100% canonical UIDs expected
SELECT count(*) FROM asset_inventory
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
  AND resource_uid NOT LIKE 'arn:%'
  AND resource_uid NOT LIKE 'ocid1.%'
  AND resource_uid NOT LIKE '/subscriptions/%'
  AND resource_uid NOT LIKE 'crn:%'
  AND resource_uid NOT LIKE 'projects/%'
  AND provider != 'k8s';
-- Expected: 0

-- Legacy: count synthetic UIDs for comparison
SELECT count(*) FROM discovery_findings
WHERE scan_run_id = '<LEGACY_SCAN_RUN_ID>'
  AND (resource_uid LIKE '%:%' AND resource_uid NOT LIKE 'arn:%' AND resource_uid NOT LIKE 'ocid1.%');
```

### 3. Di_scan_errors Audit
```sql
SELECT error_type, service, count(*)
FROM di_scan_errors
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
GROUP BY error_type, service
ORDER BY count(*) DESC;
-- Acceptable: error_type='ResourceIdMissingError' for known edge-case services
-- Unacceptable: error_type='AuthError' (auth broken) or count > 5% of total resources
```

### 4. Downstream Engine Finding Counts Comparison
Run check engine with `DI_ENGINE_ENABLED=false` and then `=true` for the SAME scan_run_id.
Compare:
```sql
-- Legacy check findings per rule
SELECT rule_id, count(*) FROM check_findings
WHERE scan_run_id = '<LEGACY_SCAN_RUN_ID>'
GROUP BY rule_id;

-- DI check findings per rule
SELECT rule_id, count(*) FROM check_findings
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
GROUP BY rule_id;

-- Delta per rule must be ≤ 2%
```

### 5. Attack-Path BFS Comparison
```sql
-- Legacy BFS
SELECT count(*) FROM attack_paths
WHERE scan_run_id = '<LEGACY_SCAN_RUN_ID>';

-- DI BFS
SELECT count(*) FROM attack_paths
WHERE scan_run_id = '<DI_SCAN_RUN_ID>';
-- Delta ≤ 10%

-- Check internet-facing entry points match
SELECT resource_uid FROM attack_paths
WHERE scan_run_id = '<LEGACY_SCAN_RUN_ID>' AND is_entry_point = TRUE
EXCEPT
SELECT resource_uid FROM attack_paths
WHERE scan_run_id = '<DI_SCAN_RUN_ID>' AND is_entry_point = TRUE;
-- Expected: 0 rows (no entry points missing from DI path)
```

### 6. asset_relationships Completeness
```sql
SELECT relation_type, count(*) FROM asset_relationships
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
GROUP BY relation_type
ORDER BY count(*) DESC;
-- Must show: PLACED_IN, BELONGS_TO, PROTECTED_BY, INTERNET_ACCESSIBLE, ATTACHED_TO
-- Each type must have > 0 rows for AWS provider
```

### 7. Network Engine 7-Layer Output
With `DI_ENGINE_ENABLED=true`: run network scan. Verify all 7 sub-layers produce findings.
```sql
SELECT rule_metadata->'network_security'->>'layer' as layer, count(*)
FROM check_findings
JOIN rule_metadata USING (rule_id)
WHERE scan_run_id = '<DI_SCAN_RUN_ID>'
  AND rule_metadata->'network_security'->>'applicable' = 'true'
GROUP BY layer;
-- Expected: rows for isolation, reachability, acl, security_group, load_balancer, waf, monitoring
```

### 8. IAM T1/T2/T3 Pattern Counts
With `DI_ENGINE_ENABLED=true`: run threat-v1. Verify T-counts within 10% of baseline.
```bash
kubectl logs -f -l app=engine-threat-v1 -n threat-engine-engines --tail=100 | grep "T1\|T2\|T3 patterns"
# Expected: ~44 T1, ~33 T2, ~34 T3 (within 10% of baseline)
```

### 9. Sensitive Field Scrubbing Verification
```sql
-- Verify no sensitive fields in raw_response
SELECT count(*) FROM asset_inventory
WHERE raw_response ? 'MasterUserPassword'
   OR raw_response ? 'AccessKeyId'
   OR raw_response ? 'SecretAccessKey';
-- Expected: 0
```

### 10. Sign-off Criteria (all must pass before DI-S4-03)
| Check | Threshold | Actual | Pass? |
|-------|-----------|--------|-------|
| Row count delta | ≤ 5% per CSP | | |
| Synthetic UIDs | 0 rows in asset_inventory | | |
| di_scan_errors AuthError | 0 rows | | |
| Check findings delta | ≤ 2% per rule | | |
| Attack paths delta | ≤ 10% | | |
| Internet entry point coverage | ≥ 90% overlap | | |
| asset_relationships types | All 5 types present | | |
| Network 7-layer coverage | All 7 layers have findings | | |
| T1/T2/T3 counts | Within 10% of baseline | | |
| Sensitive fields scrubbed | 0 sensitive rows | | |

## Acceptance Criteria

### Functional
- [ ] All 10 sign-off checks pass (table above fully populated with PASS)
- [ ] Validation report committed to `.claude/planning/stories/DI/DI-S4-02_validation_report.md`
- [ ] bmad-sm signs off on validation report before DI-S4-03 starts

### Security
- [ ] Check 9 (sensitive field scrubbing) must pass before cutover is allowed
- [ ] `di_scan_errors` reviewed for any credential-exposure errors

### Error Handling
- [ ] If any check fails: create bug ticket + block DI-S4-03 until resolved
- [ ] Partial failures documented in validation report with root cause analysis

## Testing Requirements
All validation is manual SQL execution + log review against production EKS cluster.
No code changes in this story.

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Validation sign-off | bmad-sm | DI-S4-03 start |
| QA acceptance | cspm-qa | DI-S4-03 start |

## Definition of Done
- [ ] All 10 sign-off checks pass with documented actual values
- [ ] `DI-S4-02_validation_report.md` committed with full table populated
- [ ] 0 sensitive fields in `raw_response` (Check 9 passed)
- [ ] 0 AuthError in `di_scan_errors`
- [ ] bmad-sm and cspm-qa sign-off documented in report

## Dependencies
- DI-S3-01 through DI-S3-07 all deployed with `DI_ENGINE_ENABLED=false` (adapters ready but not active)
- DI-S4-01 migration complete
- engine-di producing scans for parallel run

## Rollback
Not applicable (no code changes). If validation fails, fix the identified engine and re-run validation.